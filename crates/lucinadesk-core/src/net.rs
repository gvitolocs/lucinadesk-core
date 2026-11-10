//! A blocking WebSocket client over plain TCP, for native programs on a device with one CPU: nothing but what hbbs and
//! hbbr speak (no TLS, no extensions). The two halves work from different threads, so that input can go out while a
//! video frame is being decoded.
//!
//! Framing is RFC 6455. Only binary messages are handed up; pings are answered here.

use std::io::{self, BufReader, Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::sync::{Arc, Mutex};
use std::time::Duration;

/// A message larger than this is refused rather than allocated: a key frame of a 4K desktop stays far below it.
pub const MAX_MESSAGE: usize = 64 << 20;

const OP_CONT: u8 = 0;
const OP_TEXT: u8 = 1;
const OP_BIN: u8 = 2;
const OP_CLOSE: u8 = 8;
const OP_PING: u8 = 9;
const OP_PONG: u8 = 10;

fn invalid(what: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, what.into())
}

/// `ws://host:port[/path]` into its parts.
fn parse_url(url: &str) -> io::Result<(String, String)> {
    let rest = url.strip_prefix("ws://").ok_or_else(|| invalid(format!("only ws:// URLs: {url}")))?;
    Ok(match rest.split_once('/') {
        Some((host, path)) => (host.to_owned(), format!("/{path}")),
        None => (rest.to_owned(), "/".to_owned()),
    })
}

fn accept_key(key: &str) -> String {
    use base64::Engine;
    use sha1_smol::Sha1;
    let mut h = Sha1::new();
    h.update(key.as_bytes());
    h.update(b"258EAFA5-E914-47DA-95CA-C5AB0DC85B11");
    base64::engine::general_purpose::STANDARD.encode(h.digest().bytes())
}

/// The sending half. Cheap to clone: every clone writes whole messages, one at a time.
#[derive(Clone)]
pub struct WsWriter {
    stream: Arc<Mutex<TcpStream>>,
}

impl WsWriter {
    pub fn send(&self, data: &[u8]) -> io::Result<()> {
        self.frame(OP_BIN, data)
    }

    fn frame(&self, op: u8, data: &[u8]) -> io::Result<()> {
        let bytes = encode_frame(op, data);
        let mut s = self.stream.lock().map_err(|_| invalid("writer poisoned"))?;
        s.write_all(&bytes)
    }

    /// Ends the connection for the reader as well.
    pub fn shutdown(&self) {
        if let Ok(s) = self.stream.lock() {
            let _ = s.shutdown(std::net::Shutdown::Both);
        }
    }
}

/// One client frame: masked, as RFC 6455 requires of a client.
fn encode_frame(op: u8, data: &[u8]) -> Vec<u8> {
    let mut b = Vec::with_capacity(data.len() + 14);
    b.push(0x80 | op);
    match data.len() {
        n if n < 126 => b.push(0x80 | n as u8),
        n if n <= 0xffff => {
            b.push(0x80 | 126);
            b.extend_from_slice(&(n as u16).to_be_bytes());
        }
        n => {
            b.push(0x80 | 127);
            b.extend_from_slice(&(n as u64).to_be_bytes());
        }
    }
    let mut mask = [0u8; 4];
    crate::crypto::random(&mut mask);
    b.extend_from_slice(&mask);
    let start = b.len();
    b.extend_from_slice(data);
    for (i, v) in b[start..].iter_mut().enumerate() {
        *v ^= mask[i % 4];
    }
    b
}

/// The receiving half.
pub struct WsReader {
    r: BufReader<TcpStream>,
    w: WsWriter,
}

impl WsReader {
    /// The next binary message, or `None` when the other side closed.
    pub fn read(&mut self) -> io::Result<Option<Vec<u8>>> {
        let mut message = Vec::new();
        let mut in_message = false;
        loop {
            let mut head = [0u8; 2];
            match self.r.read_exact(&mut head) {
                Ok(()) => {}
                Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => return Ok(None),
                Err(e) => return Err(e),
            }
            let fin = head[0] & 0x80 != 0;
            let op = head[0] & 0x0f;
            let masked = head[1] & 0x80 != 0;
            let len = match head[1] & 0x7f {
                126 => {
                    let mut n = [0u8; 2];
                    self.r.read_exact(&mut n)?;
                    u16::from_be_bytes(n) as u64
                }
                127 => {
                    let mut n = [0u8; 8];
                    self.r.read_exact(&mut n)?;
                    u64::from_be_bytes(n)
                }
                n => n as u64,
            };
            if len > MAX_MESSAGE as u64 || message.len() as u64 + len > MAX_MESSAGE as u64 {
                return Err(invalid(format!("a WebSocket frame of {len} bytes")));
            }
            let mut mask = [0u8; 4];
            if masked {
                self.r.read_exact(&mut mask)?;
            }
            let at = message.len();
            message.resize(at + len as usize, 0);
            self.r.read_exact(&mut message[at..])?;
            if masked {
                for (i, v) in message[at..].iter_mut().enumerate() {
                    *v ^= mask[i % 4];
                }
            }
            match op {
                OP_BIN | OP_TEXT if !in_message => in_message = !fin,
                OP_CONT if in_message => in_message = !fin,
                OP_PING => {
                    let body = message.split_off(at);
                    self.w.frame(OP_PONG, &body)?;
                    continue;
                }
                OP_PONG => {
                    message.truncate(at);
                    continue;
                }
                OP_CLOSE => {
                    let body = message.split_off(at);
                    let _ = self.w.frame(OP_CLOSE, &body);
                    return Ok(None);
                }
                other => return Err(invalid(format!("WebSocket opcode {other} out of place"))),
            }
            if fin {
                return Ok(Some(message));
            }
        }
    }
}

/// Opens a connection and does the handshake. `timeout` bounds connecting and the handshake, not the session.
pub fn connect(url: &str, timeout: Duration) -> io::Result<(WsReader, WsWriter)> {
    let (host, path) = parse_url(url)?;
    let addr = host.to_socket_addrs()?.next().ok_or_else(|| invalid(format!("no address for {host}")))?;
    let stream = TcpStream::connect_timeout(&addr, timeout)?;
    stream.set_nodelay(true)?;
    stream.set_read_timeout(Some(timeout))?;
    let mut nonce = [0u8; 16];
    crate::crypto::random(&mut nonce);
    use base64::Engine;
    let key = base64::engine::general_purpose::STANDARD.encode(nonce);
    let request = format!(
        "GET {path} HTTP/1.1\r\nHost: {host}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: {key}\r\nSec-WebSocket-Version: 13\r\n\r\n"
    );
    (&stream).write_all(request.as_bytes())?;
    let mut r = BufReader::new(stream.try_clone()?);
    let head = read_head(&mut r)?;
    check_response(&head, &key)?;
    stream.set_read_timeout(None)?;
    let w = WsWriter { stream: Arc::new(Mutex::new(stream)) };
    Ok((WsReader { r, w: w.clone() }, w))
}

/// The framing of RustDesk's plain TCP connections (hbb_common's `BytesCodec`): a little-endian header of 1 to 4 bytes, whose
/// two low bits say how many bytes it has, less one, and the rest the length of the message.
fn encode_tcp_header(len: usize) -> Vec<u8> {
    let v = (len as u32) << 2;
    match len {
        0..=0x3f => vec![v as u8],
        0x40..=0x3fff => (v as u16 | 1).to_le_bytes().to_vec(),
        0x4000..=0x3f_ffff => (v | 2).to_le_bytes()[..3].to_vec(),
        _ => (v | 3).to_le_bytes().to_vec(),
    }
}

/// The sending half of a connection someone made to us. Cheap to clone, as [`WsWriter`].
#[derive(Clone)]
pub struct TcpWriter {
    stream: Arc<Mutex<TcpStream>>,
}

impl TcpWriter {
    pub fn send(&self, data: &[u8]) -> io::Result<()> {
        if data.len() > MAX_MESSAGE {
            return Err(invalid("message too large"));
        }
        let mut bytes = encode_tcp_header(data.len());
        bytes.extend_from_slice(data);
        let mut s = self.stream.lock().map_err(|_| invalid("writer poisoned"))?;
        s.write_all(&bytes)
    }

    pub fn shutdown(&self) {
        if let Ok(s) = self.stream.lock() {
            let _ = s.shutdown(std::net::Shutdown::Both);
        }
    }
}

/// The receiving half.
pub struct TcpReader {
    r: BufReader<TcpStream>,
}

impl TcpReader {
    /// The next message, or `None` when the connection closed between messages.
    pub fn read(&mut self) -> io::Result<Option<Vec<u8>>> {
        let mut first = [0u8; 1];
        if self.r.read(&mut first)? == 0 {
            return Ok(None);
        }
        let mut head = [first[0], 0, 0, 0];
        let more = (first[0] & 3) as usize;
        self.r.read_exact(&mut head[1..=more])?;
        let len = (u32::from_le_bytes(head) >> 2) as usize;
        if len > MAX_MESSAGE {
            return Err(invalid(format!("a message of {len} bytes")));
        }
        let mut data = vec![0u8; len];
        self.r.read_exact(&mut data)?;
        Ok(Some(data))
    }
}

/// The two halves of a connection accepted from a listener.
pub fn accepted(stream: TcpStream) -> io::Result<(TcpReader, TcpWriter)> {
    stream.set_nodelay(true)?;
    let r = BufReader::new(stream.try_clone()?);
    Ok((TcpReader { r }, TcpWriter { stream: Arc::new(Mutex::new(stream)) }))
}

/// Either kind of connection, for a program that serves both.
#[derive(Clone)]
pub enum Writer {
    Ws(WsWriter),
    Tcp(TcpWriter),
}

impl Writer {
    pub fn send(&self, data: &[u8]) -> io::Result<()> {
        match self {
            Writer::Ws(w) => w.send(data),
            Writer::Tcp(w) => w.send(data),
        }
    }

    pub fn shutdown(&self) {
        match self {
            Writer::Ws(w) => w.shutdown(),
            Writer::Tcp(w) => w.shutdown(),
        }
    }
}

pub enum Reader {
    Ws(WsReader),
    Tcp(TcpReader),
}

impl Reader {
    pub fn read(&mut self) -> io::Result<Option<Vec<u8>>> {
        match self {
            Reader::Ws(r) => r.read(),
            Reader::Tcp(r) => r.read(),
        }
    }
}

/// Up to and including the blank line, one byte at a time, so that nothing of the first frame is read past it.
fn read_head(r: &mut impl Read) -> io::Result<String> {
    let mut head = Vec::with_capacity(256);
    let mut byte = [0u8; 1];
    while !head.ends_with(b"\r\n\r\n") {
        if head.len() > 8192 {
            return Err(invalid("WebSocket response too long"));
        }
        r.read_exact(&mut byte)?;
        head.push(byte[0]);
    }
    String::from_utf8(head).map_err(|_| invalid("WebSocket response is not text"))
}

fn check_response(head: &str, key: &str) -> io::Result<()> {
    let mut lines = head.split("\r\n");
    let status = lines.next().unwrap_or("");
    if status.split_whitespace().nth(1) != Some("101") {
        return Err(invalid(format!("WebSocket refused: {status}")));
    }
    let want = accept_key(key);
    let accepted = lines.any(|l| {
        l.split_once(':')
            .is_some_and(|(n, v)| n.trim().eq_ignore_ascii_case("sec-websocket-accept") && v.trim() == want)
    });
    if !accepted {
        return Err(invalid("WebSocket answer does not match our key"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::TcpListener;

    #[test]
    fn the_accept_value_of_the_rfc_example() {
        assert_eq!(accept_key("dGhlIHNhbXBsZSBub25jZQ=="), "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=");
    }

    #[test]
    fn urls() {
        assert_eq!(parse_url("ws://a:1").unwrap(), ("a:1".into(), "/".into()));
        assert_eq!(parse_url("ws://a:1/x/y").unwrap(), ("a:1".into(), "/x/y".into()));
        assert!(parse_url("wss://a:1").is_err());
    }

    #[test]
    fn tcp_framing_is_hbb_commons() {
        assert_eq!(encode_tcp_header(0), [0]);
        assert_eq!(encode_tcp_header(0x3f), [0xfc]);
        assert_eq!(encode_tcp_header(0x40), [0x01, 0x01]);
        assert_eq!(encode_tcp_header(0x3fff), [0xfd, 0xff]);
        assert_eq!(encode_tcp_header(0x4000), [0x02, 0x00, 0x01]);
        assert_eq!(encode_tcp_header(0x40_0000), [0x03, 0x00, 0x00, 0x01]);
    }

    #[test]
    fn tcp_messages_of_every_header_size_come_through_whole() {
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = l.local_addr().unwrap();
        let sizes = [0usize, 1, 0x3f, 0x40, 0x3fff, 0x4000, 0x3f_ffff, 0x40_0000];
        let t = std::thread::spawn(move || {
            let (mut r, w) = accepted(l.accept().unwrap().0).unwrap();
            while let Some(m) = r.read().unwrap() {
                w.send(&m).unwrap();
            }
        });
        let (mut r, w) = accepted(TcpStream::connect(addr).unwrap()).unwrap();
        for n in sizes {
            let m = vec![(n % 251) as u8; n];
            let w2 = w.clone();
            let m2 = m.clone();
            // Written from its own thread: the largest doesn't fit in the socket's buffers until the other end reads.
            let s = std::thread::spawn(move || w2.send(&m2).unwrap());
            assert_eq!(r.read().unwrap().unwrap(), m, "{n}");
            s.join().unwrap();
        }
        w.shutdown();
        t.join().unwrap();
    }

    #[test]
    fn a_tcp_message_too_large_is_refused_before_it_is_allocated() {
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = l.local_addr().unwrap();
        let mut c = TcpStream::connect(addr).unwrap();
        let (mut r, _w) = accepted(l.accept().unwrap().0).unwrap();
        c.write_all(&[0xff, 0xff, 0xff, 0xff]).unwrap();
        assert!(r.read().is_err());
    }

    /// A server that answers the handshake and then says what `script` writes to it.
    fn server(script: impl FnOnce(TcpStream) + Send + 'static) -> String {
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = l.local_addr().unwrap();
        std::thread::spawn(move || {
            let (mut s, _) = l.accept().unwrap();
            let mut r = BufReader::new(s.try_clone().unwrap());
            let head = read_head(&mut r).unwrap();
            let key = head.lines().find_map(|l| l.strip_prefix("Sec-WebSocket-Key: ")).unwrap().trim().to_owned();
            write!(s, "HTTP/1.1 101 OK\r\nUpgrade: websocket\r\nSec-WebSocket-Accept: {}\r\n\r\n", accept_key(&key)).unwrap();
            script(s);
        });
        format!("ws://{addr}")
    }

    #[test]
    fn reads_all_three_lengths_a_fragmented_message_and_answers_a_ping() {
        let big = vec![7u8; 70_000];
        let mid = vec![5u8; 300];
        let (b2, m2) = (big.clone(), mid.clone());
        let url = server(move |mut s| {
            s.write_all(&[0x82, 3, 1, 2, 3]).unwrap();
            let mut f = vec![0x82, 126];
            f.extend_from_slice(&(m2.len() as u16).to_be_bytes());
            f.extend_from_slice(&m2);
            s.write_all(&f).unwrap();
            let mut f = vec![0x82, 127];
            f.extend_from_slice(&(b2.len() as u64).to_be_bytes());
            f.extend_from_slice(&b2);
            s.write_all(&f).unwrap();
            // A ping in the middle of a fragmented message.
            s.write_all(&[0x02, 2, 9, 8]).unwrap();
            s.write_all(&[0x89, 1, 42]).unwrap();
            s.write_all(&[0x80, 1, 7]).unwrap();
            // The pong: masked, its body the ping's.
            let mut pong = [0u8; 7];
            s.read_exact(&mut pong).unwrap();
            assert_eq!(pong[0], 0x8a);
            assert_eq!(pong[6] ^ pong[2], 42);
            s.write_all(&[0x88, 0]).unwrap();
        });
        let (mut r, _w) = connect(&url, Duration::from_secs(5)).unwrap();
        assert_eq!(r.read().unwrap().unwrap(), vec![1, 2, 3]);
        assert_eq!(r.read().unwrap().unwrap(), mid);
        assert_eq!(r.read().unwrap().unwrap(), big);
        assert_eq!(r.read().unwrap().unwrap(), vec![9, 8, 7]);
        assert_eq!(r.read().unwrap(), None);
    }

    #[test]
    fn what_it_sends_is_masked_and_a_lie_is_refused() {
        let url = server(|mut s| {
            let mut got = [0u8; 9];
            s.read_exact(&mut got).unwrap();
            assert_eq!(got[0], 0x82);
            assert_eq!(got[1], 0x80 | 3);
            let unmasked: Vec<u8> = got[6..].iter().enumerate().map(|(i, v)| v ^ got[2 + i % 4]).collect();
            assert_eq!(unmasked, b"abc");
            // A frame of 1 TiB.
            let mut f = vec![0x82, 127];
            f.extend_from_slice(&(1u64 << 40).to_be_bytes());
            s.write_all(&f).unwrap();
        });
        let (mut r, w) = connect(&url, Duration::from_secs(5)).unwrap();
        w.send(b"abc").unwrap();
        assert!(r.read().is_err());
    }
}
