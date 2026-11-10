//! Lets devices on the home network reach hbbs and hbbr, which publish their WebSocket ports on loopback only and their UDP port
//! not at all. It binds one address, so nothing here is reachable beyond the network that address is on.
//!
//!   lan-bridge <bind ip> tcp:<port>=<target> ... udp:<port>=<target> ...
//!   lan-bridge 192.168.1.55 tcp:21128=127.0.0.1:21128 tcp:21129=127.0.0.1:21129 udp:21116=172.21.0.3:21116
//!
//! A UDP client keeps one socket towards the target for as long as it talks, as hbbs answers the address a host registered from.
use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::{IpAddr, Shutdown, SocketAddr, TcpListener, TcpStream, UdpSocket};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// A UDP client silent for this long is forgotten: a host registers every 12 s.
const UDP_IDLE: Duration = Duration::from_secs(120);

fn copy(mut from: TcpStream, mut to: TcpStream) {
    let mut buf = vec![0u8; 64 * 1024];
    loop {
        match from.read(&mut buf) {
            Ok(0) | Err(_) => break,
            Ok(n) => {
                if to.write_all(&buf[..n]).is_err() {
                    break;
                }
            }
        }
    }
    let _ = to.shutdown(Shutdown::Both);
    let _ = from.shutdown(Shutdown::Both);
}

fn tcp(bind: SocketAddr, target: String) -> std::io::Result<()> {
    let l = TcpListener::bind(bind)?;
    eprintln!("tcp {bind} -> {target}");
    std::thread::spawn(move || {
        for c in l.incoming().flatten() {
            let target = target.clone();
            std::thread::spawn(move || {
                let peer = c.peer_addr().ok();
                let Ok(up) = TcpStream::connect(&target) else {
                    eprintln!("no answer from {target} for {peer:?}");
                    return;
                };
                let _ = c.set_nodelay(true);
                let _ = up.set_nodelay(true);
                let (Ok(c2), Ok(up2)) = (c.try_clone(), up.try_clone()) else { return };
                std::thread::spawn(move || copy(c2, up2));
                copy(up, c);
            });
        }
    });
    Ok(())
}

fn udp(bind: SocketAddr, target: SocketAddr) -> std::io::Result<()> {
    let front = Arc::new(UdpSocket::bind(bind)?);
    eprintln!("udp {bind} -> {target}");
    let clients: Arc<Mutex<HashMap<SocketAddr, (Arc<UdpSocket>, Instant)>>> = Arc::default();
    std::thread::spawn(move || {
        let mut buf = vec![0u8; 64 * 1024];
        loop {
            let Ok((n, from)) = front.recv_from(&mut buf) else { continue };
            let mut map = clients.lock().unwrap();
            map.retain(|_, (_, last)| last.elapsed() < UDP_IDLE);
            let entry = map.entry(from).or_insert_with(|| {
                let up = Arc::new(UdpSocket::bind("0.0.0.0:0").expect("a UDP socket"));
                let (up2, front2) = (up.clone(), front.clone());
                up.connect(target).expect("connect a UDP socket");
                eprintln!("udp client {from}");
                std::thread::spawn(move || {
                    let mut buf = vec![0u8; 64 * 1024];
                    while let Ok(n) = up2.recv(&mut buf) {
                        let _ = front2.send_to(&buf[..n], from);
                    }
                });
                (up, Instant::now())
            });
            entry.1 = Instant::now();
            let _ = entry.0.send(&buf[..n]);
        }
    });
    Ok(())
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let a: Vec<String> = std::env::args().collect();
    let ip: IpAddr = a.get(1).ok_or("lan-bridge <bind ip> tcp:<port>=<target> udp:<port>=<target> ...")?.parse()?;
    if ip.is_unspecified() {
        return Err("name one address: this bridge is for one network".into());
    }
    for rule in &a[2..] {
        let (kind, rest) = rule.split_once(':').ok_or("a rule is tcp:<port>=<target> or udp:<port>=<target>")?;
        let (port, target) = rest.split_once('=').ok_or("a rule is tcp:<port>=<target> or udp:<port>=<target>")?;
        let bind = SocketAddr::new(ip, port.parse()?);
        match kind {
            "tcp" => tcp(bind, target.to_owned())?,
            "udp" => udp(bind, target.parse()?)?,
            other => return Err(format!("unknown kind {other}").into()),
        }
    }
    loop {
        std::thread::park();
    }
}
