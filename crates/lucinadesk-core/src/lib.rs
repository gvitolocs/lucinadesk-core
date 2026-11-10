//! LucinaDesk client core.
//!
//! A sans-IO implementation of the client side of the RustDesk protocol, as spoken by
//! RustDesk 1.4.x hosts through a self-hosted hbbs/hbbr pair over WebSocket:
//!
//! 1. rendezvous (hbbs, ws): `PunchHoleRequest` (force relay) -> `RelayResponse` carrying a
//!    relay uuid and the host's Ed25519 key, signed by the rendezvous server's key;
//! 2. relay (hbbr, ws): `RequestRelay{uuid}`; hbbr then pairs us with the host byte for byte;
//! 3. handshake: host sends `SignedId` (its ephemeral Curve25519 key signed with its Ed25519 key);
//!    we answer `PublicKey` with our ephemeral key and a box-sealed secretbox key; from then on
//!    every message is secretbox-encrypted with counter nonces;
//! 4. login: host sends `Hash{salt, challenge}`, we answer `LoginRequest` with
//!    sha256(sha256(password + salt) + challenge); host answers `LoginResponse{peer_info}`;
//! 5. session: video frames, cursor, test-delay echoes; we send mouse/keyboard events.
//!
//! The transport (WebSockets) and the video decoding (WebCodecs) live in the embedding code:
//! every call takes the bytes of one received WebSocket message and returns the messages to send
//! and the events to show. [`wasm`] wraps this for JavaScript.

pub mod crypto;
pub mod host;
#[cfg(not(target_arch = "wasm32"))]
pub mod net;
#[cfg(target_arch = "wasm32")]
pub mod wasm;

#[allow(clippy::all)]
pub mod hbb {
    include!(concat!(env!("OUT_DIR"), "/hbb.rs"));
}

use base64::Engine;
use crypto::{verify_signed, Encrypt};
use hbb::{message, rendezvous_message as rv, Message, RendezvousMessage};
use prost::Message as _;
use sha2::{Digest, Sha256};

pub const CLIENT_VERSION: &str = "1.4.9";

#[derive(Debug, Clone, PartialEq)]
pub enum Codec {
    Vp8,
    Vp9,
    Av1,
    H264,
    H265,
}

impl Codec {
    pub fn name(&self) -> &'static str {
        match self {
            Codec::Vp8 => "vp8",
            Codec::Vp9 => "vp9",
            Codec::Av1 => "av1",
            Codec::H264 => "h264",
            Codec::H265 => "h265",
        }
    }
}

#[derive(Debug, Clone)]
pub struct Frame {
    pub data: Vec<u8>,
    pub key: bool,
    pub pts: i64,
}

#[derive(Debug, Clone)]
pub struct Display {
    pub x: i32,
    pub y: i32,
    pub width: i32,
    pub height: i32,
    pub name: String,
    pub cursor_embedded: bool,
}

#[derive(Debug, Clone)]
pub enum Event {
    /// hbbs paired us with the host through this relay session.
    Relay { uuid: String, relay_server: String },
    /// The encrypted channel is up (the host's identity was verified).
    Secured,
    LoggedIn {
        hostname: String,
        username: String,
        platform: String,
        version: String,
        displays: Vec<Display>,
        current_display: i32,
    },
    Video { codec: Codec, display: i32, frames: Vec<Frame> },
    CursorPosition { x: i32, y: i32 },
    /// A cursor picture the host will refer to by `id`: RGBA, `width * 4` bytes a row.
    CursorData { id: u64, hotx: i32, hoty: i32, width: i32, height: i32, rgba: Vec<u8> },
    /// The host switched to a cursor it sent before.
    CursorId { id: u64 },
    /// The host's clipboard changed (text only; other formats are dropped).
    Clipboard { text: String },
    /// The host's clipboard holds an image, as PNG (converted from raw RGBA when the host sent that).
    ClipboardImage { png: Vec<u8> },
    /// Session over: login refused, host closed, protocol error.
    Closed { reason: String },
}

#[derive(Debug, Default)]
pub struct Output {
    pub send: Vec<Vec<u8>>,
    pub events: Vec<Event>,
}

#[derive(Debug, Clone, Copy, PartialEq)]
enum Phase {
    Rendezvous,
    Relay,
    AwaitSignedId,
    AwaitHash,
    AwaitLogin,
    Session,
    Closed,
}

/// Which codecs the embedding can decode (WebCodecs probes) and which it prefers.
#[derive(Debug, Clone, Default)]
pub struct Decoding {
    pub vp8: bool,
    pub vp9: bool,
    pub av1: bool,
    pub h264: bool,
    pub h265: bool,
    /// 0 auto, 1 VP9, 2 H264, 3 H265, 4 VP8, 5 AV1 (`SupportedDecoding.PreferCodec`).
    pub prefer: i32,
    /// Frame rate to ask the host for (`OptionMessage.custom_fps`); 0 leaves the host default (30).
    pub custom_fps: i32,
    /// Exchange clipboard text with the host (`OptionMessage.disable_clipboard` = No); off by default.
    pub clipboard: bool,
}

pub struct Session {
    peer_id: String,
    licence_key: String,
    server_pk: [u8; 32],
    password: String,
    decoding: Decoding,
    my_name: String,
    my_platform: String,
    phase: Phase,
    rendezvous_enc: Option<Encrypt>,
    relay_enc: Option<Encrypt>,
    host_pk: Option<[u8; 32]>,
    uuid: String,
    session_id: u64,
}

fn encode<M: prost::Message>(m: &M) -> Vec<u8> {
    m.encode_to_vec()
}

impl Session {
    /// `server_key` is the base64 Ed25519 public key of hbbs (`id_ed25519.pub`); hbbs/hbbr
    /// started with `-k` also require it as the licence key.
    pub fn new(peer_id: &str, server_key: &str, password: &str, decoding: Decoding, my_name: &str) -> Result<Self, String> {
        let raw = base64::engine::general_purpose::STANDARD
            .decode(server_key.trim())
            .map_err(|e| format!("server key is not base64: {e}"))?;
        let server_pk: [u8; 32] = raw.try_into().map_err(|_| "server key must be 32 bytes".to_string())?;
        let mut sid = [0u8; 8];
        crypto::random(&mut sid);
        Ok(Session {
            peer_id: peer_id.to_owned(),
            licence_key: server_key.trim().to_owned(),
            server_pk,
            password: password.to_owned(),
            decoding,
            my_name: my_name.to_owned(),
            my_platform: "Web".to_owned(),
            phase: Phase::Rendezvous,
            rendezvous_enc: None,
            relay_enc: None,
            host_pk: None,
            uuid: String::new(),
            session_id: u64::from_le_bytes(sid),
        })
    }

    /// First message on the hbbs WebSocket.
    pub fn rendezvous_open(&mut self) -> Vec<u8> {
        let req = hbb::PunchHoleRequest {
            id: self.peer_id.clone(),
            nat_type: hbb::NatType::Symmetric as i32,
            licence_key: self.licence_key.clone(),
            conn_type: hbb::ConnType::DefaultConn as i32,
            version: CLIENT_VERSION.into(),
            force_relay: true,
            ..Default::default()
        };
        encode(&RendezvousMessage { union: Some(rv::Union::PunchHoleRequest(req)) })
    }

    pub fn rendezvous_recv(&mut self, data: &[u8]) -> Output {
        let mut out = Output::default();
        if self.phase != Phase::Rendezvous {
            return out;
        }
        let plain = match self.rendezvous_enc.as_mut() {
            Some(e) => match e.decrypt(data) {
                Ok(p) => p,
                Err(err) => return self.close(out, err),
            },
            None => data.to_vec(),
        };
        let msg = match RendezvousMessage::decode(plain.as_slice()) {
            Ok(m) => m,
            Err(e) => return self.close(out, format!("bad rendezvous message: {e}")),
        };
        match msg.union {
            // hbbs may secure the rendezvous channel first (RustDesk >= 1.2 "secure tcp").
            Some(rv::Union::KeyExchange(ex)) => {
                if ex.keys.len() != 1 {
                    return self.close(out, "bad key exchange from rendezvous server".into());
                }
                let their = match verify_signed(&ex.keys[0], &self.server_pk) {
                    Ok(m) if m.len() == 32 => m,
                    _ => return self.close(out, "rendezvous key exchange signature mismatch".into()),
                };
                let (ours, sealed, enc) = crypto::create_symmetric_key(their.as_slice().try_into().unwrap());
                let reply = RendezvousMessage { union: Some(rv::Union::KeyExchange(hbb::KeyExchange { keys: vec![ours, sealed] })) };
                out.send.push(encode(&reply));
                self.rendezvous_enc = Some(enc);
                let mut again = self.rendezvous_open();
                if let Some(e) = self.rendezvous_enc.as_mut() {
                    again = e.encrypt(&again);
                }
                out.send.push(again);
            }
            Some(rv::Union::PunchHoleResponse(r)) => {
                let reason = if !r.other_failure.is_empty() {
                    r.other_failure.clone()
                } else {
                    match hbb::punch_hole_response::Failure::try_from(r.failure) {
                        Ok(hbb::punch_hole_response::Failure::IdNotExist) => "host id not registered".into(),
                        Ok(hbb::punch_hole_response::Failure::Offline) => "host offline".into(),
                        Ok(hbb::punch_hole_response::Failure::LicenseMismatch) => "server key mismatch".into(),
                        Ok(hbb::punch_hole_response::Failure::LicenseOveruse) => "licence overuse".into(),
                        Err(_) => "punch hole refused".into(),
                    }
                };
                return self.close(out, reason);
            }
            Some(rv::Union::RelayResponse(r)) => {
                if !r.refuse_reason.is_empty() {
                    return self.close(out, format!("relay refused: {}", r.refuse_reason));
                }
                match &r.union {
                    Some(hbb::relay_response::Union::Pk(signed)) => match verify_signed(signed, &self.server_pk)
                        .ok()
                        .and_then(|m| hbb::IdPk::decode(m.as_slice()).ok())
                    {
                        Some(idpk) if idpk.id == self.peer_id && idpk.pk.len() == 32 => {
                            self.host_pk = Some(idpk.pk.as_slice().try_into().unwrap());
                        }
                        _ => return self.close(out, "host key from rendezvous server failed verification".into()),
                    },
                    // Without a signed host key we cannot authenticate the host: refuse rather than
                    // fall back to an unencrypted session like stock RustDesk does.
                    _ => return self.close(out, "rendezvous server sent no signed host key".into()),
                }
                self.uuid = r.uuid.clone();
                self.phase = Phase::Relay;
                out.events.push(Event::Relay { uuid: r.uuid, relay_server: r.relay_server });
            }
            _ => {}
        }
        out
    }

    /// First message on the hbbr WebSocket, after [`Event::Relay`].
    pub fn relay_open(&mut self) -> Vec<u8> {
        self.phase = Phase::AwaitSignedId;
        let req = hbb::RequestRelay {
            uuid: self.uuid.clone(),
            licence_key: self.licence_key.clone(),
            conn_type: hbb::ConnType::DefaultConn as i32,
            ..Default::default()
        };
        encode(&RendezvousMessage { union: Some(rv::Union::RequestRelay(req)) })
    }

    pub fn relay_recv(&mut self, data: &[u8]) -> Output {
        let mut out = Output::default();
        let plain = match self.relay_enc.as_mut() {
            // Messages of 0/1 byte are never encrypted (hbb_common's Encrypt::dec skips them).
            Some(e) if data.len() > 1 => match e.decrypt(data) {
                Ok(p) => p,
                Err(err) => return self.close(out, err),
            },
            _ => data.to_vec(),
        };
        let msg = match Message::decode(plain.as_slice()) {
            Ok(m) => m,
            Err(e) => return self.close(out, format!("bad peer message: {e}")),
        };
        let Some(union) = msg.union else { return out };
        match (self.phase, union) {
            (Phase::AwaitSignedId, message::Union::SignedId(si)) => {
                let host_pk = self.host_pk.expect("set in rendezvous");
                let idpk = verify_signed(&si.id, &host_pk).ok().and_then(|m| hbb::IdPk::decode(m.as_slice()).ok());
                match idpk {
                    Some(idpk) if idpk.id == self.peer_id && idpk.pk.len() == 32 => {
                        let (ours, sealed, enc) = crypto::create_symmetric_key(idpk.pk.as_slice().try_into().unwrap());
                        let pk = hbb::PublicKey { asymmetric_value: ours, symmetric_value: sealed };
                        out.send.push(encode(&Message { union: Some(message::Union::PublicKey(pk)) }));
                        self.relay_enc = Some(enc);
                        self.phase = Phase::AwaitHash;
                        out.events.push(Event::Secured);
                    }
                    _ => return self.close(out, "host identity check failed".into()),
                }
            }
            (Phase::AwaitHash, message::Union::Hash(h)) => {
                let first = Sha256::new().chain_update(self.password.as_bytes()).chain_update(h.salt.as_bytes()).finalize();
                let password = Sha256::new().chain_update(first).chain_update(h.challenge.as_bytes()).finalize().to_vec();
                let d = &self.decoding;
                let option = hbb::OptionMessage {
                    image_quality: hbb::ImageQuality::Balanced as i32,
                    show_remote_cursor: hbb::option_message::BoolOption::Yes as i32,
                    disable_audio: hbb::option_message::BoolOption::Yes as i32,
                    disable_clipboard: if d.clipboard {
                        hbb::option_message::BoolOption::No as i32
                    } else {
                        hbb::option_message::BoolOption::Yes as i32
                    },
                    supported_decoding: Some(hbb::SupportedDecoding {
                        ability_vp9: d.vp9 as i32,
                        ability_h264: d.h264 as i32,
                        ability_h265: d.h265 as i32,
                        ability_vp8: d.vp8 as i32,
                        ability_av1: d.av1 as i32,
                        prefer: d.prefer,
                        ..Default::default()
                    }),
                    custom_fps: d.custom_fps,
                    ..Default::default()
                };
                let login = hbb::LoginRequest {
                    username: self.peer_id.clone(),
                    password,
                    my_id: "lucinadesk".into(),
                    my_name: self.my_name.clone(),
                    option: Some(option),
                    video_ack_required: true,
                    session_id: self.session_id,
                    version: CLIENT_VERSION.into(),
                    my_platform: self.my_platform.clone(),
                    ..Default::default()
                };
                self.push(&mut out, Message { union: Some(message::Union::LoginRequest(login)) });
                self.phase = Phase::AwaitLogin;
            }
            (Phase::AwaitLogin | Phase::Session, message::Union::LoginResponse(lr)) => match lr.union {
                Some(hbb::login_response::Union::Error(e)) => return self.close(out, format!("login refused: {e}")),
                Some(hbb::login_response::Union::PeerInfo(pi)) => {
                    self.phase = Phase::Session;
                    out.events.push(Event::LoggedIn {
                        hostname: pi.hostname,
                        username: pi.username,
                        platform: pi.platform,
                        version: pi.version,
                        displays: pi
                            .displays
                            .into_iter()
                            .map(|d| Display {
                                x: d.x,
                                y: d.y,
                                width: d.width,
                                height: d.height,
                                name: d.name,
                                cursor_embedded: d.cursor_embedded,
                            })
                            .collect(),
                        current_display: pi.current_display,
                    });
                }
                None => {}
            },
            (Phase::Session, message::Union::VideoFrame(vf)) => {
                use hbb::video_frame::Union as V;
                let (codec, frames) = match vf.union {
                    Some(V::Vp9s(f)) => (Codec::Vp9, f),
                    Some(V::Vp8s(f)) => (Codec::Vp8, f),
                    Some(V::Av1s(f)) => (Codec::Av1, f),
                    Some(V::H264s(f)) => (Codec::H264, f),
                    Some(V::H265s(f)) => (Codec::H265, f),
                    _ => return out,
                };
                let frames = frames.frames.into_iter().map(|f| Frame { data: f.data, key: f.key, pts: f.pts }).collect();
                out.events.push(Event::Video { codec, display: vf.display, frames });
            }
            (Phase::AwaitHash | Phase::AwaitLogin | Phase::Session, message::Union::TestDelay(t)) if !t.from_client => {
                // Echo it back unchanged: the host measures latency from it and adapts quality.
                // The host sends the next one only after this echo, and its first one can come
                // before login; it drops the connection after 30 s without hearing from us.
                self.push(&mut out, Message { union: Some(message::Union::TestDelay(t)) });
            }
            (Phase::Session, message::Union::CursorPosition(p)) => out.events.push(Event::CursorPosition { x: p.x, y: p.y }),
            (Phase::Session, message::Union::CursorId(id)) => out.events.push(Event::CursorId { id }),
            (Phase::Session, message::Union::CursorData(c)) => {
                if let Some(rgba) = cursor_rgba(&c) {
                    out.events.push(Event::CursorData { id: c.id, hotx: c.hotx, hoty: c.hoty, width: c.width, height: c.height, rgba });
                }
            }
            (Phase::Session, message::Union::Clipboard(cb)) => clipboard_events(std::slice::from_ref(&cb), &mut out.events),
            // RustDesk >= 1.3 sends every format of one copy together: text and/or one image.
            (Phase::Session, message::Union::MultiClipboards(mc)) => clipboard_events(&mc.clipboards, &mut out.events),
            (_, message::Union::Misc(m)) => {
                if let Some(hbb::misc::Union::CloseReason(r)) = m.union {
                    return self.close(out, r);
                }
            }
            _ => {}
        }
        out
    }

    fn push(&mut self, out: &mut Output, m: Message) {
        out.send.push(self.seal(encode(&m)));
    }

    fn seal(&mut self, bytes: Vec<u8>) -> Vec<u8> {
        match self.relay_enc.as_mut() {
            Some(e) => e.encrypt(&bytes),
            None => bytes,
        }
    }

    fn close(&mut self, mut out: Output, reason: String) -> Output {
        self.phase = Phase::Closed;
        out.events.push(Event::Closed { reason });
        out
    }

    pub fn in_session(&self) -> bool {
        self.phase == Phase::Session
    }

    fn session_msg(&mut self, union: message::Union) -> Option<Vec<u8>> {
        if self.phase != Phase::Session {
            return None;
        }
        Some(self.seal(encode(&Message { union: Some(union) })))
    }

    /// `mask` = (buttons << 3) | kind; kind 0 move, 1 down, 2 up, 3 wheel. Buttons: 1 left,
    /// 2 right, 4 middle. Coordinates are absolute host pixels (display x/y offset included);
    /// for wheel, x/y are the scroll steps.
    pub fn mouse(&mut self, mask: i32, x: i32, y: i32) -> Option<Vec<u8>> {
        self.session_msg(message::Union::MouseEvent(hbb::MouseEvent { mask, x, y, modifiers: vec![] }))
    }

    /// Types a string (one KeyEvent `seq`, translated by the host).
    pub fn key_text(&mut self, text: &str) -> Option<Vec<u8>> {
        self.session_msg(message::Union::KeyEvent(hbb::KeyEvent {
            press: true,
            union: Some(hbb::key_event::Union::Seq(text.to_owned())),
            mode: hbb::KeyboardMode::Legacy as i32,
            ..Default::default()
        }))
    }

    /// Presses a `ControlKey` (e.g. Return, Backspace, Escape) with optional modifiers.
    pub fn key_control(&mut self, key: i32, modifiers: Vec<i32>) -> Option<Vec<u8>> {
        self.session_msg(message::Union::KeyEvent(hbb::KeyEvent {
            press: true,
            union: Some(hbb::key_event::Union::ControlKey(key)),
            modifiers,
            mode: hbb::KeyboardMode::Legacy as i32,
            ..Default::default()
        }))
    }

    /// A key going down or up by its position, in the codes of the host's system: X11 keycodes (evdev + 8) on Linux, set 1
    /// scan codes on Windows, virtual key codes on macOS. What a stock RustDesk client sends by default (`KeyboardMode::Map`).
    pub fn key_map(&mut self, code: u32, down: bool) -> Option<Vec<u8>> {
        self.session_msg(message::Union::KeyEvent(hbb::KeyEvent {
            down,
            union: Some(hbb::key_event::Union::Chr(code)),
            mode: hbb::KeyboardMode::Map as i32,
            ..Default::default()
        }))
    }

    /// Clicks one character key with optional modifiers (e.g. Ctrl+L = 'l' + Control).
    pub fn key_char(&mut self, c: char, modifiers: Vec<i32>) -> Option<Vec<u8>> {
        self.session_msg(message::Union::KeyEvent(hbb::KeyEvent {
            press: true,
            union: Some(hbb::key_event::Union::Chr(c as u32)),
            modifiers,
            mode: hbb::KeyboardMode::Legacy as i32,
            ..Default::default()
        }))
    }

    /// Acknowledges a displayed frame (`video_ack_required`): the host paces frames on these.
    pub fn video_ack(&mut self) -> Option<Vec<u8>> {
        self.session_msg(message::Union::Misc(hbb::Misc { union: Some(hbb::misc::Union::VideoReceived(true)) }))
    }

    /// Asks the host for a new key frame (after a decoder error or a reconfigure).
    /// Sets the host's clipboard to `text` (only honoured when the session was opened with `clipboard`).
    pub fn clipboard(&mut self, text: &str) -> Option<Vec<u8>> {
        self.session_msg(message::Union::Clipboard(hbb::Clipboard {
            compress: false,
            content: text.as_bytes().to_vec(),
            format: hbb::ClipboardFormat::Text as i32,
            ..Default::default()
        }))
    }

    /// Sets the host's clipboard to a PNG image (as a one-entry MultiClipboards, which RustDesk >= 1.3 hosts
    /// apply for every format).
    pub fn clipboard_png(&mut self, png: &[u8]) -> Option<Vec<u8>> {
        self.session_msg(message::Union::MultiClipboards(hbb::MultiClipboards {
            clipboards: vec![hbb::Clipboard {
                compress: false,
                content: png.to_vec(),
                format: hbb::ClipboardFormat::ImagePng as i32,
                ..Default::default()
            }],
        }))
    }

    pub fn refresh_video(&mut self) -> Option<Vec<u8>> {
        self.session_msg(message::Union::Misc(hbb::Misc { union: Some(hbb::misc::Union::RefreshVideo(true)) }))
    }
}

/// Who the host is told it talks to: `"Linux"` for a native program. A browser stays `"Web"`, the default.
impl Session {
    pub fn set_platform(&mut self, platform: &str) {
        self.my_platform = platform.to_owned();
    }
}

/// A cursor larger than this on either side is dropped.
pub const MAX_CURSOR: i32 = 512;

/// The cursor's RGBA, zstd-compressed on the wire; `None` if it is damaged or absurd.
fn cursor_rgba(c: &hbb::CursorData) -> Option<Vec<u8>> {
    if c.width <= 0 || c.height <= 0 || c.width > MAX_CURSOR || c.height > MAX_CURSOR {
        return None;
    }
    use std::io::Read;
    let want = c.width as usize * c.height as usize * 4;
    let mut out = Vec::with_capacity(want);
    let dec = ruzstd::streaming_decoder::StreamingDecoder::new(c.colors.as_slice()).ok()?;
    dec.take(want as u64 + 1).read_to_end(&mut out).ok()?;
    (out.len() == want).then_some(out)
}

/// Largest clipboard text accepted from the host, after decompression.
pub const MAX_CLIPBOARD_BYTES: usize = 1 << 20;

/// Largest clipboard image passed on (PNG bytes), and largest raw RGBA accepted before conversion.
pub const MAX_CLIPBOARD_PNG_BYTES: usize = 10 << 20;
const MAX_CLIPBOARD_RGBA_BYTES: usize = 64 << 20;
const PNG_SIGNATURE: &[u8] = b"\x89PNG\r\n\x1a\n";

/// The entry's content, zstd-decompressed when flagged; None past `cap` bytes or on a bad frame.
fn clipboard_bytes(cb: &hbb::Clipboard, cap: usize) -> Option<Vec<u8>> {
    use std::io::Read;
    let bytes = if cb.compress {
        let mut out = Vec::new();
        let dec = ruzstd::streaming_decoder::StreamingDecoder::new(cb.content.as_slice()).ok()?;
        dec.take(cap as u64 + 1).read_to_end(&mut out).ok()?;
        out
    } else {
        cb.content.clone()
    };
    (bytes.len() <= cap).then_some(bytes)
}

/// The text of a host clipboard entry: capped, valid UTF-8 only.
fn clipboard_text(cb: &hbb::Clipboard) -> Option<String> {
    if cb.format != hbb::ClipboardFormat::Text as i32 {
        return None;
    }
    String::from_utf8(clipboard_bytes(cb, MAX_CLIPBOARD_BYTES)?).ok()
}

/// A host clipboard image as PNG: PNG entries pass through (signature checked), raw RGBA is encoded.
fn clipboard_png(cb: &hbb::Clipboard) -> Option<Vec<u8>> {
    let png = match hbb::ClipboardFormat::try_from(cb.format).ok()? {
        hbb::ClipboardFormat::ImagePng => clipboard_bytes(cb, MAX_CLIPBOARD_PNG_BYTES).filter(|b| b.starts_with(PNG_SIGNATURE))?,
        hbb::ClipboardFormat::ImageRgba => {
            let (w, h) = (u32::try_from(cb.width).ok()?, u32::try_from(cb.height).ok()?);
            let want = (w as usize).checked_mul(h as usize)?.checked_mul(4)?;
            if w == 0 || h == 0 || want > MAX_CLIPBOARD_RGBA_BYTES {
                return None;
            }
            let rgba = clipboard_bytes(cb, want).filter(|b| b.len() == want)?;
            let mut out = Vec::new();
            let mut enc = png::Encoder::new(&mut out, w, h);
            enc.set_color(png::ColorType::Rgba);
            enc.set_depth(png::BitDepth::Eight);
            enc.set_compression(png::Compression::Fast);
            enc.write_header().ok()?.write_image_data(&rgba).ok()?;
            out
        }
        _ => return None,
    };
    (png.len() <= MAX_CLIPBOARD_PNG_BYTES).then_some(png)
}

/// One copy on the host: at most one text event and one image event.
fn clipboard_events(entries: &[hbb::Clipboard], events: &mut Vec<Event>) {
    if let Some(text) = entries.iter().find_map(clipboard_text) {
        events.push(Event::Clipboard { text });
    }
    if let Some(png) = entries.iter().find_map(clipboard_png) {
        events.push(Event::ClipboardImage { png });
    }
}

#[cfg(test)]
mod clipboard_tests {
    use super::*;

    fn text_cb(content: Vec<u8>, compress: bool) -> hbb::Clipboard {
        hbb::Clipboard { compress, content, format: hbb::ClipboardFormat::Text as i32, ..Default::default() }
    }

    #[test]
    fn plain_and_compressed_text() {
        assert_eq!(clipboard_text(&text_cb(b"hello".to_vec(), false)).as_deref(), Some("hello"));
        // `printf 'hello world' | zstd -19`: a zstd frame, the format RustDesk's hbb_common::compress produces.
        let frame = vec![
            0x28, 0xb5, 0x2f, 0xfd, 0x04, 0x68, 0x59, 0x00, 0x00, 0x68, 0x65, 0x6c, 0x6c, 0x6f, 0x20, 0x77, 0x6f, 0x72,
            0x6c, 0x64, 0x68, 0x69, 0x1e, 0xb2,
        ];
        assert_eq!(clipboard_text(&text_cb(frame, true)).as_deref(), Some("hello world"));
    }

    #[test]
    fn drops_non_text_bad_utf8_and_oversize() {
        let mut png = text_cb(b"x".to_vec(), false);
        png.format = hbb::ClipboardFormat::ImagePng as i32;
        assert_eq!(clipboard_text(&png), None);
        assert_eq!(clipboard_text(&text_cb(vec![0xff, 0xfe], false)), None);
        assert_eq!(clipboard_text(&text_cb(vec![b'a'; MAX_CLIPBOARD_BYTES + 1], false)), None);
        assert_eq!(clipboard_text(&text_cb(b"garbage".to_vec(), true)), None);
    }

    fn image_cb(format: hbb::ClipboardFormat, content: Vec<u8>, w: i32, h: i32) -> hbb::Clipboard {
        hbb::Clipboard { content, width: w, height: h, format: format as i32, ..Default::default() }
    }

    #[test]
    fn rgba_becomes_png_and_png_passes_through() {
        let rgba: Vec<u8> = (0..2 * 3 * 4).map(|i| i as u8).collect();
        let png = clipboard_png(&image_cb(hbb::ClipboardFormat::ImageRgba, rgba.clone(), 2, 3)).unwrap();
        assert!(png.starts_with(PNG_SIGNATURE));
        let mut reader = png::Decoder::new(png.as_slice()).read_info().unwrap();
        let mut buf = vec![0; reader.output_buffer_size()];
        let info = reader.next_frame(&mut buf).unwrap();
        assert_eq!((info.width, info.height), (2, 3));
        assert_eq!(&buf[..info.buffer_size()], rgba.as_slice());
        assert_eq!(clipboard_png(&image_cb(hbb::ClipboardFormat::ImagePng, png.clone(), 0, 0)), Some(png));
    }

    #[test]
    fn rejects_bad_images() {
        // Wrong RGBA length, zero size, absurd size, PNG without signature, SVG.
        assert_eq!(clipboard_png(&image_cb(hbb::ClipboardFormat::ImageRgba, vec![0; 7], 2, 1)), None);
        assert_eq!(clipboard_png(&image_cb(hbb::ClipboardFormat::ImageRgba, vec![], 0, 0)), None);
        assert_eq!(clipboard_png(&image_cb(hbb::ClipboardFormat::ImageRgba, vec![0; 4], 100_000, 100_000)), None);
        assert_eq!(clipboard_png(&image_cb(hbb::ClipboardFormat::ImagePng, b"not a png".to_vec(), 0, 0)), None);
        assert_eq!(clipboard_png(&image_cb(hbb::ClipboardFormat::ImageSvg, b"<svg/>".to_vec(), 0, 0)), None);
    }

    #[test]
    fn one_copy_gives_text_and_image() {
        let mut ev = Vec::new();
        let png_bytes = [PNG_SIGNATURE, b"rest"].concat();
        clipboard_events(
            &[text_cb(b"caption".to_vec(), false), image_cb(hbb::ClipboardFormat::ImagePng, png_bytes, 0, 0)],
            &mut ev,
        );
        assert!(matches!(&ev[..], [Event::Clipboard { text }, Event::ClipboardImage { .. }] if text == "caption"));
    }
}
