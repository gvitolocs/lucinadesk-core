//! The host side of the RustDesk protocol, sans-IO like the client: what a machine does to be reached.
//!
//! No listening port. The host registers with hbbs over UDP, hbbs tells it when a client asks, and it goes out to hbbr for the
//! session, as RustDesk does when a connection has to be relayed (`rendezvous_mediator.rs`, `server.rs`, `server/connection.rs`
//! in RustDesk 1.4.9):
//!
//! 1. hbbs (UDP): `RegisterPeer` every [`REGISTER_EVERY_SECS`]; `RegisterPk` when asked, or at the start;
//! 2. hbbs says `PunchHole` or `FetchLocalAddr`. Either way we pick a relay uuid, tell hbbs in a `RelayResponse` over a short
//!    connection, and open the relay with `RequestRelay`. hbbs signs our public key for the client;
//! 3. relay: `SignedId` (a fresh box key signed by our Ed25519 key), client's `PublicKey` with the sealed session key;
//! 4. `Hash{salt, challenge}`, `LoginRequest` checked against what is stored: never the password, only sha256(password + salt);
//! 5. session: video frames from us; mouse, keys, acks from the client.
//!
//! What this host refuses: every connection type but a plain desktop session. No file transfer, port forward, terminal or camera.

use crypto_box::{aead::Aead, PublicKey, SalsaBox, SecretKey};
use ed25519_dalek::{Signer, SigningKey};
use prost::Message as _;
use rand_core::OsRng;
use sha2::{Digest, Sha256};

use crate::crypto::{self, Encrypt};
use crate::hbb::{self, message, rendezvous_message as rv, Message, RendezvousMessage};
use crate::CLIENT_VERSION;

/// How often a host says it is there (hbbs's `REG_INTERVAL`).
pub const REGISTER_EVERY_SECS: u64 = 12;

/// What stock clients look for in these words (`client.rs`, `LOGIN_MSG_*`).
pub const WRONG_PASSWORD: &str = "Wrong Password";
pub const EMPTY_PASSWORD: &str = "Empty Password";

/// A machine's identity: chosen once, kept.
pub struct Identity {
    pub id: String,
    pub signing: SigningKey,
    /// hbbs ties the id to this.
    pub uuid: Vec<u8>,
}

/// The password as it is stored. RustDesk's challenge needs only this, so the password itself is never kept.
#[derive(Clone)]
pub struct PasswordRecord {
    pub salt: String,
    pub h1: [u8; 32],
}

impl PasswordRecord {
    pub fn new(password: &str) -> PasswordRecord {
        let mut raw = [0u8; 12];
        crypto::random(&mut raw);
        let salt: String = raw.iter().map(|b| format!("{b:02x}")).collect();
        let h1 = Sha256::new().chain_update(password.as_bytes()).chain_update(salt.as_bytes()).finalize().into();
        PasswordRecord { salt, h1 }
    }
}

/// The signing key from its stored seed.
pub fn signing_key(seed: &[u8; 32]) -> SigningKey {
    SigningKey::from_bytes(seed)
}

fn rendezvous(u: rv::Union) -> Vec<u8> {
    RendezvousMessage { union: Some(u) }.encode_to_vec()
}

pub fn register_peer(id: &str) -> Vec<u8> {
    rendezvous(rv::Union::RegisterPeer(hbb::RegisterPeer { id: id.to_owned(), serial: 0 }))
}

pub fn register_pk(identity: &Identity) -> Vec<u8> {
    rendezvous(rv::Union::RegisterPk(hbb::RegisterPk {
        id: identity.id.clone(),
        uuid: identity.uuid.clone(),
        pk: identity.signing.verifying_key().to_bytes().to_vec(),
        ..Default::default()
    }))
}

/// What hbbs told us.
#[derive(Debug, PartialEq, Eq)]
pub enum RendezvousEvent {
    /// Send [`register_pk`].
    WantsKey,
    /// Registered. `Err` holds hbbs's complaint.
    Registered(Result<(), String>),
    /// A client wants a session: start one with this address.
    Incoming { socket_addr: Vec<u8> },
    Other,
}

pub fn parse_rendezvous(data: &[u8]) -> RendezvousEvent {
    let Ok(m) = RendezvousMessage::decode(data) else { return RendezvousEvent::Other };
    match m.union {
        Some(rv::Union::RegisterPeerResponse(r)) if r.request_pk => RendezvousEvent::WantsKey,
        Some(rv::Union::RegisterPkResponse(r)) => {
            RendezvousEvent::Registered(match hbb::register_pk_response::Result::try_from(r.result) {
                Ok(hbb::register_pk_response::Result::Ok) => Ok(()),
                Ok(other) => Err(format!("{other:?}")),
                Err(_) => Err(format!("result {}", r.result)),
            })
        }
        Some(rv::Union::PunchHole(p)) => RendezvousEvent::Incoming { socket_addr: p.socket_addr },
        Some(rv::Union::FetchLocalAddr(f)) => RendezvousEvent::Incoming { socket_addr: f.socket_addr },
        Some(rv::Union::RequestRelay(r)) => RendezvousEvent::Incoming { socket_addr: r.socket_addr },
        _ => RendezvousEvent::Other,
    }
}

/// A fresh relay uuid, in RustDesk's textual form.
pub fn new_relay_uuid() -> String {
    let mut b = [0u8; 16];
    crypto::random(&mut b);
    b[6] = (b[6] & 0x0f) | 0x40;
    b[8] = (b[8] & 0x3f) | 0x80;
    let h: String = b.iter().map(|v| format!("{v:02x}")).collect();
    format!("{}-{}-{}-{}-{}", &h[..8], &h[8..12], &h[12..16], &h[16..20], &h[20..])
}

/// To hbbs, on a connection of its own: which relay session the client is to join. `relay_server` is what the client will dial.
pub fn relay_response(id: &str, socket_addr: Vec<u8>, uuid: &str, relay_server: &str) -> Vec<u8> {
    rendezvous(rv::Union::RelayResponse(hbb::RelayResponse {
        socket_addr,
        uuid: uuid.to_owned(),
        relay_server: relay_server.to_owned(),
        union: Some(hbb::relay_response::Union::Id(id.to_owned())),
        version: CLIENT_VERSION.to_owned(),
        ..Default::default()
    }))
}

/// The first message on the relay.
pub fn request_relay(uuid: &str, licence_key: &str) -> Vec<u8> {
    rendezvous(rv::Union::RequestRelay(hbb::RequestRelay {
        uuid: uuid.to_owned(),
        licence_key: licence_key.trim().to_owned(),
        ..Default::default()
    }))
}

/// What the session shows the client about this machine.
#[derive(Clone)]
pub struct HostInfo {
    pub hostname: String,
    pub username: String,
    pub platform: String,
    pub width: i32,
    pub height: i32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KeyAction {
    /// A key by position, in the codes this host told the client it has: X keycodes for Linux.
    Position { code: u32, down: bool },
    /// A character, with its own press and release.
    Char { c: u32, down: bool, press: bool, modifiers: Vec<i32> },
    /// `ControlKey` by value.
    Control { key: i32, down: bool, press: bool, modifiers: Vec<i32> },
    /// Text to type.
    Text(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HostEvent {
    /// The password was right. The session has begun: send a key frame.
    LoggedIn { name: String, platform: String, wants_acks: bool },
    LoginFailed { name: String },
    /// As the client sent it; see [`crate::Session::mouse`].
    Mouse { mask: i32, x: i32, y: i32 },
    Key(KeyAction),
    VideoAck,
    /// The client lost track: a key frame is due.
    RefreshVideo,
    /// The client changed its wishes. Zero leaves a value as it was.
    Options { custom_fps: i32, image_quality: i32 },
    Closed { reason: String },
}

#[derive(Debug, Default)]
pub struct HostOutput {
    pub send: Vec<Vec<u8>>,
    pub events: Vec<HostEvent>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Phase {
    AwaitKey,
    AwaitLogin,
    Session,
    Closed,
}

pub struct HostSession {
    password: PasswordRecord,
    info: HostInfo,
    phase: Phase,
    box_sk: SecretKey,
    enc: Option<Encrypt>,
    challenge: String,
    pending_signed_id: Option<Vec<u8>>,
}

fn encode(m: Message) -> Vec<u8> {
    m.encode_to_vec()
}

fn msg(u: message::Union) -> Message {
    Message { union: Some(u) }
}

/// Whether two byte strings are equal, taking the same time wherever they differ.
fn same(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

fn new_challenge() -> String {
    let mut c = [0u8; 8];
    crypto::random(&mut c);
    c.iter().map(|b| format!("{b:02x}")).collect()
}

impl HostSession {
    pub fn new(identity: &Identity, password: PasswordRecord, info: HostInfo) -> HostSession {
        let box_sk = SecretKey::generate(&mut OsRng);
        let idpk = hbb::IdPk { id: identity.id.clone(), pk: box_sk.public_key().as_bytes().to_vec() };
        let body = idpk.encode_to_vec();
        let mut signed = identity.signing.sign(&body).to_bytes().to_vec();
        signed.extend_from_slice(&body);
        let first = encode(msg(message::Union::SignedId(hbb::SignedId { id: signed })));
        let challenge = new_challenge();
        HostSession { password, info, phase: Phase::AwaitKey, box_sk, enc: None, challenge, pending_signed_id: Some(first) }
    }

    /// A client that dialled this host's address, with no server to vouch for either side. As in stock RustDesk (`direct_server`,
    /// `secure_connection`), such a session has no key exchange: **the picture and the input are not encrypted**. The password still
    /// crosses only as a hash over a fresh challenge. Starts at the login.
    pub fn direct(password: PasswordRecord, info: HostInfo) -> HostSession {
        let challenge = new_challenge();
        let hash = hbb::Hash { salt: password.salt.clone(), challenge: challenge.clone() };
        let first = encode(msg(message::Union::Hash(hash)));
        let box_sk = SecretKey::generate(&mut OsRng);
        HostSession { password, info, phase: Phase::AwaitLogin, box_sk, enc: None, challenge, pending_signed_id: Some(first) }
    }

    /// The first message on the connection, once it is there: on a relay, once it has paired us.
    pub fn start(&mut self) -> Vec<u8> {
        self.pending_signed_id.take().unwrap_or_default()
    }

    pub fn in_session(&self) -> bool {
        self.phase == Phase::Session
    }

    fn seal(&mut self, bytes: Vec<u8>) -> Vec<u8> {
        match self.enc.as_mut() {
            Some(e) => e.encrypt(&bytes),
            None => bytes,
        }
    }

    fn close(&mut self, mut out: HostOutput, reason: &str) -> HostOutput {
        self.phase = Phase::Closed;
        out.events.push(HostEvent::Closed { reason: reason.to_owned() });
        out
    }

    pub fn recv(&mut self, data: &[u8]) -> HostOutput {
        let mut out = HostOutput::default();
        let plain = match self.enc.as_mut() {
            // Messages of 0 or 1 byte are never encrypted (hbb_common's Encrypt::dec).
            Some(e) if data.len() > 1 => match e.decrypt(data) {
                Ok(p) => p,
                Err(err) => return self.close(out, &err),
            },
            _ => data.to_vec(),
        };
        let m = match Message::decode(plain.as_slice()) {
            Ok(m) => m,
            Err(e) => return self.close(out, &format!("bad message: {e}")),
        };
        let Some(u) = m.union else { return out };
        match (self.phase, u) {
            (Phase::AwaitKey, message::Union::PublicKey(pk)) => {
                let Ok(theirs): Result<[u8; 32], _> = pk.asymmetric_value.as_slice().try_into() else {
                    return self.close(out, "a client without a session key");
                };
                let key = SalsaBox::new(&PublicKey::from(theirs), &self.box_sk).decrypt(&[0u8; 24].into(), pk.symmetric_value.as_slice());
                let key: [u8; 32] = match key.ok().and_then(|k| k.try_into().ok()) {
                    Some(k) => k,
                    None => return self.close(out, "the session key does not open"),
                };
                self.enc = Some(Encrypt::new(&key));
                self.phase = Phase::AwaitLogin;
                let hash = hbb::Hash { salt: self.password.salt.clone(), challenge: self.challenge.clone() };
                let b = self.seal(encode(msg(message::Union::Hash(hash))));
                out.send.push(b);
            }
            (Phase::AwaitKey, _) => return self.close(out, "the client skipped the key exchange"),
            (Phase::AwaitLogin, message::Union::LoginRequest(lr)) => return self.login(out, lr),
            (Phase::AwaitLogin | Phase::Session, message::Union::TestDelay(t)) => {
                if t.from_client {
                    let b = self.seal(encode(msg(message::Union::TestDelay(t))));
                    out.send.push(b);
                }
            }
            (Phase::Session, message::Union::MouseEvent(me)) => out.events.push(HostEvent::Mouse { mask: me.mask, x: me.x, y: me.y }),
            (Phase::Session, message::Union::KeyEvent(k)) => {
                if let Some(a) = key_action(k) {
                    out.events.push(HostEvent::Key(a));
                }
            }
            (Phase::Session, message::Union::Misc(mi)) => match mi.union {
                Some(hbb::misc::Union::VideoReceived(_)) => out.events.push(HostEvent::VideoAck),
                Some(hbb::misc::Union::RefreshVideo(_)) | Some(hbb::misc::Union::RefreshVideoDisplay(_)) => {
                    out.events.push(HostEvent::RefreshVideo)
                }
                Some(hbb::misc::Union::Option(o)) => {
                    out.events.push(HostEvent::Options { custom_fps: o.custom_fps, image_quality: o.image_quality })
                }
                Some(hbb::misc::Union::CloseReason(r)) => return self.close(out, &r),
                _ => {}
            },
            // Clipboard, audio, file requests and the rest: this host does not take them.
            _ => {}
        }
        out
    }

    fn login(&mut self, mut out: HostOutput, lr: hbb::LoginRequest) -> HostOutput {
        // A plain session or nothing. Refused before the password is looked at, as nothing else is on offer.
        if lr.union.is_some() {
            let b = self.login_error("This host offers desktop sessions only");
            out.send.push(b);
            return self.close(out, "a client asked for something other than a desktop session");
        }
        if lr.password.is_empty() {
            let b = self.login_error(EMPTY_PASSWORD);
            out.send.push(b);
            // The client asks the person and sends LoginRequest again.
            return out;
        }
        let want: [u8; 32] = Sha256::new().chain_update(self.password.h1).chain_update(self.challenge.as_bytes()).finalize().into();
        if !same(&lr.password, &want) {
            let b = self.login_error(WRONG_PASSWORD);
            out.send.push(b);
            out.events.push(HostEvent::LoginFailed { name: lr.my_name.clone() });
            return self.close(out, "wrong password");
        }
        self.phase = Phase::Session;
        let d = hbb::DisplayInfo {
            width: self.info.width,
            height: self.info.height,
            name: "Juno".into(),
            online: true,
            // The pointer is in the pictures: this is the framebuffer.
            cursor_embedded: true,
            scale: 1.0,
            ..Default::default()
        };
        let pi = hbb::PeerInfo {
            username: self.info.username.clone(),
            hostname: self.info.hostname.clone(),
            platform: self.info.platform.clone(),
            displays: vec![d],
            current_display: 0,
            version: CLIENT_VERSION.into(),
            encoding: Some(hbb::SupportedEncoding { vp8: true, ..Default::default() }),
            ..Default::default()
        };
        let resp = hbb::LoginResponse { union: Some(hbb::login_response::Union::PeerInfo(pi)), ..Default::default() };
        let b = self.seal(encode(msg(message::Union::LoginResponse(resp))));
        out.send.push(b);
        out.events.push(HostEvent::LoggedIn { name: lr.my_name, platform: lr.my_platform, wants_acks: lr.video_ack_required });
        if let Some(o) = lr.option {
            out.events.push(HostEvent::Options { custom_fps: o.custom_fps, image_quality: o.image_quality });
        }
        out
    }

    fn login_error(&mut self, why: &str) -> Vec<u8> {
        let resp = hbb::LoginResponse { union: Some(hbb::login_response::Union::Error(why.to_owned())), ..Default::default() };
        self.seal(encode(msg(message::Union::LoginResponse(resp))))
    }

    /// One VP8 frame for the client.
    pub fn video_vp8(&mut self, data: Vec<u8>, key: bool, pts: i64) -> Option<Vec<u8>> {
        if self.phase != Phase::Session {
            return None;
        }
        let frame = hbb::EncodedVideoFrame { data, key, pts };
        let vf = hbb::VideoFrame {
            union: Some(hbb::video_frame::Union::Vp8s(hbb::EncodedVideoFrames { frames: vec![frame] })),
            display: 0,
        };
        Some(self.seal(encode(msg(message::Union::VideoFrame(vf)))))
    }

    /// A latency probe, which also keeps a quiet session alive: the client echoes it.
    pub fn test_delay(&mut self, now_ms: i64) -> Option<Vec<u8>> {
        if self.phase != Phase::Session {
            return None;
        }
        let t = hbb::TestDelay { time: now_ms, from_client: false, ..Default::default() };
        Some(self.seal(encode(msg(message::Union::TestDelay(t)))))
    }

    /// Ends the session for the client, with a reason it shows.
    pub fn goodbye(&mut self, why: &str) -> Option<Vec<u8>> {
        if self.enc.is_none() {
            return None;
        }
        let m = hbb::Misc { union: Some(hbb::misc::Union::CloseReason(why.to_owned())) };
        self.phase = Phase::Closed;
        Some(self.seal(encode(msg(message::Union::Misc(m)))))
    }
}

fn key_action(k: hbb::KeyEvent) -> Option<KeyAction> {
    use hbb::key_event::Union as K;
    let map_mode = k.mode == hbb::KeyboardMode::Map as i32;
    match k.union? {
        K::Chr(c) if map_mode => Some(KeyAction::Position { code: c, down: k.down }),
        K::Chr(c) => Some(KeyAction::Char { c, down: k.down, press: k.press, modifiers: k.modifiers }),
        K::ControlKey(key) => Some(KeyAction::Control { key, down: k.down, press: k.press, modifiers: k.modifiers }),
        K::Seq(s) => Some(KeyAction::Text(s)),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Decoding, Event, Session};

    fn identity() -> Identity {
        Identity { id: "junotest".into(), signing: SigningKey::from_bytes(&[9u8; 32]), uuid: b"uuid-of-this".to_vec() }
    }

    fn info() -> HostInfo {
        HostInfo { hostname: "juno".into(), username: "owner".into(), platform: "Linux".into(), width: 1920, height: 1080 }
    }

    /// Plays hbbs's part for the client, so that the two ends of the core talk to each other.
    fn client(password: &str, identity: &Identity) -> Session {
        let server = SigningKey::from_bytes(&[5u8; 32]);
        let server_key = {
            use base64::Engine;
            base64::engine::general_purpose::STANDARD.encode(server.verifying_key().to_bytes())
        };
        let decoding = Decoding { vp8: true, prefer: 4, ..Decoding::default() };
        let mut s = Session::new(&identity.id, &server_key, password, decoding, "test client").unwrap();
        let idpk = hbb::IdPk { id: identity.id.clone(), pk: identity.signing.verifying_key().to_bytes().to_vec() };
        let body = idpk.encode_to_vec();
        let mut signed = server.sign(&body).to_bytes().to_vec();
        signed.extend_from_slice(&body);
        let rr = rendezvous(rv::Union::RelayResponse(hbb::RelayResponse {
            uuid: "u".into(),
            union: Some(hbb::relay_response::Union::Pk(signed)),
            ..Default::default()
        }));
        let o = s.rendezvous_recv(&rr);
        assert!(matches!(o.events[..], [Event::Relay { .. }]), "{:?}", o.events);
        s.relay_open();
        s
    }

    /// Passes messages both ways until nothing is left; returns what each side reported.
    fn pump(h: &mut HostSession, c: &mut Session, first: Vec<u8>) -> (Vec<HostEvent>, Vec<Event>) {
        let (mut he, mut ce) = (Vec::new(), Vec::new());
        let mut to_client = vec![first];
        for _ in 0..16 {
            let mut to_host = Vec::new();
            for m in to_client.drain(..) {
                let o = c.relay_recv(&m);
                to_host.extend(o.send);
                ce.extend(o.events);
            }
            for m in to_host {
                let o = h.recv(&m);
                to_client.extend(o.send);
                he.extend(o.events);
            }
            if to_client.is_empty() {
                break;
            }
        }
        (he, ce)
    }

    #[test]
    fn the_right_password_opens_a_session_and_everything_flows() {
        let id = identity();
        let mut h = HostSession::new(&id, PasswordRecord::new("correct horse"), info());
        let mut c = client("correct horse", &id);
        let first = h.start();
        let (he, ce) = pump(&mut h, &mut c, first);
        assert!(h.in_session());
        assert!(matches!(he[0], HostEvent::LoggedIn { .. }), "{he:?}");
        let Some(Event::LoggedIn { displays, platform, .. }) = ce.iter().find(|e| matches!(e, Event::LoggedIn { .. })) else {
            panic!("{ce:?}")
        };
        assert_eq!(platform, "Linux");
        assert_eq!((displays[0].width, displays[0].height), (1920, 1080));
        assert!(displays[0].cursor_embedded);

        // A frame reaches the client, and input reaches the host.
        let b = h.video_vp8(vec![1, 2, 3], true, 7).unwrap();
        let o = c.relay_recv(&b);
        let Event::Video { codec, frames, .. } = &o.events[0] else { panic!() };
        assert_eq!(codec, &crate::Codec::Vp8);
        assert_eq!(frames[0].data, vec![1, 2, 3]);
        assert!(frames[0].key);

        let o = h.recv(&c.mouse(1 | 1 << 3, 40, 50).unwrap());
        assert_eq!(o.events, vec![HostEvent::Mouse { mask: 9, x: 40, y: 50 }]);
        let o = h.recv(&c.key_map(38, true).unwrap());
        assert_eq!(o.events, vec![HostEvent::Key(KeyAction::Position { code: 38, down: true })]);
        let o = h.recv(&c.video_ack().unwrap());
        assert_eq!(o.events, vec![HostEvent::VideoAck]);
        let o = h.recv(&c.refresh_video().unwrap());
        assert_eq!(o.events, vec![HostEvent::RefreshVideo]);

        // A probe comes back from the client; the host only takes note.
        let t = h.test_delay(123).unwrap();
        let o = c.relay_recv(&t);
        assert_eq!(o.send.len(), 1);
        let back = h.recv(&o.send[0]);
        assert!(back.send.is_empty() && back.events.is_empty());
    }

    /// What a stock client answers to a direct host's first message.
    fn direct_login(first: &[u8], password: &str) -> Vec<u8> {
        let Ok(Message { union: Some(message::Union::Hash(hash)) }) = Message::decode(first) else { panic!("{first:?}") };
        let h1: [u8; 32] = Sha256::new().chain_update(password.as_bytes()).chain_update(hash.salt.as_bytes()).finalize().into();
        let answer = Sha256::new().chain_update(h1).chain_update(hash.challenge.as_bytes()).finalize().to_vec();
        encode(msg(message::Union::LoginRequest(hbb::LoginRequest { password: answer, my_name: "a client".into(), ..Default::default() })))
    }

    #[test]
    fn a_direct_client_logs_in_with_no_key_exchange() {
        let mut h = HostSession::direct(PasswordRecord::new("correct horse"), info());
        let first = h.start();
        // A stock client's empty first message, as it has no key to check the host against.
        assert!(h.recv(&[]).events.is_empty());
        let o = h.recv(&direct_login(&first, "correct horse"));
        assert!(h.in_session());
        assert!(matches!(o.events[..], [HostEvent::LoggedIn { .. }]), "{:?}", o.events);
        let Ok(Message { union: Some(message::Union::LoginResponse(_)) }) = Message::decode(o.send[0].as_slice()) else { panic!() };
        let raw = encode(msg(message::Union::MouseEvent(hbb::MouseEvent { mask: 9, x: 1, y: 1, modifiers: vec![] })));
        assert_eq!(h.recv(&raw).events, vec![HostEvent::Mouse { mask: 9, x: 1, y: 1 }]);
    }

    #[test]
    fn a_direct_client_gets_nothing_without_the_password() {
        let mut h = HostSession::direct(PasswordRecord::new("correct horse"), info());
        let first = h.start();
        let raw = encode(msg(message::Union::MouseEvent(hbb::MouseEvent { mask: 9, x: 1, y: 1, modifiers: vec![] })));
        assert!(h.recv(&raw).events.is_empty());
        assert!(h.video_vp8(vec![0], true, 0).is_none());
        let o = h.recv(&direct_login(&first, "battery staple"));
        assert!(!h.in_session());
        assert!(o.events.iter().any(|e| matches!(e, HostEvent::LoginFailed { .. })), "{:?}", o.events);
        assert!(h.video_vp8(vec![0], true, 0).is_none());
    }

    #[test]
    fn a_wrong_password_gets_nothing_and_ends_it() {
        let id = identity();
        let mut h = HostSession::new(&id, PasswordRecord::new("correct horse"), info());
        let mut c = client("battery staple", &id);
        let first = h.start();
        let (he, ce) = pump(&mut h, &mut c, first);
        assert!(!h.in_session());
        assert!(he.iter().any(|e| matches!(e, HostEvent::LoginFailed { .. })));
        assert!(ce.iter().any(|e| matches!(e, Event::Closed { reason } if reason.contains(WRONG_PASSWORD))), "{ce:?}");
        assert!(h.video_vp8(vec![0], true, 0).is_none());
        assert!(h.test_delay(0).is_none());
    }

    #[test]
    fn input_before_login_does_nothing() {
        let id = identity();
        let mut h = HostSession::new(&id, PasswordRecord::new("pw"), info());
        let _ = h.start();
        // Unencrypted, before any key: a mouse event is the end of it.
        let raw = encode(msg(message::Union::MouseEvent(hbb::MouseEvent { mask: 9, x: 1, y: 1, modifiers: vec![] })));
        let o = h.recv(&raw);
        assert!(matches!(o.events[..], [HostEvent::Closed { .. }]), "{:?}", o.events);
    }

    #[test]
    fn only_a_desktop_session_is_on_offer() {
        let id = identity();
        let pw = PasswordRecord::new("pw");
        let mut h = HostSession::new(&id, pw.clone(), info());
        let mut c = client("pw", &id);
        let first = h.start();
        // Through the key exchange by hand: the client's own login is a plain one.
        let key = c.relay_recv(&first).send.remove(0);
        let hash_msg = h.recv(&key).send.remove(0);
        // The client's encryption is what we need, so its answer goes unused; the host's cipher decides what it reads next.
        let _ = c.relay_recv(&hash_msg);
        let mut fresh = HostSession::new(&id, pw, info());
        fresh.enc = None;
        fresh.phase = Phase::AwaitLogin;
        let lr = hbb::LoginRequest {
            password: vec![1; 32],
            union: Some(hbb::login_request::Union::FileTransfer(hbb::FileTransfer::default())),
            ..Default::default()
        };
        let o = fresh.recv(&encode(msg(message::Union::LoginRequest(lr))));
        assert!(matches!(o.events[..], [HostEvent::Closed { .. }]), "{:?}", o.events);
        assert!(!fresh.in_session());
    }

    #[test]
    fn rendezvous_messages() {
        let id = identity();
        let m = RendezvousMessage::decode(register_peer("abcdef").as_slice()).unwrap();
        assert!(matches!(m.union, Some(rv::Union::RegisterPeer(p)) if p.id == "abcdef"));
        let m = RendezvousMessage::decode(register_pk(&id).as_slice()).unwrap();
        let Some(rv::Union::RegisterPk(p)) = m.union else { panic!() };
        assert_eq!(p.pk, id.signing.verifying_key().to_bytes().to_vec());
        assert_eq!(
            parse_rendezvous(&rendezvous(rv::Union::RegisterPeerResponse(hbb::RegisterPeerResponse { request_pk: true }))),
            RendezvousEvent::WantsKey
        );
        assert_eq!(
            parse_rendezvous(&rendezvous(rv::Union::PunchHole(hbb::PunchHole { socket_addr: vec![1, 2], ..Default::default() }))),
            RendezvousEvent::Incoming { socket_addr: vec![1, 2] }
        );
        assert_eq!(
            parse_rendezvous(&rendezvous(rv::Union::FetchLocalAddr(hbb::FetchLocalAddr { socket_addr: vec![3], ..Default::default() }))),
            RendezvousEvent::Incoming { socket_addr: vec![3] }
        );
        assert_eq!(new_relay_uuid().len(), 36);
    }

    #[test]
    fn the_stored_record_holds_no_password() {
        let r = PasswordRecord::new("hunter2");
        assert_eq!(r.salt.len(), 24);
        assert!(!r.salt.contains("hunter2"));
        let want: [u8; 32] = Sha256::new().chain_update(b"hunter2").chain_update(r.salt.as_bytes()).finalize().into();
        assert_eq!(r.h1, want);
    }
}
