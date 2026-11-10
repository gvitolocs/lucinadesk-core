//! JavaScript bindings. Every `*_recv` returns `{ send: Uint8Array[], events: object[] }`;
//! input methods return the Uint8Array to send on the relay socket, or `undefined` before login.

use crate::{Decoding, Event, Output, Session};
use js_sys::{Array, Object, Reflect, Uint8Array};
use wasm_bindgen::prelude::*;

#[wasm_bindgen]
pub struct Client(Session);

fn set(o: &Object, k: &str, v: impl Into<JsValue>) {
    let _ = Reflect::set(o, &JsValue::from_str(k), &v.into());
}

fn bytes(b: &[u8]) -> Uint8Array {
    Uint8Array::from(b)
}

fn event(e: Event) -> Object {
    let o = Object::new();
    match e {
        Event::Relay { uuid, relay_server } => {
            set(&o, "type", "relay");
            set(&o, "uuid", uuid);
            set(&o, "relayServer", relay_server);
        }
        Event::Secured => set(&o, "type", "secured"),
        Event::LoggedIn { hostname, username, platform, version, displays, current_display } => {
            set(&o, "type", "login");
            set(&o, "hostname", hostname);
            set(&o, "username", username);
            set(&o, "platform", platform);
            set(&o, "version", version);
            set(&o, "currentDisplay", current_display);
            let ds = Array::new();
            for d in displays {
                let x = Object::new();
                set(&x, "x", d.x);
                set(&x, "y", d.y);
                set(&x, "width", d.width);
                set(&x, "height", d.height);
                set(&x, "name", d.name);
                set(&x, "cursorEmbedded", d.cursor_embedded);
                ds.push(&x);
            }
            set(&o, "displays", ds);
        }
        Event::Video { codec, display, frames } => {
            set(&o, "type", "video");
            set(&o, "codec", codec.name());
            set(&o, "display", display);
            let fs = Array::new();
            for f in frames {
                let x = Object::new();
                set(&x, "data", bytes(&f.data));
                set(&x, "key", f.key);
                set(&x, "pts", f.pts as f64);
                fs.push(&x);
            }
            set(&o, "frames", fs);
        }
        // The page draws its own cursor; only the native viewer uses these pictures.
        Event::CursorData { id, .. } | Event::CursorId { id } => {
            set(&o, "type", "cursorId");
            set(&o, "id", id as f64);
        }
        Event::CursorPosition { x, y } => {
            set(&o, "type", "cursorPosition");
            set(&o, "x", x);
            set(&o, "y", y);
        }
        Event::Clipboard { text } => {
            set(&o, "type", "clipboard");
            set(&o, "text", text);
        }
        Event::ClipboardImage { png } => {
            set(&o, "type", "clipboardImage");
            set(&o, "png", bytes(&png));
        }
        Event::Closed { reason } => {
            set(&o, "type", "closed");
            set(&o, "reason", reason);
        }
    }
    o
}

fn output(out: Output) -> Object {
    let o = Object::new();
    let send = Array::new();
    for b in out.send {
        send.push(&bytes(&b));
    }
    let events = Array::new();
    for e in out.events {
        events.push(&event(e));
    }
    set(&o, "send", send);
    set(&o, "events", events);
    o
}

fn opt(b: Option<Vec<u8>>) -> Option<Uint8Array> {
    b.map(|b| bytes(&b))
}

#[wasm_bindgen]
impl Client {
    /// `codecs`: the codecs WebCodecs can decode, e.g. "vp9,av1,h264"; `prefer`: one of them or "".
    #[wasm_bindgen(constructor)]
    pub fn new(peer_id: &str, server_key: &str, password: &str, codecs: &str, prefer: &str, my_name: &str) -> Result<Client, JsError> {
        let has = |c: &str| codecs.split(',').any(|x| x.trim() == c);
        let prefer = match prefer {
            "vp9" => 1,
            "h264" => 2,
            "h265" => 3,
            "vp8" => 4,
            "av1" => 5,
            _ => 0,
        };
        let decoding = Decoding { vp8: has("vp8"), vp9: has("vp9"), av1: has("av1"), h264: has("h264"), h265: has("h265"), prefer, custom_fps: 0, clipboard: false };
        Session::new(peer_id, server_key, password, decoding, my_name).map(Client).map_err(|e| JsError::new(&e))
    }

    #[wasm_bindgen(js_name = rendezvousOpen)]
    pub fn rendezvous_open(&mut self) -> Uint8Array {
        bytes(&self.0.rendezvous_open())
    }

    #[wasm_bindgen(js_name = rendezvousRecv)]
    pub fn rendezvous_recv(&mut self, data: &[u8]) -> Object {
        output(self.0.rendezvous_recv(data))
    }

    #[wasm_bindgen(js_name = relayOpen)]
    pub fn relay_open(&mut self) -> Uint8Array {
        bytes(&self.0.relay_open())
    }

    #[wasm_bindgen(js_name = relayRecv)]
    pub fn relay_recv(&mut self, data: &[u8]) -> Object {
        output(self.0.relay_recv(data))
    }

    pub fn mouse(&mut self, mask: i32, x: i32, y: i32) -> Option<Uint8Array> {
        opt(self.0.mouse(mask, x, y))
    }

    #[wasm_bindgen(js_name = keyText)]
    pub fn key_text(&mut self, text: &str) -> Option<Uint8Array> {
        opt(self.0.key_text(text))
    }

    #[wasm_bindgen(js_name = keyControl)]
    pub fn key_control(&mut self, key: i32, modifiers: Vec<i32>) -> Option<Uint8Array> {
        opt(self.0.key_control(key, modifiers))
    }

    #[wasm_bindgen(js_name = videoAck)]
    pub fn video_ack(&mut self) -> Option<Uint8Array> {
        opt(self.0.video_ack())
    }

    #[wasm_bindgen(js_name = refreshVideo)]
    pub fn refresh_video(&mut self) -> Option<Uint8Array> {
        opt(self.0.refresh_video())
    }
}
