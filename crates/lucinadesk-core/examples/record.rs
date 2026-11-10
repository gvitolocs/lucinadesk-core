//! Records what a host really sends, as an IVF file per run, so that decoders can be compared on the same bytes.
//!
//! LUCINADESK_PASSWORD=... cargo run --release --example record -- ws://127.0.0.1:21128 ws://127.0.0.1:21129 <id> <server key> <vp8|vp9|av1> <seconds> <out.ivf> [fps]
use futures_util::{SinkExt, StreamExt};
use lucinadesk_core::{Decoding, Event, Session};
use std::io::Write;
use std::time::{Duration, Instant};
use tokio_tungstenite::{connect_async, tungstenite::Message as Ws};

fn ivf_header(fourcc: &[u8; 4], w: u16, h: u16) -> Vec<u8> {
    let mut b = Vec::with_capacity(32);
    b.extend_from_slice(b"DKIF");
    b.extend_from_slice(&0u16.to_le_bytes());
    b.extend_from_slice(&32u16.to_le_bytes());
    b.extend_from_slice(fourcc);
    b.extend_from_slice(&w.to_le_bytes());
    b.extend_from_slice(&h.to_le_bytes());
    b.extend_from_slice(&1000u32.to_le_bytes());
    b.extend_from_slice(&1u32.to_le_bytes());
    b.extend_from_slice(&0u32.to_le_bytes());
    b.extend_from_slice(&0u32.to_le_bytes());
    b
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let a: Vec<String> = std::env::args().collect();
    let (rv_url, relay_url, id, key, codec, secs, out_path) = (&a[1], &a[2], &a[3], &a[4], a[5].as_str(), a[6].parse::<u64>()?, &a[7]);
    let fps: i32 = a.get(8).and_then(|s| s.parse().ok()).unwrap_or(30);
    let password = std::env::var("LUCINADESK_PASSWORD")?;
    let (prefer, fourcc): (i32, &[u8; 4]) = match codec {
        "vp9" => (1, b"VP90"),
        "vp8" => (4, b"VP80"),
        "av1" => (5, b"AV01"),
        other => return Err(format!("unknown codec {other}").into()),
    };
    let decoding = Decoding {
        vp8: codec == "vp8",
        vp9: codec == "vp9",
        av1: codec == "av1",
        h264: false,
        h265: false,
        prefer,
        custom_fps: fps,
        clipboard: false,
    };
    let mut s = Session::new(id, key, &password, decoding, "LucinaDesk record")?;

    let (mut rv, _) = connect_async(rv_url.as_str()).await?;
    rv.send(Ws::Binary(s.rendezvous_open())).await?;
    'rv: while let Some(m) = rv.next().await {
        let Ws::Binary(b) = m? else { continue };
        let out = s.rendezvous_recv(&b);
        for b in out.send {
            rv.send(Ws::Binary(b)).await?;
        }
        for e in out.events {
            match e {
                Event::Relay { .. } => break 'rv,
                Event::Closed { reason } => return Err(reason.into()),
                _ => {}
            }
        }
    }
    let _ = rv.close(None).await;

    let (mut relay, _) = connect_async(relay_url.as_str()).await?;
    relay.send(Ws::Binary(s.relay_open())).await?;
    let mut file = std::fs::File::create(out_path)?;
    let (mut size, mut wrote_header) = ((0u16, 0u16), false);
    let (mut frames, mut bytes, mut keys) = (0u32, 0usize, 0u32);
    let mut started: Option<Instant> = None;
    let end = tokio::time::sleep(Duration::from_secs(secs + 15));
    tokio::pin!(end);
    loop {
        let m = tokio::select! {
            m = relay.next() => m,
            _ = &mut end => break,
        };
        let Some(m) = m else { break };
        let Ws::Binary(b) = m? else { continue };
        let out = s.relay_recv(&b);
        for b in out.send {
            relay.send(Ws::Binary(b)).await?;
        }
        for e in out.events {
            match e {
                Event::LoggedIn { displays, current_display, hostname, platform, version, .. } => {
                    let d = &displays[current_display.max(0) as usize];
                    size = (d.width as u16, d.height as u16);
                    eprintln!("logged in to {hostname} ({platform} {version}), {}x{}", d.width, d.height);
                }
                Event::Video { codec: got, frames: fs, .. } => {
                    if !wrote_header {
                        eprintln!("host sends {}", got.name());
                        file.write_all(&ivf_header(fourcc, size.0, size.1))?;
                        wrote_header = true;
                    }
                    let t0 = *started.get_or_insert_with(Instant::now);
                    for f in &fs {
                        let ms = t0.elapsed().as_millis() as u64;
                        file.write_all(&(f.data.len() as u32).to_le_bytes())?;
                        file.write_all(&ms.to_le_bytes())?;
                        file.write_all(&f.data)?;
                        frames += 1;
                        bytes += f.data.len();
                        keys += f.key as u32;
                    }
                    if let Some(ack) = s.video_ack() {
                        relay.send(Ws::Binary(ack)).await?;
                    }
                }
                Event::Closed { reason } => {
                    eprintln!("closed: {reason}");
                    return Ok(());
                }
                _ => {}
            }
        }
        if started.is_some_and(|t| t.elapsed().as_secs() >= secs) {
            break;
        }
    }
    let dur = started.map(|t| t.elapsed().as_secs_f32()).unwrap_or(0.0);
    println!("{codec}: {frames} frames ({keys} key), {:.1} fps, {:.0} kB/s, in {dur:.1} s", frames as f32 / dur.max(0.01), bytes as f32 / 1000.0 / dur.max(0.01));
    Ok(())
}
