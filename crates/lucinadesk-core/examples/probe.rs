//! Native end-to-end probe: connects to hbbs/hbbr over WebSocket exactly like the browser does,
//! logs in, counts video frames for a few seconds and moves the mouse.
//!
//! LUCINADESK_PASSWORD=... cargo run --example probe -- ws://127.0.0.1:21128 ws://127.0.0.1:21129 lucinaws <server key>
use futures_util::{SinkExt, StreamExt};
use lucinadesk_core::{Decoding, Event, Session};
use std::time::{Duration, Instant};
use tokio_tungstenite::{connect_async, tungstenite::Message as Ws};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let a: Vec<String> = std::env::args().collect();
    let (rv_url, relay_url, id, key) = (&a[1], &a[2], &a[3], &a[4]);
    let password = std::env::var("LUCINADESK_PASSWORD")?;
    let secs: u64 = std::env::var("PROBE_SECS").ok().and_then(|s| s.parse().ok()).unwrap_or(5);
    let decoding = Decoding { vp8: true, vp9: true, av1: true, h264: false, h265: false, prefer: 1, custom_fps: 60, clipboard: false };
    let mut s = Session::new(id, key, &password, decoding, "LucinaDesk probe")?;
    let t0 = Instant::now();

    let (mut rv, _) = connect_async(rv_url.as_str()).await?;
    rv.send(Ws::Binary(s.rendezvous_open())).await?;
    let mut relay_ready = false;
    while let Some(m) = rv.next().await {
        let Ws::Binary(b) = m? else { continue };
        let out = s.rendezvous_recv(&b);
        for b in out.send {
            rv.send(Ws::Binary(b)).await?;
        }
        for e in out.events {
            println!("{:>6} ms rendezvous {:?}", t0.elapsed().as_millis(), e);
            match e {
                Event::Relay { .. } => relay_ready = true,
                Event::Closed { reason } => return Err(reason.into()),
                _ => {}
            }
        }
        if relay_ready {
            break;
        }
    }
    let _ = rv.close(None).await;

    let (mut relay, _) = connect_async(relay_url.as_str()).await?;
    relay.send(Ws::Binary(s.relay_open())).await?;
    let (mut frames, mut bytes, mut keyframes) = (0u32, 0usize, 0u32);
    let mut first_frame: Option<Instant> = None;
    let mut size = (0, 0);
    let deadline = tokio::time::sleep(Duration::from_secs(secs + 10));
    tokio::pin!(deadline);
    loop {
        let m = tokio::select! {
            m = relay.next() => m,
            _ = &mut deadline => break,
        };
        let Some(m) = m else { break };
        let Ws::Binary(b) = m? else { continue };
        let out = s.relay_recv(&b);
        for b in out.send {
            relay.send(Ws::Binary(b)).await?;
        }
        for e in out.events {
            match e {
                Event::Video { codec, frames: fs, .. } => {
                    if first_frame.is_none() {
                        first_frame = Some(Instant::now());
                        println!("{:>6} ms first frame ({})", t0.elapsed().as_millis(), codec.name());
                    }
                    for f in &fs {
                        frames += 1;
                        bytes += f.data.len();
                        keyframes += f.key as u32;
                    }
                    if let Some(ack) = s.video_ack() {
                        relay.send(Ws::Binary(ack)).await?;
                    }
                    // Wiggle the mouse so the desktop changes and frames keep coming.
                    let n = frames as i32;
                    if let Some(m) = s.mouse(0, size.0 / 2 + (n % 40) * 5, size.1 / 2) {
                        relay.send(Ws::Binary(m)).await?;
                    }
                }
                Event::LoggedIn { ref displays, .. } => {
                    size = (displays[0].width, displays[0].height);
                    println!("{:>6} ms {:?}", t0.elapsed().as_millis(), e);
                }
                Event::Closed { reason } => return Err(reason.into()),
                e => println!("{:>6} ms {:?}", t0.elapsed().as_millis(), e),
            }
        }
        if let Some(f) = first_frame {
            if f.elapsed() >= Duration::from_secs(secs) {
                break;
            }
        }
    }
    let span = first_frame.map(|f| f.elapsed().as_secs_f64()).unwrap_or(0.0);
    println!(
        "frames={frames} keyframes={keyframes} bytes={bytes} span={span:.1}s fps={:.1} kbps={:.0}",
        frames as f64 / span.max(0.001),
        bytes as f64 * 8.0 / 1000.0 / span.max(0.001)
    );
    if frames == 0 {
        return Err("no video".into());
    }
    Ok(())
}
