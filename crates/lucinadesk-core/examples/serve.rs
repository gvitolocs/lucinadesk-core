//! Minimal static file server for the spike page (loopback only).
//! cargo run --example serve -- <dir> [port]
use std::io::{BufRead, BufReader, Write};
use std::net::TcpListener;
use std::path::{Component, Path};

fn main() -> std::io::Result<()> {
    let a: Vec<String> = std::env::args().collect();
    let root = Path::new(&a[1]).canonicalize()?;
    let port = a.get(2).map(String::as_str).unwrap_or("8790");
    let listener = TcpListener::bind(format!("127.0.0.1:{port}"))?;
    eprintln!("serving {} on http://127.0.0.1:{port}/", root.display());
    for stream in listener.incoming() {
        let mut stream = stream?;
        let mut line = String::new();
        if BufReader::new(&stream).read_line(&mut line).is_err() {
            continue;
        }
        let path = line.split_whitespace().nth(1).unwrap_or("/").split('?').next().unwrap_or("/");
        let rel = Path::new(path.trim_start_matches('/'));
        let file = if rel.components().all(|c| matches!(c, Component::Normal(_))) {
            let p = root.join(rel);
            if p.is_dir() { p.join("index.html") } else { p }
        } else {
            root.join("missing")
        };
        let ctype = match file.extension().and_then(|e| e.to_str()) {
            Some("html") => "text/html; charset=utf-8",
            Some("js") => "text/javascript",
            Some("wasm") => "application/wasm",
            Some("json") => "application/json",
            _ => "application/octet-stream",
        };
        let _ = match std::fs::read(&file) {
            Ok(body) => stream
                .write_all(format!("HTTP/1.1 200 OK\r\nContent-Type: {ctype}\r\nContent-Length: {}\r\nCache-Control: no-store\r\nConnection: close\r\n\r\n", body.len()).as_bytes())
                .and_then(|_| stream.write_all(&body)),
            Err(_) => stream.write_all(b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"),
        };
    }
    Ok(())
}
