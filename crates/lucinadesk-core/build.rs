fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("cargo:rerun-if-changed=protos");
    let fds = protox::compile(["message.proto", "rendezvous.proto"], ["protos"])?;
    prost_build::Config::new().compile_fds(fds)?;
    Ok(())
}
