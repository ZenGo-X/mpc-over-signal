use std::io::Result;

fn main() -> Result<()> {
    prost_build::compile_protos(
        &[
            "protos/DeviceMessages.proto",
            "protos/SubProtocol.proto",
            "protos/SignalService.proto",
        ],
        &["protos/"],
    )?;
    Ok(())
}
