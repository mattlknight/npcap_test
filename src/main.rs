use npcap_sys::{Pcap};
use log::debug;

fn main() -> Result<(), Box<std::error::Error>> {
    dotenv::dotenv().ok();
    env_logger::init();

    let mut pcap = Pcap::new();
    let devices = pcap.get_device_list()?;
    debug!("\nDevices Found:");
    for device in devices.iter() {
        println!("  {}", device);
    }

    debug!("main() -> OK");
    Ok(())
}
