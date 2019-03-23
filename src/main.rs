use npcap_sys::{Pcap};
use log::debug;
// use npcap_sys::pcap_freealldevs;
// use log::{debug, error, info, trace};
// use std::ffi::CStr;





fn main() -> Result<(), Box<std::error::Error>> {
    dotenv::dotenv().ok();
    env_logger::init();

    debug!("Pcap::new()");
    let mut pcap = Pcap::new();
    let devices = pcap.get_device_list()?;
    for device in devices.iter() {
        debug!("device: {:?}", device);
    }

    debug!("main() -> OK");
    Ok(())
}

