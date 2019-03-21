use npcap_sys::{pcap_findalldevs, errbuf, pcap_if_t, PCAP_ERRBUF_SIZE};
// use npcap_sys::pcap_freealldevs;
use log::{debug, error, info, trace};
use std::ffi::CStr;

pub struct ErrBuf {
    buf: errbuf,
}

impl ErrBuf {
    pub fn new() -> Self {
        Self {
            buf: [0; PCAP_ERRBUF_SIZE],
        }
    }

    pub fn as_ptr(&self) -> *const errbuf {
        &self.buf
    }

    pub fn as_ptr_mut(&mut self) -> *mut errbuf {
        &mut self.buf
    }

    pub fn clear(&mut self) {
        self.buf = [0; PCAP_ERRBUF_SIZE];
    }
}

fn main() -> Result<(), Box<std::error::Error>> {
    dotenv::dotenv().ok();
    env_logger::init();

    let mut err_buf = ErrBuf::new();
    

    get_device_list(&mut err_buf)?;

    Ok(())
}

fn print_errbuf(err_buf: &ErrBuf) {
    trace!("Converting errbuf to string");

    let errbuf_u8 = unsafe { &*(err_buf.as_ptr() as *const[i8] as *const[u8]) };
    let buf = str_from_null_terminated_utf8(&errbuf_u8);

    trace!("errbuf says:  \"{}\"", buf);
    error!("{}", buf);
}

fn str_from_null_terminated_utf8(s: &[u8]) -> &str {
    unsafe { CStr::from_ptr(s.as_ptr() as *const _) }.to_str().unwrap()
}

fn get_device_list(err_buf: &mut ErrBuf) -> Result<(), Box<std::error::Error>> {
    let mut device: *mut pcap_if_t = unsafe { std::mem::uninitialized() };
    let device_ptr: *mut *mut pcap_if_t = &mut device;

    err_buf.clear();

    debug!("\npcap_findalldevs()");
    unsafe { match pcap_findalldevs(device_ptr, err_buf.as_ptr_mut()) {
        0   => {},
        -1  => print_errbuf(&err_buf),
        _   => unreachable!(),
    }}

    info!("Looping through devices");
    loop {
        let this_device = unsafe { (*device) };

        trace!("Converting device name to string");
        let name = unsafe { CStr::from_ptr(this_device.name).to_str()? };

        trace!("Converting device description to string");
        let description = unsafe { CStr::from_ptr(this_device.description).to_str()? };
        
        println!("Dev \"{}\" \"{}\"", name, description);

        if this_device.next.is_null() {
            break;
        } else {
            device = this_device.next;
        }
    }

    

    Ok(())
}