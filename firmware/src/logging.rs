#[cfg(feature = "debug-console")]
use core::cell::RefCell;
#[cfg(feature = "debug-console")]
use core::fmt::{self, Write};

#[cfg(feature = "debug-console")]
use critical_section::Mutex;
#[cfg(feature = "debug-console")]
use heapless::Deque;
#[cfg(feature = "debug-console")]
use usb_device::bus::UsbBus;
#[cfg(feature = "debug-console")]
use usbd_serial::SerialPort;

#[macro_export]
macro_rules! log {
    ($($arg:tt)*) => {
        $crate::logging::print_args(core::format_args!($($arg)*))
    };
}

#[macro_export]
macro_rules! logln {
    () => {
        $crate::log!("\r\n")
    };
    ($fmt:expr) => {
        $crate::log!(concat!($fmt, "\r\n"))
    };
    ($fmt:expr, $($arg:tt)*) => {
        $crate::log!(concat!($fmt, "\r\n"), $($arg)*)
    };
}

#[cfg(feature = "debug-console")]
const LOG_BUFFER_SIZE: usize = 1024;

#[cfg(feature = "debug-console")]
static LOG_BUFFER: Mutex<RefCell<Deque<u8, LOG_BUFFER_SIZE>>> =
    Mutex::new(RefCell::new(Deque::new()));

#[cfg(feature = "debug-console")]
pub struct Logger;

#[cfg(feature = "debug-console")]
impl Write for Logger {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        critical_section::with(|cs| {
            let buffer = &mut *LOG_BUFFER.borrow_ref_mut(cs);
            for byte in s.bytes() {
                let _ = buffer.push_back(byte);
            }
        });
        Ok(())
    }
}

#[cfg(feature = "debug-console")]
pub fn print_args(args: fmt::Arguments<'_>) {
    let mut logger = Logger;
    let _ = logger.write_fmt(args);
}

#[cfg(not(feature = "debug-console"))]
#[allow(dead_code)]
pub fn print_args(_: core::fmt::Arguments<'_>) {}

#[cfg(feature = "debug-console")]
pub fn flush<B: UsbBus>(serial: &mut SerialPort<'_, B>) {
    let mut chunk = [0u8; 64];
    let mut count = 0usize;

    critical_section::with(|cs| {
        let buffer = &mut *LOG_BUFFER.borrow_ref_mut(cs);
        while count < chunk.len() {
            match buffer.pop_front() {
                Some(byte) => {
                    chunk[count] = byte;
                    count += 1;
                }
                None => break,
            }
        }
    });

    if count == 0 {
        return;
    }

    match serial.write(&chunk[..count]) {
        Ok(written) if written < count => {
            critical_section::with(|cs| {
                let buffer = &mut *LOG_BUFFER.borrow_ref_mut(cs);
                for &byte in chunk[written..count].iter().rev() {
                    let _ = buffer.push_front(byte);
                }
            });
        }
        Err(_) => {
            critical_section::with(|cs| {
                let buffer = &mut *LOG_BUFFER.borrow_ref_mut(cs);
                for &byte in chunk[..count].iter().rev() {
                    let _ = buffer.push_front(byte);
                }
            });
        }
        _ => {}
    }
}

#[cfg(not(feature = "debug-console"))]
pub fn flush() {}
