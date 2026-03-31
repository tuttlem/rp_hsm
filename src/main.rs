#![no_std]
#![no_main]

mod logging;

use panic_halt as _;
use rp235x_hal as hal;

use embedded_hal::digital::OutputPin;
#[cfg(feature = "debug-console")]
use usb_device::{class_prelude::*, prelude::*};
#[cfg(feature = "debug-console")]
use usbd_serial::SerialPort;

#[unsafe(link_section = ".start_block")]
#[used]
pub static IMAGE_DEF: hal::block::ImageDef = hal::block::ImageDef::secure_exe();

const XTAL_FREQ_HZ: u32 = 12_000_000u32;
const LED_ON_TICKS: u64 = 100_000;
const LED_OFF_TICKS: u64 = 900_000;

#[hal::entry]
fn main() -> ! {
    let mut pac = match hal::pac::Peripherals::take() {
        Some(peripherals) => peripherals,
        None => halt(),
    };
    let mut watchdog = hal::Watchdog::new(pac.WATCHDOG);

    let clocks = match hal::clocks::init_clocks_and_plls(
        XTAL_FREQ_HZ,
        pac.XOSC,
        pac.CLOCKS,
        pac.PLL_SYS,
        pac.PLL_USB,
        &mut pac.RESETS,
        &mut watchdog,
    ) {
        Ok(clocks) => clocks,
        Err(_) => halt(),
    };

    let timer = hal::Timer::new_timer0(pac.TIMER0, &mut pac.RESETS, &clocks);
    let sio = hal::Sio::new(pac.SIO);

    let pins = hal::gpio::Pins::new(
        pac.IO_BANK0,
        pac.PADS_BANK0,
        sio.gpio_bank0,
        &mut pac.RESETS,
    );

    let mut led = pins.gpio25.into_push_pull_output();

    #[cfg(feature = "debug-console")]
    let usb_bus = UsbBusAllocator::new(hal::usb::UsbBus::new(
        pac.USB,
        pac.USB_DPRAM,
        clocks.usb_clock,
        true,
        &mut pac.RESETS,
    ));

    #[cfg(feature = "debug-console")]
    let mut serial = SerialPort::new(&usb_bus);

    #[cfg(feature = "debug-console")]
    let mut usb_dev = UsbDeviceBuilder::new(&usb_bus, UsbVidPid(0x1209, 0x0001))
        .strings(&[StringDescriptors::default()
            .manufacturer("Tuttle Labs")
            .product("RP2350 HSM")
            .serial_number("TEST")])
        .unwrap_or_else(|_| halt())
        .max_packet_size_0(64)
        .unwrap_or_else(|_| halt())
        .device_class(usbd_serial::USB_CLASS_CDC)
        .build();

    #[cfg(feature = "debug-console")]
    let mut buf = [0u8; 64];
    let mut led_is_on = false;
    let mut next_toggle_at = timer.get_counter().ticks();
    #[cfg(feature = "debug-console")]
    let mut host_connected = false;

    #[cfg(feature = "debug-console")]
    logln!("boot");
    #[cfg(feature = "debug-console")]
    logln!("rp_hsm starting");

    loop {
        #[cfg(feature = "debug-console")]
        if usb_dev.poll(&mut [&mut serial]) {
            let dtr = serial.dtr();
            if dtr && !host_connected {
                host_connected = true;
                logln!("console connected");
            } else if !dtr && host_connected {
                host_connected = false;
            }

            if host_connected
                && let Ok(count) = serial.read(&mut buf)
                && count > 0
            {
                // Consume debug input without interpreting or echoing it in release firmware.
                for byte in &mut buf[..count] {
                    *byte = 0;
                }
            }
        }

        #[cfg(feature = "debug-console")]
        if host_connected {
            logging::flush(&mut serial);
        }

        #[cfg(not(feature = "debug-console"))]
        logging::flush();

        let now = timer.get_counter().ticks();
        if now >= next_toggle_at {
            led_is_on = !led_is_on;

            if led_is_on {
                led.set_high().ok();
                #[cfg(feature = "debug-console")]
                logln!("heartbeat: on");
                next_toggle_at = now + LED_ON_TICKS;
            } else {
                led.set_low().ok();
                #[cfg(feature = "debug-console")]
                logln!("heartbeat: off");
                next_toggle_at = now + LED_OFF_TICKS;
            }
        }
    }
}

fn halt() -> ! {
    loop {
        core::hint::spin_loop();
    }
}
