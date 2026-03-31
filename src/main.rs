#![no_std]
#![no_main]

mod logging;

use panic_halt as _;
use rp235x_hal as hal;

use embedded_hal::digital::OutputPin;
use usb_device::{class_prelude::*, prelude::*};
use usbd_serial::SerialPort;

#[unsafe(link_section = ".start_block")]
#[used]
pub static IMAGE_DEF: hal::block::ImageDef = hal::block::ImageDef::secure_exe();

const XTAL_FREQ_HZ: u32 = 12_000_000u32;

#[hal::entry]
fn main() -> ! {
    let mut pac = hal::pac::Peripherals::take().unwrap();
    let mut watchdog = hal::Watchdog::new(pac.WATCHDOG);

    let clocks = hal::clocks::init_clocks_and_plls(
        XTAL_FREQ_HZ,
        pac.XOSC,
        pac.CLOCKS,
        pac.PLL_SYS,
        pac.PLL_USB,
        &mut pac.RESETS,
        &mut watchdog,
    )
        .unwrap();

    let timer = hal::Timer::new_timer0(pac.TIMER0, &mut pac.RESETS, &clocks);
    let sio = hal::Sio::new(pac.SIO);

    let pins = hal::gpio::Pins::new(
        pac.IO_BANK0,
        pac.PADS_BANK0,
        sio.gpio_bank0,
        &mut pac.RESETS,
    );

    let mut led = pins.gpio25.into_push_pull_output();

    let usb_bus = UsbBusAllocator::new(hal::usb::UsbBus::new(
        pac.USB,
        pac.USB_DPRAM,
        clocks.usb_clock,
        true,
        &mut pac.RESETS,
    ));

    let mut serial = SerialPort::new(&usb_bus);

    let mut usb_dev = UsbDeviceBuilder::new(&usb_bus, UsbVidPid(0x1209, 0x0001))
        .strings(&[StringDescriptors::default()
            .manufacturer("Tuttle Labs")
            .product("RP2350 HSM")
            .serial_number("TEST")])
        .unwrap()
        .max_packet_size_0(64)
        .unwrap()
        .device_class(usbd_serial::USB_CLASS_CDC)
        .build();

    let mut buf = [0u8; 64];
    let mut led_is_on = false;
    let mut next_toggle_at = timer.get_counter().ticks();
    let mut host_connected = false;

    logln!("boot");
    logln!("rp_hsm starting");

    loop {
        if usb_dev.poll(&mut [&mut serial]) {
            let dtr = serial.dtr();
            if dtr && !host_connected {
                host_connected = true;
                logln!("console connected");
            } else if !dtr && host_connected {
                host_connected = false;
            }

            if host_connected {
                if let Ok(count) = serial.read(&mut buf) {
                    if count > 0 {
                        let _ = serial.write(&buf[..count]);
                    }
                }
            }
        }

        if host_connected {
            logging::flush(&mut serial);
        }

        let now = timer.get_counter().ticks();
        if now >= next_toggle_at {
            led_is_on = !led_is_on;

            if led_is_on {
                led.set_high().ok();
                logln!("heartbeat: on");
                next_toggle_at = now + 100_000;
            } else {
                led.set_low().ok();
                logln!("heartbeat: off");
                next_toggle_at = now + 900_000;
            }
        }
    }
}
