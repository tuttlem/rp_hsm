#![cfg_attr(
    all(target_os = "none", any(target_arch = "riscv32", target_arch = "arm")),
    no_std
)]
#![cfg_attr(
    all(target_os = "none", any(target_arch = "riscv32", target_arch = "arm")),
    no_main
)]

#[cfg(all(target_os = "none", any(target_arch = "riscv32", target_arch = "arm")))]
mod logging;

#[cfg(all(target_os = "none", any(target_arch = "riscv32", target_arch = "arm")))]
use embedded_hal::digital::OutputPin;
#[cfg(all(target_os = "none", any(target_arch = "riscv32", target_arch = "arm")))]
use panic_halt as _;
#[cfg(all(
    target_os = "none",
    any(target_arch = "riscv32", target_arch = "arm"),
    feature = "debug-console"
))]
use protocol::protocol::{
    DeviceState, ProtocolEngine, SessionState, clear_transient_buffer,
};
#[cfg(all(target_os = "none", any(target_arch = "riscv32", target_arch = "arm")))]
use rp235x_hal as hal;
#[cfg(all(
    target_os = "none",
    any(target_arch = "riscv32", target_arch = "arm"),
    feature = "debug-console"
))]
use usb_device::{class_prelude::*, prelude::*};
#[cfg(all(
    target_os = "none",
    any(target_arch = "riscv32", target_arch = "arm"),
    feature = "debug-console"
))]
use usbd_serial::SerialPort;

#[cfg(all(target_os = "none", any(target_arch = "riscv32", target_arch = "arm")))]
#[unsafe(link_section = ".start_block")]
#[used]
pub static IMAGE_DEF: hal::block::ImageDef = hal::block::ImageDef::secure_exe();

#[cfg(all(target_os = "none", any(target_arch = "riscv32", target_arch = "arm")))]
const XTAL_FREQ_HZ: u32 = 12_000_000u32;
#[cfg(all(target_os = "none", any(target_arch = "riscv32", target_arch = "arm")))]
const LED_ON_TICKS: u64 = 100_000;
#[cfg(all(target_os = "none", any(target_arch = "riscv32", target_arch = "arm")))]
const LED_OFF_TICKS: u64 = 900_000;

#[cfg(all(target_os = "none", any(target_arch = "riscv32", target_arch = "arm")))]
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
    #[cfg(feature = "debug-console")]
    let mut protocol_engine =
        ProtocolEngine::new(DeviceState::Operational, SessionState::Unauthenticated);
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
                let response = protocol_engine.handle_bytes(&buf[..count]);
                if let Some(encoded) = protocol::protocol::encode_frame(&response) {
                    let _ = serial.write(&encoded);
                }
                clear_transient_buffer(&mut buf[..count]);
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

#[cfg(all(target_os = "none", any(target_arch = "riscv32", target_arch = "arm")))]
fn halt() -> ! {
    loop {
        core::hint::spin_loop();
    }
}

#[cfg(not(all(target_os = "none", any(target_arch = "riscv32", target_arch = "arm"))))]
fn main() {}
