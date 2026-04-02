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
mod persistence;

#[cfg(all(target_os = "none", any(target_arch = "riscv32", target_arch = "arm")))]
use embedded_hal::digital::OutputPin;
#[cfg(all(target_os = "none", any(target_arch = "riscv32", target_arch = "arm")))]
use panic_halt as _;
#[cfg(all(
    target_os = "none",
    any(target_arch = "riscv32", target_arch = "arm"),
    feature = "developer-mode"
))]
use protocol::protocol::{
    DeviceState, FirmwareAction, HEADER_LEN, MAX_FRAME_LEN, MAX_PAYLOAD_LEN, ProtocolEngine,
    SessionState, StatusCode, clear_transient_buffer, status_response,
};
#[cfg(all(target_os = "none", any(target_arch = "riscv32", target_arch = "arm")))]
use rp235x_hal as hal;
#[cfg(all(
    target_os = "none",
    any(target_arch = "riscv32", target_arch = "arm"),
    feature = "developer-mode"
))]
use usb_device::{class_prelude::*, prelude::*};
#[cfg(all(
    target_os = "none",
    any(target_arch = "riscv32", target_arch = "arm"),
    feature = "developer-mode"
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
    let Some(mut pac) = hal::pac::Peripherals::take() else {
        halt();
    };
    let mut watchdog = hal::Watchdog::new(pac.WATCHDOG);

    let Ok(clocks) = hal::clocks::init_clocks_and_plls(
        XTAL_FREQ_HZ,
        pac.XOSC,
        pac.CLOCKS,
        pac.PLL_SYS,
        pac.PLL_USB,
        &mut pac.RESETS,
        &mut watchdog,
    ) else {
        halt();
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

    #[cfg(feature = "developer-mode")]
    let usb_bus = UsbBusAllocator::new(hal::usb::UsbBus::new(
        pac.USB,
        pac.USB_DPRAM,
        clocks.usb_clock,
        true,
        &mut pac.RESETS,
    ));

    #[cfg(feature = "developer-mode")]
    let mut serial = SerialPort::new(&usb_bus);

    #[cfg(feature = "developer-mode")]
    let mut usb_dev = UsbDeviceBuilder::new(&usb_bus, UsbVidPid(0x1209, 0x0001))
        .strings(&[StringDescriptors::default()
            .manufacturer("Tuttle Labs")
            .product("RP2350 HSM Developer Mode")
            .serial_number("DEV")])
        .unwrap_or_else(|_| halt())
        .max_packet_size_0(64)
        .unwrap_or_else(|_| halt())
        .device_class(usbd_serial::USB_CLASS_CDC)
        .build();

    #[cfg(feature = "developer-mode")]
    let mut io_buf = [0u8; 64];
    #[cfg(feature = "developer-mode")]
    let mut frame_buf = [0u8; MAX_FRAME_LEN];
    #[cfg(feature = "developer-mode")]
    let mut frame_len = 0usize;
    #[cfg(feature = "developer-mode")]
    let mut protocol_engine = ProtocolEngine::new(DeviceState::Factory, SessionState::Developer);
    #[cfg(feature = "developer-mode")]
    protocol_engine.set_developer_mode(true);
    #[cfg(feature = "developer-mode")]
    if let Ok(Some(boot_random)) = hal::rom_data::sys_info_api::boot_random() {
        let mut seed = [0u8; 32];
        let boot_bytes = boot_random.0.to_le_bytes();
        seed[..16].copy_from_slice(&boot_bytes);
        seed[16..].copy_from_slice(&boot_bytes);
        protocol_engine.seed_rng(seed);
    }
    #[cfg(feature = "developer-mode")]
    #[cfg(feature = "developer-mode")]
    match persistence::FlashStateStore::load() {
        Ok(persistence::LoadOutcome::Restored(state)) => {
            protocol_engine.restore_provisioning_snapshot(state.provisioning);
            protocol_engine.restore_key_store(state.key_store);
            protocol_engine.restore_auth_snapshot(state.auth);
            protocol_engine.restore_crypto_persistent_state(state.crypto);
        }
        Ok(persistence::LoadOutcome::Corrupted) => {
            let fallback = persistence::corrupted_recovery_state();
            protocol_engine.restore_provisioning_snapshot(fallback.provisioning);
            protocol_engine.restore_key_store(fallback.key_store);
            protocol_engine.restore_auth_snapshot(fallback.auth);
            protocol_engine.restore_crypto_persistent_state(fallback.crypto);
        }
        Ok(persistence::LoadOutcome::Empty) | Err(_) => {}
    }
    #[cfg(feature = "developer-mode")]
    protocol_engine.reconcile_boot();
    #[cfg(feature = "developer-mode")]
    let _ = persistence::FlashStateStore::save(&persistence::PersistedState {
        provisioning: protocol_engine.provisioning_snapshot(),
        key_store: protocol_engine.key_store().snapshot(),
        auth: protocol_engine.auth_snapshot().clone(),
        crypto: protocol_engine.crypto_persistent_state(),
    });
    let mut led_is_on = false;
    let mut next_toggle_at = timer.get_counter().ticks();
    #[cfg(feature = "developer-mode")]
    let mut host_connected = false;

    loop {
        #[cfg(feature = "developer-mode")]
        if usb_dev.poll(&mut [&mut serial]) {
            let dtr = serial.dtr();
            if dtr && !host_connected {
                host_connected = true;
            } else if !dtr && host_connected {
                host_connected = false;
            }

            if host_connected
                && let Ok(count) = serial.read(&mut io_buf)
                && count > 0
            {
                let available = MAX_FRAME_LEN.saturating_sub(frame_len);
                let copy_len = count.min(available);
                frame_buf[frame_len..frame_len + copy_len].copy_from_slice(&io_buf[..copy_len]);
                frame_len = frame_len.saturating_add(copy_len);
                clear_transient_buffer(&mut io_buf[..count]);

                if frame_len < HEADER_LEN {
                    continue;
                }

                let payload_len = usize::from(u16::from_le_bytes([frame_buf[4], frame_buf[5]]));
                if payload_len > MAX_PAYLOAD_LEN {
                    let response = status_response(StatusCode::FormatError, &[]);
                    if let Some(encoded) = protocol::protocol::encode_frame(&response) {
                        let _ = serial.write(&encoded);
                    }
                    clear_transient_buffer(&mut frame_buf[..frame_len]);
                    frame_len = 0;
                    continue;
                }

                let expected_len = HEADER_LEN.saturating_add(payload_len);
                if expected_len > MAX_FRAME_LEN {
                    let response = status_response(StatusCode::FormatError, &[]);
                    if let Some(encoded) = protocol::protocol::encode_frame(&response) {
                        let _ = serial.write(&encoded);
                    }
                    clear_transient_buffer(&mut frame_buf[..frame_len]);
                    frame_len = 0;
                    continue;
                }
                if frame_len < expected_len {
                    continue;
                }

                let prior_provisioning = protocol_engine.provisioning_snapshot();
                let prior_key_store = protocol_engine.key_store().snapshot();
                let prior_auth = protocol_engine.auth_snapshot().clone();
                let prior_crypto = protocol_engine.crypto_persistent_state();
                let mut response = protocol_engine.handle_bytes(&frame_buf[..expected_len]);
                let mut reboot_requested = false;
                if response.code == StatusCode::Success.as_u8() {
                    let current_provisioning = protocol_engine.provisioning_snapshot();
                    let current_key_store = protocol_engine.key_store().snapshot();
                    let current_auth = protocol_engine.auth_snapshot().clone();
                    let current_crypto = protocol_engine.crypto_persistent_state();
                    if current_provisioning != prior_provisioning
                        || current_key_store != prior_key_store
                        || current_auth != prior_auth
                        || current_crypto != prior_crypto
                    {
                        let persist_result = persistence::FlashStateStore::save(&persistence::PersistedState {
                            provisioning: current_provisioning.clone(),
                            key_store: current_key_store.clone(),
                            auth: current_auth.clone(),
                            crypto: current_crypto,
                        });
                        if persist_result.is_err() {
                            protocol_engine.restore_provisioning_snapshot(prior_provisioning);
                            protocol_engine.restore_key_store(prior_key_store);
                            protocol_engine.restore_auth_snapshot(prior_auth);
                            protocol_engine.restore_crypto_persistent_state(prior_crypto);
                            let _ = protocol_engine.take_firmware_action();
                            response = status_response(StatusCode::InternalError, &[]);
                        }
                    }
                }
                if response.code == StatusCode::Success.as_u8()
                    && let Some(action) = protocol_engine.take_firmware_action()
                {
                    match action {
                        FirmwareAction::DeveloperStoreFault(action) => {
                            if persistence::FlashStateStore::inject_fault(action).is_err() {
                                response = status_response(StatusCode::InternalError, &[]);
                            }
                        }
                        FirmwareAction::DeveloperReboot => {
                            reboot_requested = true;
                        }
                    }
                }
                if let Some(encoded) = protocol::protocol::encode_frame(&response) {
                    let _ = serial.write(&encoded);
                }
                clear_transient_buffer(&mut frame_buf[..frame_len]);
                frame_len = 0;
                if reboot_requested && response.code == StatusCode::Success.as_u8() {
                    hal::reboot::reboot(
                        hal::reboot::RebootKind::Normal,
                        hal::reboot::RebootArch::Riscv,
                    );
                }
            }
        }

        #[cfg(feature = "developer-mode")]
        if host_connected {
            logging::flush(&mut serial);
        }

        #[cfg(not(feature = "developer-mode"))]
        logging::flush();

        let now = timer.get_counter().ticks();
        if now >= next_toggle_at {
            led_is_on = !led_is_on;

            if led_is_on {
                led.set_high().ok();
                next_toggle_at = now + LED_ON_TICKS;
            } else {
                led.set_low().ok();
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
