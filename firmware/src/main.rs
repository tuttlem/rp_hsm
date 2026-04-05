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
const LED_PULSE_ON_TICKS: u64 = 60_000;
#[cfg(all(target_os = "none", any(target_arch = "riscv32", target_arch = "arm")))]
const LED_PULSE_GAP_TICKS: u64 = 120_000;

#[cfg(all(target_os = "none", any(target_arch = "riscv32", target_arch = "arm")))]
const LED_SUCCESS_PULSES: u8 = 1;
#[cfg(all(target_os = "none", any(target_arch = "riscv32", target_arch = "arm")))]
const LED_ERROR_PULSES: u8 = 2;
#[cfg(all(target_os = "none", any(target_arch = "riscv32", target_arch = "arm")))]
const LED_MAX_PENDING_PULSES: u8 = 4;

#[cfg(all(target_os = "none", any(target_arch = "riscv32", target_arch = "arm")))]
struct LedUi {
    is_on: bool,
    phase_deadline: u64,
    pending_pulses: u8,
}

#[cfg(all(target_os = "none", any(target_arch = "riscv32", target_arch = "arm")))]
impl LedUi {
    const fn new(now: u64) -> Self {
        Self {
            is_on: false,
            phase_deadline: now,
            pending_pulses: 0,
        }
    }

    fn trigger_success(&mut self, now: u64) {
        self.enqueue(now, LED_SUCCESS_PULSES);
    }

    fn trigger_error(&mut self, now: u64) {
        self.enqueue(now, LED_ERROR_PULSES);
    }

    fn enqueue(&mut self, now: u64, count: u8) {
        self.pending_pulses = self.pending_pulses.saturating_add(count).min(LED_MAX_PENDING_PULSES);
        if !self.is_on {
            self.phase_deadline = now;
        }
    }

    fn tick(&mut self, now: u64, led: &mut impl OutputPin) {
        if self.pending_pulses == 0 {
            if self.is_on {
                led.set_low().ok();
                self.is_on = false;
            }
            return;
        }

        if now < self.phase_deadline {
            return;
        }

        if self.is_on {
            led.set_low().ok();
            self.is_on = false;
            self.pending_pulses = self.pending_pulses.saturating_sub(1);
            self.phase_deadline = now + LED_PULSE_GAP_TICKS;
        } else {
            led.set_high().ok();
            self.is_on = true;
            self.phase_deadline = now + LED_PULSE_ON_TICKS;
        }
    }
}

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
            protocol_engine.restore_audit_snapshot(state.audit);
            protocol_engine.restore_auth_snapshot(state.auth);
            protocol_engine.restore_crypto_persistent_state(state.crypto);
            protocol_engine.restore_firmware_update_state(
                state.accepted_firmware,
                state.boot_slots,
                state.update_transfer,
                state.recovery,
            );
            protocol_engine.restore_policy_profile(state.policy);
            protocol_engine.restore_approval_tickets(
                state.approval_tickets,
                state.next_approval_ticket_id,
            );
        }
        Ok(persistence::LoadOutcome::Corrupted) => {
            let fallback = persistence::corrupted_recovery_state();
            protocol_engine.restore_provisioning_snapshot(fallback.provisioning);
            protocol_engine.restore_key_store(fallback.key_store);
            protocol_engine.restore_audit_snapshot(fallback.audit);
            protocol_engine.restore_auth_snapshot(fallback.auth);
            protocol_engine.restore_crypto_persistent_state(fallback.crypto);
            protocol_engine.restore_firmware_update_state(
                fallback.accepted_firmware,
                fallback.boot_slots,
                fallback.update_transfer,
                fallback.recovery,
            );
            protocol_engine.restore_policy_profile(fallback.policy);
            protocol_engine.restore_approval_tickets(
                fallback.approval_tickets,
                fallback.next_approval_ticket_id,
            );
        }
        Ok(persistence::LoadOutcome::Empty) | Err(_) => {}
    }
    #[cfg(feature = "developer-mode")]
    protocol_engine.reconcile_boot();
    #[cfg(feature = "developer-mode")]
    let _ = persistence::FlashStateStore::save(&persistence::PersistedState {
        provisioning: protocol_engine.provisioning_snapshot(),
        key_store: protocol_engine.key_store().snapshot(),
        audit: protocol_engine.audit_snapshot(),
        auth: protocol_engine.auth_snapshot().clone(),
        crypto: protocol_engine.crypto_persistent_state(),
        accepted_firmware: protocol_engine.accepted_firmware_state(),
        boot_slots: *protocol_engine.boot_slots(),
        update_transfer: protocol_engine.update_transfer_state().clone(),
        recovery: protocol_engine.recovery_state(),
        policy: protocol_engine.policy_profile(),
        approval_tickets: protocol_engine.approval_tickets().clone(),
        next_approval_ticket_id: protocol_engine.next_approval_ticket_id(),
    });
    let mut led_ui = LedUi::new(timer.get_counter().ticks());
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
                let prior_audit = protocol_engine.audit_snapshot();
                let prior_auth = protocol_engine.auth_snapshot().clone();
                let prior_crypto = protocol_engine.crypto_persistent_state();
                let prior_accepted_firmware = protocol_engine.accepted_firmware_state();
                let prior_boot_slots = *protocol_engine.boot_slots();
                let prior_update_transfer = protocol_engine.update_transfer_state().clone();
                let prior_recovery = protocol_engine.recovery_state();
                let prior_policy = protocol_engine.policy_profile();
                let prior_approval_tickets = protocol_engine.approval_tickets().clone();
                let prior_next_approval_ticket_id = protocol_engine.next_approval_ticket_id();
                let mut response = protocol_engine.handle_bytes(&frame_buf[..expected_len]);
                let mut reboot_requested = false;
                if response.code == StatusCode::Success.as_u8() {
                    let current_provisioning = protocol_engine.provisioning_snapshot();
                    let current_key_store = protocol_engine.key_store().snapshot();
                    let current_audit = protocol_engine.audit_snapshot();
                    let current_auth = protocol_engine.auth_snapshot().clone();
                    let current_crypto = protocol_engine.crypto_persistent_state();
                    let current_accepted_firmware = protocol_engine.accepted_firmware_state();
                    let current_boot_slots = *protocol_engine.boot_slots();
                    let current_update_transfer = protocol_engine.update_transfer_state().clone();
                    let current_recovery = protocol_engine.recovery_state();
                    let current_policy = protocol_engine.policy_profile();
                    let current_approval_tickets = protocol_engine.approval_tickets().clone();
                    let current_next_approval_ticket_id = protocol_engine.next_approval_ticket_id();
                    if current_provisioning != prior_provisioning
                        || current_key_store != prior_key_store
                        || current_audit != prior_audit
                        || current_auth != prior_auth
                        || current_crypto != prior_crypto
                        || current_accepted_firmware != prior_accepted_firmware
                        || current_boot_slots != prior_boot_slots
                        || current_update_transfer != prior_update_transfer
                        || current_recovery != prior_recovery
                        || current_policy != prior_policy
                        || current_approval_tickets != prior_approval_tickets
                        || current_next_approval_ticket_id != prior_next_approval_ticket_id
                    {
                        let persist_result = persistence::FlashStateStore::save(&persistence::PersistedState {
                            provisioning: current_provisioning.clone(),
                            key_store: current_key_store.clone(),
                            audit: current_audit.clone(),
                            auth: current_auth.clone(),
                            crypto: current_crypto,
                            accepted_firmware: current_accepted_firmware,
                            boot_slots: current_boot_slots,
                            update_transfer: current_update_transfer.clone(),
                            recovery: current_recovery,
                            policy: current_policy,
                            approval_tickets: current_approval_tickets.clone(),
                            next_approval_ticket_id: current_next_approval_ticket_id,
                        });
                        if persist_result.is_err() {
                            protocol_engine.restore_provisioning_snapshot(prior_provisioning);
                            protocol_engine.restore_key_store(prior_key_store);
                            protocol_engine.restore_audit_snapshot(prior_audit);
                            protocol_engine.restore_auth_snapshot(prior_auth);
                            protocol_engine.restore_crypto_persistent_state(prior_crypto);
                            protocol_engine.restore_firmware_update_state(
                                prior_accepted_firmware,
                                prior_boot_slots,
                                prior_update_transfer,
                                prior_recovery,
                            );
                            protocol_engine.restore_policy_profile(prior_policy);
                            protocol_engine.restore_approval_tickets(
                                prior_approval_tickets,
                                prior_next_approval_ticket_id,
                            );
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
                let now = timer.get_counter().ticks();
                if response.code == StatusCode::Success.as_u8() {
                    led_ui.trigger_success(now);
                } else {
                    led_ui.trigger_error(now);
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
        led_ui.tick(now, &mut led);
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
