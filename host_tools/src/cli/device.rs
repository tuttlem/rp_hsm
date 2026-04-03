use crate::client::{ClientConfig, SerialBackend};
use crate::cli::output::CliError;
use std::thread;
use std::time::Duration;

const DISCOVERY_ATTEMPTS: usize = 10;
const DISCOVERY_RETRY_DELAY_MS: u64 = 200;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DiscoveredDevice {
    pub device_path: String,
    pub protocol_version: u8,
    pub device_state: u8,
    pub session_state: u8,
    pub developer_mode_present: bool,
}

/// # Errors
///
/// Returns `CliError` when host serial enumeration fails.
pub fn discover_devices(baud: u32) -> Result<Vec<DiscoveredDevice>, CliError> {
    for attempt in 0..DISCOVERY_ATTEMPTS {
        let ports = serialport::available_ports().map_err(|err| {
            CliError::transport(format!("failed to enumerate serial ports: {err}"))
        })?;
        let mut devices = Vec::new();
        for port in ports {
            if !looks_like_candidate(&port.port_name) {
                continue;
            }
            let backend = SerialBackend::new(ClientConfig::new(port.port_name.clone(), baud));
            if let Ok(info) = backend.probe() {
                devices.push(DiscoveredDevice {
                    device_path: port.port_name,
                    protocol_version: info.protocol_version,
                    device_state: info.device_state,
                    session_state: info.session_state,
                    developer_mode_present: info.session_state == 0x05,
                });
            }
        }
        if !devices.is_empty() || attempt + 1 == DISCOVERY_ATTEMPTS {
            devices.sort_by(|a, b| a.device_path.cmp(&b.device_path));
            return Ok(devices);
        }
        thread::sleep(Duration::from_millis(DISCOVERY_RETRY_DELAY_MS));
    }
    Ok(Vec::new())
}

/// # Errors
///
/// Returns `CliError` when no compatible device exists, more than one
/// compatible device exists without explicit selection, or the explicit device
/// does not match a compatible target.
pub fn resolve_device_selector(
    explicit: Option<&str>,
    discovered: &[DiscoveredDevice],
) -> Result<String, CliError> {
    match explicit {
        Some(path) => {
            if discovered.iter().any(|device| device.device_path == path) {
                Ok(path.to_string())
            } else {
                Err(CliError::not_found(format!(
                    "device '{path}' was not found among compatible RP HSM targets"
                )))
            }
        }
        None => match discovered {
            [device] => Ok(device.device_path.clone()),
            [] => Err(CliError::not_found("no compatible RP HSM devices found")),
            _ => Err(CliError::failure(
                "multiple compatible RP HSM devices found; specify --device explicitly",
            )),
        },
    }
}

#[must_use]
pub fn looks_like_candidate(path: &str) -> bool {
    path.starts_with("/dev/ttyACM") || path.starts_with("/dev/ttyUSB")
}

#[cfg(test)]
mod tests {
    use super::{DiscoveredDevice, looks_like_candidate, resolve_device_selector};

    fn dev(path: &str) -> DiscoveredDevice {
        DiscoveredDevice {
            device_path: path.into(),
            protocol_version: 1,
            device_state: 1,
            session_state: 5,
            developer_mode_present: true,
        }
    }

    #[test]
    fn resolves_single_discovered_device() {
        let resolved = resolve_device_selector(None, &[dev("/dev/ttyACM0")]).expect("resolve");
        assert_eq!(resolved, "/dev/ttyACM0");
    }

    #[test]
    fn rejects_ambiguous_selection() {
        let err = resolve_device_selector(None, &[dev("/dev/ttyACM0"), dev("/dev/ttyACM1")])
            .expect_err("must fail");
        assert!(err.message.contains("multiple compatible"));
    }

    #[test]
    fn rejects_unknown_explicit_device() {
        let err = resolve_device_selector(Some("/dev/ttyACM9"), &[dev("/dev/ttyACM0")])
            .expect_err("must fail");
        assert!(err.message.contains("was not found"));
    }

    #[test]
    fn candidate_filter_accepts_usb_serial_names() {
        assert!(looks_like_candidate("/dev/ttyACM0"));
        assert!(looks_like_candidate("/dev/ttyUSB0"));
        assert!(!looks_like_candidate("/dev/ttyS0"));
    }
}
