# Data Model: Host Tooling Consolidation and Integration

## Entity: Tooling Surface

Represents a supported host-side entry point and its intended audience.

### Fields

- `name`: stable tool or surface identifier
- `audience`: operator, integration, engineering, or factory
- `mode`: production-supported, development-only, engineering-only, or factory-only
- `entrypoint`: binary name, library path, or documented invocation
- `supported_workflows`: list of workflows this surface is allowed to perform
- `unsupported_workflows`: list of workflows intentionally excluded
- `machine_consumable`: whether the surface is intended for automation

### Validation Rules

- Every supported host entry point must belong to exactly one primary audience.
- A production-supported operator surface must not depend on engineering-only
  commands for its nominal workflow.
- Engineering-only surfaces must be labeled clearly and not presented as the
  canonical operator path.

## Entity: Operator Workflow

Represents a documented end-to-end task supported through the canonical host
tooling.

### Fields

- `workflow_id`: stable identifier
- `name`: human-readable task name
- `prerequisites`: required device state, proofs, files, and host permissions
- `commands`: ordered host-tooling steps
- `expected_outcomes`: bounded success and denial outcomes
- `engineering_fallback`: whether an engineering-only tool is permitted, and if
  so why

### Validation Rules

- Supported workflows must be completable without raw protocol framing.
- Prerequisites must declare host-side assumptions such as serial permissions or
  port ownership.
- If a workflow is not fully supported through the canonical operator tool, it
  must be documented as engineering-only or incomplete.

## Entity: Host Integration Surface

Represents the machine-consumable host-side interface intended for other
software.

### Fields

- `surface_id`: stable identifier
- `boundary_type`: reusable client API, structured CLI output mode, or both
- `stability_expectation`: internal, supported, or compatibility-bound
- `result_shapes`: documented result payload categories
- `error_classes`: bounded host-side and device-side error categories
- `protocol_dependency`: supported protocol-version assumptions

### Validation Rules

- Integrations must not require parsing freeform diagnostics.
- Device-side denials must remain distinguishable from host-side transport or
  usage failures.
- Unsupported protocol or firmware mismatches must fail clearly.

## Entity: Host Transport Condition

Represents a host-side device access condition affecting workflow reliability.

### Fields

- `condition_id`: stable identifier
- `kind`: busy, missing permission, missing device, incompatible firmware, or
  competing service
- `detection_signal`: observable host-side symptom
- `user_guidance`: bounded recovery action
- `retry_policy`: whether and how tooling should retry automatically

### Validation Rules

- Conditions must not be misreported as device policy failures.
- Recovery guidance must avoid destructive host actions by default.
- Common Linux USB-serial conflicts must have explicit operator guidance.

## Entity: Capability Exposure Decision

Represents the host-tooling disposition of a firmware capability.

### Fields

- `capability_name`: firmware/user-facing capability identifier
- `device_support_state`: implemented, planned, or unavailable
- `tooling_exposure_state`: operator-exposed, integration-only,
  engineering-only, or intentionally unavailable
- `justification`: rationale for the exposure state
- `documentation_location`: where the decision is recorded

### Validation Rules

- Every implemented user-relevant firmware capability must have an exposure
  decision.
- Capabilities intentionally kept out of the canonical operator surface must be
  documented explicitly.
