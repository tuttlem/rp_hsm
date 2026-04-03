# Feature Specification: Host Tooling Consolidation and Integration

**Feature Branch**: `009-host-tooling`  
**Created**: 2026-04-01  
**Status**: Draft  
**Input**: User description: "Consolidate the existing host CLI and integration tooling into a complete supported operator and integration surface, including workflow polish, robust transport handling, reusable client boundaries, conformance support, and operator guidance"

## Scope Adjustment

This feature does **not** start from zero. The repository already includes a
real host tooling surface:

- the `rphsmtool` operator CLI
- the shared host-side client in `host_tools`
- discovery, provisioning, diagnostics, lifecycle, audit, crypto, and firmware
  update commands
- a protocol probe used for engineering validation

`009-host-tooling` therefore covers the remaining productization and integration
work needed to make that surface coherent, dependable, and supportable. It is
about consolidation, polish, workflow completion, and packaging boundaries, not
about merely creating the first CLI.

## User Scenarios & Testing *(mandatory)*

### User Story 1 - Operate the Device Reliably (Priority: P1)

As an operator, I need a supported command-line workflow for provisioning,
administration, diagnostics, and recovery so that I can manage the device
without raw protocol manipulation, hidden preconditions, or undocumented host
workarounds.

**Why this priority**: A product is not operable if users must handcraft device
messages or infer lifecycle steps from firmware internals.

**Independent Test**: Use the supported tooling to perform provisioning,
administrative review, audit access, firmware update, and recovery, confirming
that routine workflows can be completed end to end without ad hoc manual steps,
probe-only commands, or hidden transport assumptions.

**Acceptance Scenarios**:

1. **Given** an operator needs to perform a supported administrative workflow,
   **When** they use the approved tooling, **Then** the workflow can be
   completed using documented commands, outputs, and prerequisites alone.
2. **Given** an operator attempts an action without sufficient authority,
   **When** the tooling relays the request, **Then** the tooling presents the
   device denial clearly without inventing alternate behavior.
3. **Given** a device is present but temporarily unavailable because of host
   transport contention, **When** the operator uses the supported tooling,
   **Then** the tool reports the likely host-side cause and recovery guidance
   clearly rather than failing with an opaque error alone.

---

### User Story 2 - Integrate with a Stable Client Surface (Priority: P2)

As an integration team, I need a supported client surface and protocol
conformance guidance so that applications can interact with the device reliably
without reverse-engineering firmware behavior or scraping CLI text output.

**Why this priority**: Clear integration boundaries reduce misuse and support a
stable product interface.

**Independent Test**: Build a client workflow using the supported host-side
surface and confirm that the resulting interaction matches the documented device
contract without depending on undocumented framing, counters, or CLI internals.

**Acceptance Scenarios**:

1. **Given** an integration team follows the supported guidance, **When** they
   implement a standard workflow, **Then** the workflow succeeds without relying
   on undocumented protocol details.
2. **Given** a client deviates from the documented command contract, **When** it
   is tested for conformance, **Then** the deviation is identified clearly.
3. **Given** an integration team needs machine-consumable results, **When**
   they use the supported host-side surface, **Then** they can do so through a
   stable interface rather than parsing human-oriented diagnostics.

---

### User Story 3 - Separate Product Surface from Engineering Surface (Priority: P3)

As a product owner, I need host tooling to distinguish development-only behavior
from production operations so that convenience utilities do not become
accidental production control paths.

**Why this priority**: Tooling can easily widen attack surface if development
and operational workflows are not separated deliberately.

**Independent Test**: Review the supported tooling catalog and packaging
boundaries and confirm that production-safe operations are distinct from
development-only utilities, engineering probes, and factory-only capabilities.

**Acceptance Scenarios**:

1. **Given** a tool is intended only for development or lab use, **When** an
   operator reviews supported tooling, **Then** that tool is clearly marked as
   not part of production operations.
2. **Given** a production workflow is documented, **When** an operator follows
   it, **Then** the workflow does not rely on development-only interfaces.
3. **Given** multiple host-side entry points exist, **When** a user inspects
   the product surface, **Then** the canonical operator tool, engineering probe,
   and reusable integration surface are each clearly identified.

### Edge Cases

- An operator loses connectivity while using the CLI during a multi-step
  administrative workflow.
- A host process such as modem-management software or another serial consumer
  temporarily holds the device node open.
- A diagnostic request is attempted while the device is in a restricted state.
- A client library version lags behind the currently supported protocol version.
- Conformance testing finds a client behavior that is ambiguous under the
  documentation.
- Provisioning guidance is followed on a device that has already been claimed.
- A workflow is technically implemented in firmware but only partially exposed
  in the CLI, leaving operators stranded between product and engineering tools.
- A command returns machine-relevant data but only in a human-oriented freeform
  layout that is hard to integrate safely.

### Security Misuse Cases *(mandatory)*

- An attacker attempts to use host tooling outputs to discover hidden commands,
  secrets, or privileged states.
- An attacker attempts to treat a development convenience tool as a production
  control path.
- An integrator assumes host-side validation is a substitute for device-side
  authorization and policy enforcement.
- An operator or integrator treats verbose diagnostics, probe output, or debug
  transport state as a supported stable API.

## Requirements *(mandatory)*

### Functional Requirements

- **FR-001**: The system MUST provide a supported host tooling surface for
  provisioning, administration, diagnostics, recovery, audit access, and
  firmware update workflows.
- **FR-002**: The system MUST define the supported operator workflows that can
  be completed through the host tooling surface and identify any workflows that
  remain intentionally engineering-only.
- **FR-003**: The system MUST provide integration guidance sufficient for a
  client to use the device without undocumented behavior and without scraping
  human-oriented CLI output.
- **FR-004**: The system MUST provide protocol conformance support so that
  client implementations can be checked against the documented contract.
- **FR-005**: The system MUST distinguish production-supported tooling from
  development-only, engineering-only, or factory-only tooling.
- **FR-006**: The system MUST define fail-safe behavior for interrupted host
  workflows, partial command completion, diagnostics failures, transport
  contention, and client conformance mismatches.
- **FR-007**: The system MUST define how host-side transient secrets,
  credentials, and diagnostic artifacts are bounded, protected, and destroyed
  when no longer needed.
- **FR-008**: The system MUST present device denials, authorization failures,
  and state restrictions accurately rather than masking them with host-side
  shortcuts.
- **FR-009**: The system MUST define operator-facing documentation for supported
  workflows, failure handling, and security boundaries.
- **FR-010**: The system MUST define the canonical operator-facing entry point
  and the engineering validation entry point, including when each is intended to
  be used.
- **FR-011**: The system MUST define a stable machine-consumable host-side
  surface for integrations, whether through a reusable client library,
  structured output mode, or another documented interface.
- **FR-012**: The system MUST define how host tooling detects and reports
  host-side device access conflicts such as busy serial ports, missing
  permissions, or competing system services.
- **FR-013**: The system MUST define packaging or installation expectations for
  host tooling so operators know how the supported tools are obtained and run.
- **FR-014**: The system MUST define the completion standard for exposing newly
  implemented firmware capabilities through the supported host tooling surface.

### Security Requirements *(mandatory)*

- **SR-001**: The feature MUST preserve the device's security boundaries rather
  than re-implementing privileged behavior in host tooling.
- **SR-002**: The feature MUST ensure that development-only tools and production
  tooling are clearly separated in purpose and expected use.
- **SR-003**: The feature MUST prevent tooling output, diagnostics, and guidance
  from disclosing secrets, hidden commands, or privileged internal state beyond
  approved operational needs.
- **SR-004**: The feature MUST prevent engineering validation output from being
  misrepresented as a stable supported integration API.

### Key Entities *(include if feature involves data)*

- **Operator Workflow**: A documented end-to-end task performed through the
  supported tooling, such as provisioning, audit review, firmware update, or
  recovery.
- **Client Conformance Check**: The validation outcome showing whether a client
  behaves according to the documented protocol contract.
- **Tooling Mode**: The declared operational category of a tool, such as
  production, development, engineering validation, or factory use.
- **Integration Guide**: The supported documentation describing how external
  software should interact with the device safely.
- **Canonical Operator Tool**: The supported user-facing tool intended for
  normal human operation.
- **Engineering Probe**: A deliberately broader validation tool intended for lab
  regression and contract checks rather than everyday operation.
- **Host Integration Surface**: The supported machine-consumable interface used
  by other software to drive the device safely.

## Success Criteria *(mandatory)*

### Measurable Outcomes

- **SC-001**: Operators can complete all supported provisioning and routine
  administrative workflows using documented tooling without crafting raw device
  messages or dropping into engineering-only utilities.
- **SC-002**: Integration teams can implement a conformant client workflow using
  the documented host integration surface and guidance alone.
- **SC-003**: 100% of tooling-mediated privileged actions remain subject to the
  same device-side authorization and policy denials as direct protocol use.
- **SC-004**: Reviewers can distinguish production-supported tooling from
  development-only tooling from the documentation alone.
- **SC-005**: Newly implemented firmware capabilities are either exposed through
  the supported host tooling surface or explicitly documented as intentionally
  unavailable there.
- **SC-006**: Operators encountering host-side transport contention receive a
  bounded, actionable explanation rather than only a raw OS error string.

## Assumptions

- Host tooling exists to improve operator safety and usability, not to move
  trust away from the device.
- A CLI already exists as the primary operator surface.
- A reusable host-side client surface already exists in some form and should be
  treated as the likely basis for supported integrations rather than starting
  over.
- Manufacturing utilities may exist but are not automatically part of the
  production operator toolkit.
- Tooling documentation is part of the product surface and must be treated as a
  security-relevant artifact.
- `probe_protocol` already exists and should be treated as an engineering
  validation tool, not as the canonical operator interface.

## Security Acceptance Notes

- Acceptance coverage must prove that tooling respects device denials instead of
  working around them.
- Any host-side credential handling claim must identify which data is transient
  and how it is protected and cleared.
- The specification must not imply that a conformant client is trusted more than
  an untrusted client once requests reach the device boundary.
- The specification must not imply that merely having a CLI completes the host
  tooling story if the remaining gaps are around reliability, packaging,
  integration boundaries, or workflow completeness.
