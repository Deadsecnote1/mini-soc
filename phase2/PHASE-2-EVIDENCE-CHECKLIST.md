# Phase 2 — Evidence Checklist

## Required evidence

- [x] `phase2-4625-event.png`
  - Real Wazuh Windows Security Event `4625` evidence.

- [x] `phase2-logtest.png`
  - Synthetic JSON `wazuh-logtest` evidence showing successful field decoding as `json`.
  - Important: this screenshot does **not** prove a Phase 3 rule match.

- [x] `phase2-custom-alert.png`
  - Real Windows EventChannel event triggering custom rule `100002`.

## Supporting evidence captured in the project

- [x] Windows test-account context
- [x] Account-lockout policy/configuration
- [x] Wazuh agent/service status
- [x] Custom rule validation
- [x] Investigation report

## Screenshot quality rules

Each screenshot should:

- Show enough context to prove what is being demonstrated.
- Avoid exposing unrelated personal information.
- Include the relevant event ID/rule ID where possible.
- Use consistent naming.
- Be referenced from the relevant documentation.

## Repository location

`screenshots/`
