# Mini SOC Lab

A hands-on security operations lab for collecting Windows authentication events, validating custom detections in Wazuh, and documenting investigations.

**Validated detection.** A controlled failed logon on a Windows endpoint generated Security Event ID `4625`. Wazuh decoded the event through `windows_eventchannel` and triggered custom rule `100002` at level 7. The alert evidence and investigation are documented in IR-001.

## Lab phases

| Phase | What it covers |
|---|---|
| [Phase 1](./phase1) | Initial lab documentation and screenshots. |
| [Phase 2 — Authentication detection](./phase2) | Windows EventChannel telemetry, custom Wazuh rule configuration, validation with a live lab event, and investigation reporting. |
| Phase 3 — Authentication correlation | Planned exercise to correlate repeated `4625` failures followed by a `4624` successful logon. |

## Detection validation

1. Generated a controlled failed logon and confirmed that Wazuh received the Windows Security event.
2. Reviewed Wazuh’s built-in authentication rules `60104`, `60105`, and `60122` before adding custom rule `100002`.
3. Validated the rule configuration with `wazuh-analysisd -t`, then generated another failed logon and verified the level 7 alert.
4. Captured the supporting evidence and documented the investigation in IR-001.

The synthetic JSON sample decoded successfully in `wazuh-logtest` without matching the custom rule. The live Windows EventChannel test confirmed the match.

## Evidence

- [Authentication detection files](./phase2/detections/authentication)
- [Investigation reports](./phase2/investigation-reports)
- [Evidence screenshots](./phase2/screenshots)
- [Phase 2 evidence checklist](./phase2/PHASE-2-EVIDENCE-CHECKLIST.md)
