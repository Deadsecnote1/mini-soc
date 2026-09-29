# Phase 2 — Completion Record

## Phase

Authentication Detection

## Completion Date

`2026-09-29`

## Status

`Complete`

## Technical Results

- Event 4625 observed: `Yes`
- Actual fields recorded: `Yes`
- Existing Wazuh authentication chain inspected: `Yes`
- Custom authentication rule created: `Yes`
- Custom rule ID: `100002`
- Custom rule level: `7`
- Rule configuration validated with `wazuh-analysisd -t`: `Yes`
- Rule tested with `wazuh-logtest`: `Partial`
- `wazuh-logtest` result: synthetic JSON decoded as `json`; no Phase 3 rule match was observed
- Controlled event generated after deployment: `Yes`
- Custom alert observed: `Yes`

## Evidence

- 4625 event: `screenshots/phase2-4625-event.png`
- Logtest evidence: `screenshots/phase2-logtest.png`
- Custom alert: `screenshots/phase2-custom-alert.png`
- Investigation report: `investigation-reports/IR-001-authentication.md`

## Custom Detection

```text
Rule ID: 100002
Level: 7
Description: MINI-SOC: Failed authentication for monitored account soc-test
Parent rule: 60122
Field condition: win.eventdata.targetUserName = soc-test
```

## Observed Real Event

- Windows Event ID: `4625`
- Decoder: `windows_eventchannel`
- Location: `EventChannel`
- Target username: `soc-test`
- Logon type: `2`
- Status: `0xc000006d`
- Sub-status: `0xc000006a`
- Source address: `::1`
- Workstation: `SOC-WIN01`
- Process: `C:\Windows\System32\svchost.exe`
- Authentication package: `Negotiate`
- Logon process: `seclogo`
- Agent: `SOC-WIN01` (`001`)
- Agent IP: `192.168.56.10`

## False-Positive / Scope Notes

The custom rule is intentionally scoped to the lab account `soc-test`. It demonstrates project-specific detection engineering and is not a general brute-force detector.

The observed `::1` address is IPv6 loopback. This test was generated in the Windows/local authentication context through the lab's SSH workflow, so the event should not be documented as a remote login originating from the Parrot host's `192.168.56.x` address.

`svchost.exe` was observed in the event and is recorded as telemetry. Its presence alone is not treated as evidence of malicious activity.

## Lessons Learned

- The real Windows EventChannel event and the synthetic JSON `wazuh-logtest` input do not follow the same decoder path.
- The synthetic JSON test was useful for confirming field extraction, but it did not prove that the custom rule matched.
- Inspecting the existing Wazuh rule chain allowed the custom rule to reuse rule `60122` instead of duplicating the built-in Windows authentication logic.
- The first chosen custom ID, `100001`, conflicted with an existing local rule, so the project rule was changed to `100002`.
- The deployed rule was validated against the real Windows event and successfully generated the expected custom alert.

## Phase 2 Conclusion

Phase 2 is complete. The Mini-SOC successfully collected a real Windows Security Event `4625`, decoded it through `windows_eventchannel`, and generated custom Wazuh rule `100002` for the controlled `soc-test` authentication failure.

## Next Phase

**Phase 3 — Authentication Correlation**

Planned sequence:

```text
4625 failure
      ↓
4625 failure
      ↓
4625 failure
      ↓
4624 success
```
