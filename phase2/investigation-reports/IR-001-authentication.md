# IR-001 — Authentication Failure

## 1. Executive Summary

A controlled Windows authentication failure was generated against the lab account `soc-test` on `SOC-WIN01`.

Wazuh received Windows Security Event ID `4625`, decoded the event through `windows_eventchannel`, and generated the project-specific Wazuh rule `100002` at level `7`.

This was a controlled laboratory validation event. The evidence does not by itself indicate compromise.

## 2. Detection

- Wazuh Rule ID: `100002`
- Rule Level: `7`
- Description: `MINI-SOC: Failed authentication for monitored account soc-test`
- Parent rule: `60122`
- Windows Event ID: `4625`
- Decoder: `windows_eventchannel`
- Location: `EventChannel`

## 3. Affected Asset

- Endpoint: `SOC-WIN01`
- Endpoint IP: `192.168.56.10`
- Wazuh agent ID: `001`
- Wazuh manager: `soc-wazuh`
- Wazuh manager IP: `192.168.56.20`
- Target account: `soc-test`

## 4. Timeline

The observed real event had the following Windows event time:

`2026-09-29T06:03:27.4186214Z`

Wazuh indexed the alert at:

`2026-09-29T06:03:29.278+0000`

Windows Event Record ID:

`44210`

## 5. Evidence

Observed fields from the real Wazuh alert:

| Field | Value |
|---|---|
| `win.system.eventID` | `4625` |
| `win.eventdata.targetUserName` | `soc-test` |
| `win.eventdata.subjectUserName` | `soc-win` |
| `win.eventdata.targetDomainName` | `SOC-WIN01` |
| `win.eventdata.logonType` | `2` |
| `win.eventdata.status` | `0xc000006d` |
| `win.eventdata.subStatus` | `0xc000006a` |
| `win.eventdata.ipAddress` | `::1` |
| `win.eventdata.ipPort` | `0` |
| `win.eventdata.workstationName` | `SOC-WIN01` |
| `win.eventdata.processName` | `C:\Windows\System32\svchost.exe` |
| `win.eventdata.authenticationPackageName` | `Negotiate` |
| `win.eventdata.logonProcessName` | `seclogo` |

## 6. Investigation

The event represents a controlled failed authentication test using the `soc-test` account.

The event contains status `0xc000006d` and sub-status `0xc000006a`, consistent with the failed-logon event observed during the controlled incorrect-password test.

The source address is `::1`, which is IPv6 loopback. The test was performed in the Windows/local authentication context through the lab's SSH workflow. Therefore, the event should not be documented as a remote authentication originating from the Parrot host's `192.168.56.x` address.

The process `C:\Windows\System32\svchost.exe` is recorded because it appears in the Windows event. Its presence alone is not treated as evidence of malicious activity.

## 7. Detection Logic

The project rule is:

```xml
<rule id="100002" level="7">
  <if_sid>60122</if_sid>
  <field name="win.eventdata.targetUserName">^soc-test$</field>
  <description>MINI-SOC: Failed authentication for monitored account soc-test</description>
  <group>mini_soc_authentication,authentication_failed,</group>
</rule>
```

Wazuh's existing authentication chain already identifies the failed Windows logon. The custom rule adds project-specific context by matching the monitored account.

## 8. `wazuh-logtest` Finding

A synthetic JSON event containing the observed fields was submitted to `wazuh-logtest`.

It successfully decoded as:

```text
name: 'json'
```

and exposed fields including:

```text
win.eventdata.targetUserName: 'soc-test'
win.system.eventID: '4625'
```

No Phase 3 rule match was observed. This test is therefore documented as field-decoding validation only.

The actual Windows EventChannel event was subsequently used to validate the deployed custom rule, and rule `100002` fired successfully.

## 9. MITRE ATT&CK Mapping

No project-specific MITRE ATT&CK mapping was assigned in Phase 2. Mapping is planned for the later detection-engineering stage after the detection behavior and correlation scenarios are finalized.

## 10. False Positive Analysis

The custom rule is intentionally limited to `soc-test`. It can trigger on legitimate authentication mistakes against that lab account and should not be interpreted as a general brute-force detector.

A single failed authentication does not establish malicious activity.

## 11. Response

No containment or remediation was performed because this was a controlled laboratory test.

## 12. Lessons Learned

- Real Windows EventChannel telemetry should be distinguished from synthetic JSON supplied to `wazuh-logtest`.
- Existing Wazuh rules can be reused as parents for project-specific detections.
- Custom rule IDs must be checked for conflicts before deployment; `100001` was already present in `local_rules.xml`, so this project uses `100002`.
- Evidence should distinguish the observed source address from the network address of the test host.

## 13. Evidence Files

- `screenshots/phase2-4625-event.png`
- `screenshots/phase2-logtest.png`
- `screenshots/phase2-custom-alert.png`

## 14. Conclusion

Phase 2 successfully demonstrated collection and custom detection of a controlled Windows Security Event `4625`. The real EventChannel event triggered Wazuh rule `100002`, completing the authentication-detection objective.
