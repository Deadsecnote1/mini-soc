# Authentication Detection

## 1. Objective

Detect a controlled Windows failed authentication for the monitored lab account `soc-test` using Wazuh, while reusing Wazuh's existing Windows authentication rule chain.

## 2. Lab Context

- Endpoint: `SOC-WIN01`
- Endpoint IP: `192.168.56.10`
- Agent ID: `001`
- Wazuh manager: `soc-wazuh`
- Wazuh manager IP: `192.168.56.20`
- Wazuh version: `4.14.7`
- Test account: `soc-test`

The Windows agent is configured to collect Security EventChannel telemetry. The observed configuration contains a Security `<localfile>` with `<log_format>eventchannel</log_format>`. PowerShell and Sysmon EventChannel collection are also configured, but they are outside the scope of this Phase 2 authentication rule.

## 3. Observed Windows Event

The real event used for validation was Windows Security Event ID `4625`.

| Field | Observed value |
|---|---|
| `win.system.eventID` | `4625` |
| `win.eventdata.targetUserName` | `soc-test` |
| `win.eventdata.subjectUserName` | `soc-win` |
| `win.eventdata.targetDomainName` | `SOC-WIN01` |
| `win.eventdata.logonType` | `2` |
| `win.eventdata.status` | `0xc000006d` |
| `win.eventdata.subStatus` | `0xc000006a` |
| `win.eventdata.ipAddress` | `::1` |
| `win.eventdata.workstationName` | `SOC-WIN01` |
| `win.eventdata.processName` | `C:\Windows\System32\svchost.exe` |
| `win.eventdata.authenticationPackageName` | `Negotiate` |
| `win.eventdata.logonProcessName` | `seclogo` |
| Decoder | `windows_eventchannel` |
| Location | `EventChannel` |

The `::1` address is IPv6 loopback. This particular authentication test was generated in the Windows/local authentication context through the lab's SSH workflow; it is not evidence that the failed authentication originated from the Parrot host's network IP.

## 4. Existing Wazuh Rule Chain

The real event was already covered by Wazuh's built-in Windows authentication rules:

```text
60104 — Windows audit failure
        ↓
60105 — Windows Logon Failure
        ↓
60122 — Logon Failure - Unknown user or bad password
```

The built-in rule `60122` matches Windows Event ID `4625` through the normalized field `win.system.eventID`.

## 5. Custom Project Rule

The project rule is stored in:

`/var/ossec/etc/rules/auth-rules.xml`

The repository copy is `auth-rules.xml` in this directory.

Actual rule:

```xml
<group name="mini_soc_authentication,windows,">

  <rule id="100002" level="7">
    <if_sid>60122</if_sid>
    <field name="win.eventdata.targetUserName">^soc-test$</field>
    <description>MINI-SOC: Failed authentication for monitored account soc-test</description>
    <group>mini_soc_authentication,authentication_failed,</group>
  </rule>

</group>
```

The initial project ID `100001` conflicted with an existing rule in `local_rules.xml`. The project rule was therefore changed to `100002`.

## 6. Validation

The rule configuration was validated successfully with:

```bash
sudo /var/ossec/bin/wazuh-analysisd -t
```

No configuration/rule error was reported.

## 7. `wazuh-logtest` Observation

A synthetic JSON representation of the observed fields was supplied to `wazuh-logtest`:

```json
{"win":{"system":{"eventID":"4625"},"eventdata":{"targetUserName":"soc-test","logonType":"2","status":"0xc000006d","subStatus":"0xc000006a","ipAddress":"::1"}}}
```

The result showed:

```text
Phase 1: Completed pre-decoding
Phase 2: Completed decoding
name: 'json'
win.eventdata.targetUserName: 'soc-test'
win.system.eventID: '4625'
```

No Phase 3 rule match was observed. Therefore this test is documented as field-decoding validation only, not as proof that rule `100002` matched.

The real Windows EventChannel event was subsequently used for validation.

## 8. Real Detection Result

After deployment and Wazuh manager restart, a new controlled Windows `4625` event generated:

```text
Rule ID: 100002
Level: 7
Description: MINI-SOC: Failed authentication for monitored account soc-test
Decoder: windows_eventchannel
```

This is the successful custom-rule validation for Phase 2.

## 9. False-Positive Considerations

A single failed login does not by itself establish malicious activity. Legitimate causes include incorrect credentials, stale credentials, or administrative testing.

The custom rule is intentionally scoped to `soc-test` for this lab. It is therefore a project-specific detection and not a general brute-force detector.

`svchost.exe` was observed as the process associated with the event. Its presence alone is not treated as evidence of malicious activity.

## 10. Evidence

- `../../screenshots/phase2-4625-event.png`
- `../../screenshots/phase2-logtest.png`
- `../../screenshots/phase2-custom-alert.png`
- `../../investigation-reports/IR-001-authentication.md`

## 11. Next Phase

Phase 3 will correlate multiple authentication failures with a subsequent successful authentication (`4624`). The correlation should be built from the actual fields observed in this lab rather than assumed field names.
