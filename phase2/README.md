# Mini SOC — Phase 2 Documentation

## Phase 2 — Authentication Detection

This phase implements and validates a custom Wazuh detection for a controlled Windows failed-authentication event.

### Lab context

- Wazuh version: `4.14.7`
- Wazuh manager: `soc-wazuh` / `192.168.56.20`
- Windows endpoint: `SOC-WIN01` / `192.168.56.10`
- Wazuh agent ID: `001`
- Test account: `soc-test`
- Windows Security telemetry: EventChannel

### What was actually demonstrated

1. Windows Security Event ID `4625` was generated and received by Wazuh.
2. The real event was decoded by `windows_eventchannel`.
3. The built-in Wazuh authentication chain was inspected:
   - `60104` — Windows audit failure
   - `60105` — Windows Logon Failure
   - `60122` — Logon Failure - Unknown user or bad password
4. A project-specific rule `100002` was created under `/var/ossec/etc/rules/auth-rules.xml`.
5. The rule configuration passed `wazuh-analysisd -t`.
6. A real Windows `4625` event triggered custom rule `100002` at level `7`.
7. Evidence was captured and IR-001 was documented.

### Important logtest limitation

A synthetic JSON event was tested with `wazuh-logtest`. It decoded successfully as the generic `json` decoder and exposed the expected fields, but it did **not** produce a Phase 3 rule match. This was not recorded as a successful custom-rule match.

The later validation used the real Windows EventChannel event, which decoded as `windows_eventchannel` and successfully triggered rule `100002`.

### Phase 2 status

- [x] Controlled failed-logon test completed
- [x] Event 4625 verified in Wazuh
- [x] Actual event fields recorded
- [x] Existing Wazuh authentication chain inspected
- [x] Custom authentication rule created
- [x] Rule configuration validated with `wazuh-analysisd -t`
- [x] Real controlled event generated after deployment
- [x] Custom Wazuh alert verified
- [x] Evidence screenshots captured
- [x] IR-001 investigation report completed

### Next phase

**Phase 3 — Authentication Correlation**

The next stage will examine a sequence of authentication events, including multiple `4625` failures followed by a `4624` successful authentication, and will use the actual Wazuh event fields observed in this lab.
