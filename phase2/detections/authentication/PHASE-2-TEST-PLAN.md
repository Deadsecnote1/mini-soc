# Phase 2 — Authentication Detection Test Plan

## Test Objective

Verify that a controlled Windows failed-logon event can be collected by Wazuh and trigger a project-specific authentication detection.

## Preconditions

- [x] Wazuh Manager is running.
- [x] Wazuh Dashboard is accessible.
- [x] Windows agent is active.
- [x] Test account `SOC-WIN01\\soc-test` exists.
- [x] Windows Security auditing is working.
- [x] Event 4625 has been observed.
- [x] Account lockout settings have been checked.

Observed account policy during the test:

- Lockout threshold: `10`
- Lockout duration: `10` minutes
- Observation window: `10` minutes

## Test 1 — Raw Event Validation

### Action

Generate one controlled failed authentication attempt against `soc-test`.

### Expected

Windows generates Event ID `4625` and Wazuh receives it.

### Result

`PASS`

### Evidence

`screenshots/phase2-4625-event.png`

## Test 2 — Field Validation with `wazuh-logtest`

### Action

Submit a synthetic JSON representation containing the observed fields to:

```text
/var/ossec/bin/wazuh-logtest
```

### Result

`PARTIAL — field decoding confirmed; no Phase 3 rule match`

The input decoded as the generic `json` decoder. It exposed the expected fields, but it did not reproduce the real Windows EventChannel decoder/rule path and did not produce a Phase 3 rule match.

### Evidence

`screenshots/phase2-logtest.png`

## Test 3 — Custom Rule Configuration Validation

### Action

Validate the deployed Wazuh rule configuration with:

```bash
sudo /var/ossec/bin/wazuh-analysisd -t
```

### Result

`PASS`

No configuration/rule error was reported after changing the conflicting project ID from `100001` to `100002`.

## Test 4 — Real Deployed Detection

### Action

Deploy the custom rule under:

```text
/var/ossec/etc/rules/auth-rules.xml
```

Restart the Wazuh Manager and generate another controlled failed authentication.

### Expected

The real Windows EventChannel event triggers custom rule `100002`.

### Result

`PASS`

Observed:

```text
Rule ID: 100002
Level: 7
Description: MINI-SOC: Failed authentication for monitored account soc-test
Decoder: windows_eventchannel
```

### Evidence

`screenshots/phase2-custom-alert.png`

## Test 5 — False-Positive Review

### Findings

- The event is a controlled failed authentication against `soc-test`.
- The source address is `::1`, so this test should not be represented as a remote authentication from the Parrot host IP.
- `svchost.exe` is recorded as observed telemetry, not independently classified as malicious.
- The rule is scoped to `soc-test` and therefore is not a general brute-force detector.

### Result

`PASS — limitations documented`

## Test Completion

- [x] Raw event validated
- [x] Actual fields recorded
- [x] Existing Wazuh authentication chain inspected
- [x] Rule configuration validated
- [x] Controlled event generated after deployment
- [x] Custom alert observed
- [x] Evidence captured
- [x] Documentation updated
