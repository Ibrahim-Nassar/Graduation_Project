# Malformed logs

Records whose corpus intent is `Malformed`.

_size=16_

| # | Family | Subtype | Intent | Expected | Actual | Severity | Source | Failing | Triage |
|---:|---|---|---|---|---|---|---|---|---|
| 36 | Firewall | Fortinet KV | Malformed | — | — | info | none | — | — |
| 37 | Firewall | Fortinet KV | Malformed | — | — | info | none | — | — |
| 38 | Firewall | Fortinet KV | Malformed | — | — | info | none | — | — |
| 39 | Firewall | Fortinet KV | Malformed | — | — | info | none | — | — |
| 84 | IDS | Zeek JSON | Malformed | — | — | info | none | — | — |
| 85 | IDS | Zeek JSON | Malformed | — | — | info | none | — | — |
| 86 | IDS | Zeek JSON | Malformed | — | — | info | none | — | — |
| 87 | IDS | Zeek JSON | Malformed | — | — | info | none | — | — |
| 132 | Windows | Winlogbeat JSON | Malformed | — | — | info | none | — | — |
| 133 | Windows | Winlogbeat JSON | Malformed | — | — | info | none | — | — |
| 134 | Windows | Winlogbeat JSON | Malformed | — | — | info | none | — | — |
| 135 | Windows | Winlogbeat JSON | Malformed | — | — | info | none | — | — |
| 180 | Linux | Syslog | Malformed | — | — | info | none | `family_match`, `subtype_match` | `heuristic_limit` |
| 181 | Linux | Syslog | Malformed | — | — | info | none | — | — |
| 182 | Linux | Syslog | Malformed | — | — | info | none | — | — |
| 183 | Linux | Syslog | Malformed | — | — | info | none | — | — |

## Records

### Record 36

- Family / subtype: `Firewall` / `Fortinet KV`
- Intent: `Malformed`
- Expected technique: — — actual: —
- Severity: `info` — mapping source: `none`
- Outcome: No ATT&CK mapping produced for this Firewall log; handled gracefully as `no_mapping`. Parser extracted 3 normalized field(s); 0 mapping evidence ref(s); severity `info`.

```
date=2026-04-18 time=03:15:00 devname= srcip=10.10.25.10 dstip=198.51.100.1 bytes=ERR
```

### Record 37

- Family / subtype: `Firewall` / `Fortinet KV`
- Intent: `Malformed`
- Expected technique: — — actual: —
- Severity: `info` — mapping source: `none`
- Outcome: No ATT&CK mapping produced for this Firewall log; handled gracefully as `no_mapping`. Parser extracted 4 normalized field(s); 0 mapping evidence ref(s); severity `info`.

```
date=2026-04-18 time=03:15:05 srcip=10.10.25.10 dstip= dstport=0 action=accept
```

### Record 38

- Family / subtype: `Firewall` / `Fortinet KV`
- Intent: `Malformed`
- Expected technique: — — actual: —
- Severity: `info` — mapping source: `none`
- Outcome: No ATT&CK mapping produced for this Firewall log; handled gracefully as `no_mapping`. Parser extracted 5 normalized field(s); 0 mapping evidence ref(s); severity `info`.

```
date=2026-04-18 time=03:15:10 devname="FW-CORE-01" srcip=10.10.25.10 dstip=198.51.100.1 sentbyte=NaN rcvdbyte=NaN
```

### Record 39

- Family / subtype: `Firewall` / `Fortinet KV`
- Intent: `Malformed`
- Expected technique: — — actual: —
- Severity: `info` — mapping source: `none`
- Outcome: No ATT&CK mapping produced for this Firewall log; handled gracefully as `no_mapping`. Parser extracted 3 normalized field(s); 0 mapping evidence ref(s); severity `info`.

```
date=9999-99-99 time=99:99:99 devname="FW-CORE-01" srcip=256.256.256.256 dstip=10.10.10.10
```

### Record 84

- Family / subtype: `IDS` / `Zeek JSON`
- Intent: `Malformed`
- Expected technique: — — actual: —
- Severity: `info` — mapping source: `none`
- Outcome: No ATT&CK mapping produced for this IDS log; handled gracefully as `no_mapping`. Parser extracted 2 normalized field(s); 0 mapping evidence ref(s); severity `info`.

```
{"ts":null,"uid":1234,"id.orig_h":"10.10.10"}
```

### Record 85

- Family / subtype: `IDS` / `Zeek JSON`
- Intent: `Malformed`
- Expected technique: — — actual: —
- Severity: `info` — mapping source: `none`
- Outcome: No ATT&CK mapping produced for this IDS log; handled gracefully as `no_mapping`. Parser extracted 1 normalized field(s); 0 mapping evidence ref(s); severity `info`.

```
{"ts":1713411000,"uid":"","id.orig_h":"999.999.999.999"}
```

### Record 86

- Family / subtype: `IDS` / `Zeek JSON`
- Intent: `Malformed`
- Expected technique: — — actual: —
- Severity: `info` — mapping source: `none`
- Outcome: No ATT&CK mapping produced for this IDS log; handled gracefully as `no_mapping`. Parser extracted 1 normalized field(s); 0 mapping evidence ref(s); severity `info`.

```
{"ts":1713411010,"uid":"C123","id.orig_h":10.10.10.10}
```

### Record 87

- Family / subtype: `IDS` / `Zeek JSON`
- Intent: `Malformed`
- Expected technique: — — actual: —
- Severity: `info` — mapping source: `none`
- Outcome: No ATT&CK mapping produced for this IDS log; handled gracefully as `no_mapping`. Parser extracted 1 normalized field(s); 0 mapping evidence ref(s); severity `info`.

```
{"ts":1713411020,"id.orig_h":"10.10.25.10",}
```

### Record 132

- Family / subtype: `Windows` / `Winlogbeat JSON`
- Intent: `Malformed`
- Expected technique: — — actual: —
- Severity: `info` — mapping source: `none`
- Outcome: No ATT&CK mapping produced for this Windows log; handled gracefully as `no_mapping`. Parser extracted 1 normalized field(s); 0 mapping evidence ref(s); severity `info`.

```
{"@timestamp":"NULL","winlog":{"event_id":4624,"event_data":{"TargetUserName":{}}}}
```

### Record 133

- Family / subtype: `Windows` / `Winlogbeat JSON`
- Intent: `Malformed`
- Expected technique: — — actual: —
- Severity: `info` — mapping source: `none`
- Outcome: No ATT&CK mapping produced for this Windows log; handled gracefully as `no_mapping`. Parser extracted 2 normalized field(s); 0 mapping evidence ref(s); severity `info`.

```
{"@timestamp":"2026-04-18T03:15:00Z","winlog":{"event_id":"ERR","event_data":{"ProcessName":"\\.\\PhysicalDrive0"}}}
```

### Record 134

- Family / subtype: `Windows` / `Winlogbeat JSON`
- Intent: `Malformed`
- Expected technique: — — actual: —
- Severity: `info` — mapping source: `none`
- Outcome: No ATT&CK mapping produced for this Windows log; handled gracefully as `no_mapping`. Parser extracted 2 normalized field(s); 0 mapping evidence ref(s); severity `info`.

```
{"@timestamp":"2026-13-45T25:00:00Z","winlog":{"event_id":"4688"}}
```

### Record 135

- Family / subtype: `Windows` / `Winlogbeat JSON`
- Intent: `Malformed`
- Expected technique: — — actual: —
- Severity: `info` — mapping source: `none`
- Outcome: No ATT&CK mapping produced for this Windows log; handled gracefully as `no_mapping`. Parser extracted 2 normalized field(s); 0 mapping evidence ref(s); severity `info`.

```
{"@timestamp":"2026-04-18T03:15:10Z","winlog":{"event_id":"4688","event_data":{"CommandLine":[1,2,3]}}}
```

### Record 180

- Family / subtype: `Linux` / `Syslog`
- Intent: `Malformed`
- Expected technique: — — actual: —
- Severity: `info` — mapping source: `none`
- Failing assertions: `family_match`, `subtype_match`
- Triage: `heuristic_limit`
- Outcome: No ATT&CK mapping produced for this Linux log; handled gracefully as `no_mapping`. Parser extracted 0 normalized field(s); 0 mapping evidence ref(s); severity `info`.

```
Apr 18 03:45:00 srv-linux-01 : %LOG_SYSTEM_FAILURE% error_code=0xDEADBEEF
```

### Record 181

- Family / subtype: `Linux` / `Syslog`
- Intent: `Malformed`
- Expected technique: — — actual: —
- Severity: `info` — mapping source: `none`
- Outcome: No ATT&CK mapping produced for this Linux log; handled gracefully as `no_mapping`. Parser extracted 0 normalized field(s); 0 mapping evidence ref(s); severity `info`.

```
Apr 99 77:77:77 badhost sshd[]: Accepted password for ??? from 999.999.999.999 port -1
```

### Record 182

- Family / subtype: `Linux` / `Syslog`
- Intent: `Malformed`
- Expected technique: — — actual: —
- Severity: `info` — mapping source: `none`
- Outcome: No ATT&CK mapping produced for this Linux log; handled gracefully as `no_mapping`. Parser extracted 1 normalized field(s); 0 mapping evidence ref(s); severity `info`.

```
srv-linux-01 sudo root COMMAND=/bin/bash
```

### Record 183

- Family / subtype: `Linux` / `Syslog`
- Intent: `Malformed`
- Expected technique: — — actual: —
- Severity: `info` — mapping source: `none`
- Outcome: No ATT&CK mapping produced for this Linux log; handled gracefully as `no_mapping`. Parser extracted 0 normalized field(s); 0 mapping evidence ref(s); severity `info`.

```
Apr 18 03:45:15 sshd[abc]: Invalid user from port ssh2
```

