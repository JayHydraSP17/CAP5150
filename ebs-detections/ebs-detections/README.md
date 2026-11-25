# Detecting a Zero Day: CVE-2025-61882 Detection Rules

Code and test data for the CAP 5150 final report *Catching a Zero Day Before the Patch:
Layered Detection and Root-Cause Analysis of the Oracle E-Business Suite Campaign
(CVE-2025-61882)*.

The rules target the Oracle E-Business Suite (EBS) exploitation campaign that ran from
August 9, 2025 until Oracle's patch on October 4, 2025. Every rule is tested offline
against **synthetic** traffic and logs. No vulnerable EBS build, live system, or exploit
code is used, and nothing in this repository sends traffic anywhere.

## Repository layout

| Path | Contents |
|---|---|
| `suricata/ebs-cve-2025-61882.rules` | 7 network rules (sids 1000001-1000007) |
| `sigma/` | 4 Sigma rules: 2 host (process creation), 2 web log |
| `sql/xdo_hunt.sql` | Database hunt for malicious XSL templates (written, not executed) |
| `scripts/make_pcaps.py` | Builds `testdata/attack.pcap` and `testdata/benign.pcap` with Scapy |
| `scripts/run_suricata.sh` | Replays both PCAPs through Suricata and prints alerts |
| `scripts/test_sigma.py` | Converts the Sigma rules to SQLite and runs them over synthetic logs |
| `testdata/` | The generated PCAPs used for the reported results |

## Detection layers

| Layer | Tool | Attack stages covered |
|---|---|---|
| Network (N) | Suricata | UiServlet SSRF, SyncServlet POST, TemplatePreviewPG with `TMP`/`DEF` code, reverse shell, published attacker IPs |
| Host (H) | Sigma (process creation) | Java spawning an interactive shell, `applmgr` running discovery commands |
| Web log (W) | Sigma (webserver) | External servlet POSTs, TemplatePreviewPG with `TMP`/`DEF` code |
| Database (D) | SQL | Payload templates stored in `XDO_TEMPLATES_B` / `XDO_LOBS` |

## Reproducing the results

Tested on Ubuntu 24.04 in VirtualBox (NAT adapter for installs only, no bridged
networking, restored from a clean snapshot before each run).

```bash
sudo apt update
sudo apt install -y suricata python3-pip
pip install --break-system-packages scapy sigma-cli pySigma-backend-sqlite

python3 scripts/make_pcaps.py     # rebuild synthetic PCAPs (optional; copies are in testdata/)
bash scripts/run_suricata.sh      # network rules
python3 scripts/test_sigma.py     # host and web-log rules
```

## Results

Suricata 7.0.3, sigma-cli with the SQLite backend.

Pre-disclosure class: **G** = generic (could be written with no knowledge of this
campaign), **E** = EBS-specific (needs details published in October 2025),
**I** = indicator (needs attacker IPs published October 4, 2025).

| Rule | Layer | Detects | ATT&CK | Class | Attack hits | False positives |
|---|---|---|---|---|---|---|
| 1000001 | N | UiServlet `getUiType` XML | T1190 | E | 1/1 | 0 |
| 1000002 | N | UiServlet `return_url` SSRF | T1190 | E | 1/1 | 0 |
| 1000003 | N | POST to SyncServlet | T1190 | E | 1/1 | 0 |
| 1000004 | N | TemplatePreviewPG + `TMP`/`DEF` | T1059 | E | 2/2 | 0 |
| 1000005 | N | Outbound to published C2 IPs | T1071.001 | I | 1/1 | 0 |
| 1000006 | N | Inbound from exploit-source IPs | T1190 | I | 1/1 | 0 |
| 1000007 | N | `bash -i` + `/dev/tcp/` | T1059.004 | G | 1/1 | 0 |
| java_shell | H | Java -> interactive shell | T1059.004 | G | 1/1 | 0/6 |
| applmgr_recon | H | Recon under Java parent | T1082, T1016, T1033 | G | 4/4 | 0/6 |
| web_servlet | W | External servlet POST | T1190 | E | 2/2 | 0/5 |
| web_preview | W | TemplatePreviewPG + `TMP`/`DEF` | T1059 | E | 2/2 | 0/5 |
| xdo_hunt | D | Payload templates in DB | T1505 | E | not tested | - |

`test_sigma.py` prints each Sigma rule's hits against the whole attack set (for example
`applmgr_recon 4/5`), because each rule targets only its own slice. The table above
counts only each rule's target events; the script's combined-coverage line shows that
every attack event (5/5 process, 4/4 web) was caught by at least one rule.

### Benign near-misses

The benign data deliberately includes events that look like the attack, so zero false
positives tests each rule's specificity:

- TemplatePreviewPG with legitimate code `XXAP_INVOICE` (1000004, web_preview)
- Bare `GET` to UiServlet, and an internal UiServlet POST with ordinary form data (1000001, 1000002, web_servlet)
- Java running a non-interactive script (java_shell)
- `applmgr` running `id` and `ps` from a terminal, not a Java parent (applmgr_recon)
- Ordinary outbound HTTPS from the EBS host to a non-C2 address (1000005)

## Limitations

- **Circular test data.** Rules and test data both come from the same public reports, so
  the results show the rules match documented behavior, not that they catch unseen variants.
- **Indicator rules (1000005, 1000006)** could not have existed before October 4, 2025 and
  are easy for an attacker to evade by changing infrastructure.
- **SyncServlet rules** are low-fidelity until legitimate use is baselined.
- **TLS.** URI-based network rules need a sensor after TLS termination (load balancer or
  reverse proxy); the web-log rules cover the same stages when that isn't possible.
- **Database hunt** was written against the published table layout and not executed,
  since no licensed EBS database was available.
- **In-memory persistence** (servlet-filter implants) has no rule.

## Sources

- Oracle, Security Alert Advisory: CVE-2025-61882
- Google Threat Intelligence Group and Mandiant, *Oracle E-Business Suite Zero-Day Exploited in Widespread Extortion Campaign*
- CrowdStrike, campaign targeting Oracle EBS via CVE-2025-61882
- Cyderes Howler Cell, *Investigation into Oracle E-Business Suite Exploit Components*
