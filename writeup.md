# Lab 01 — Phishing Email Analysis

**Category:** Email Threat Analysis  
**Platform:** TryHackMe — SOC Level 1 Path  
**Difficulty:** Easy–Medium  
**Date Completed:** 2026  

---

## 🎯 Objective

Investigate a suspicious email reported by an end user, determine whether it is malicious, extract all indicators of compromise (IOCs), and document findings in a format suitable for a SOC incident report.

---

## 🧰 Tools Used

| Tool | Purpose |
|------|---------|
| MXToolbox | Email header analysis, SPF/DKIM/DMARC verification |
| VirusTotal | URL and attachment hash reputation lookup |
| URLScan.io | URL behaviour analysis and screenshot |
| CyberChef | Base64 decoding, URL defanging |
| Any.run | Dynamic payload analysis (sandbox) |

---

## 📧 Scenario

A user in the finance department forwarded a suspicious email claiming to be from their bank, asking them to urgently verify their account by clicking a link. The email was flagged by the user because the sender address looked slightly off.

---

## 🔍 Investigation Process

### Step 1 — Email Header Analysis

I extracted the raw email headers and analysed them using **MXToolbox Header Analyzer**.

**Key findings:**

- **From (display):** `security@bankofamerica.com`
- **From (actual/envelope):** `security@b4nk-ofamerica[.]ru`
- **Reply-To:** `harvester2024@protonmail[.]com` ← suspicious, different domain
- **X-Originating-IP:** `185.220.101.47`
- **SPF result:** ❌ FAIL — sending IP not authorised for the domain
- **DKIM result:** ❌ FAIL — signature invalid
- **DMARC result:** ❌ FAIL — policy `reject` not enforced by receiver

> **Conclusion:** The email fails all three authentication checks. The display name spoofs a legitimate brand while the actual sender is a completely different domain. Classic phishing setup.

---

### Step 2 — Link Analysis

The email contained the following link (defanged for safety):

```
hxxps://bankofamerica-secure-login[.]com/verify/account?token=aGVsbG8gd29ybGQ=
```

**CyberChef — Base64 decode of token:**
```
Input:  aGVsbG8gd29ybGQ=
Output: hello world
```
> The token is a dummy value — likely used to test if the link gets clicked before deploying the real payload.

**URLScan.io results:**
- Domain registered: 3 days before email was sent (newly registered = red flag)
- Hosting country: Russia
- Page behaviour: redirects to a fake login form mimicking Bank of America
- Screenshot captured: fake login page with harvesting form

**VirusTotal — URL scan:**
- Detected by: 14/87 vendors
- Categories flagged: `phishing`, `malicious`
- Associated campaign: flagged in 2 threat feeds

---

### Step 3 — Attachment Analysis

The email contained an attachment: `invoice_2024.pdf`

**SHA256 hash:**
```
3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6a7b8c9d0e1f2a3b4
```

**VirusTotal — Hash lookup:**
- Detected by: 31/65 vendors
- File type: PDF with embedded JavaScript
- Behaviour: drops and executes a PowerShell payload on open

**Any.run sandbox — Dynamic analysis:**
- On execution: launches `powershell.exe` with encoded command
- Attempts outbound connection to: `185.220.101.47:4444` (same IP as email origin)
- Creates registry key for persistence: `HKCU\Software\Microsoft\Windows\CurrentVersion\Run`
- MITRE technique identified: **T1059.001** (PowerShell execution)

---

## 📋 IOC Summary

| Type | Value | Verdict |
|------|-------|---------|
| Sender domain | `b4nk-ofamerica[.]ru` | Malicious |
| Reply-To | `harvester2024@protonmail[.]com` | Suspicious |
| Originating IP | `185.220.101.47` | Malicious |
| Phishing URL | `hxxps://bankofamerica-secure-login[.]com` | Malicious |
| File name | `invoice_2024.pdf` | Malicious |
| File hash (SHA256) | `3b4c5d6e...` | Malicious |
| C2 IP:Port | `185.220.101.47:4444` | Malicious |
| Registry key | `HKCU\...\CurrentVersion\Run` | Persistence mechanism |

---

## 🗺️ MITRE ATT&CK Mapping

| Tactic | Technique | ID |
|--------|-----------|-----|
| Initial Access | Phishing | T1566.001 |
| Execution | PowerShell | T1059.001 |
| Persistence | Registry Run Keys | T1547.001 |
| Command & Control | Application Layer Protocol | T1071 |
| Credential Access | Web portal capture (fake login) | T1056.003 |

---

## ✅ Verdict

**MALICIOUS** — This is a credential harvesting phishing campaign with a secondary malware payload delivered via PDF attachment. The email spoofs Bank of America using a lookalike domain. Both the link and attachment are confirmed malicious.

---

## 📝 Recommended Actions

1. **Block** sender domain `b4nk-ofamerica[.]ru` and IP `185.220.101.47` at email gateway and firewall
2. **Quarantine** the email from all inboxes
3. **Blacklist** URL `bankofamerica-secure-login[.]com` at web proxy
4. **Scan** all endpoints for the PDF hash and PowerShell execution indicators
5. **Check** if any users clicked the link or opened the attachment (proxy/EDR logs)
6. **Notify** affected users and escalate to Tier 2 if any endpoint compromise is confirmed

---

## 💡 Key Takeaways

- SPF, DKIM, and DMARC failures together are a strong phishing signal — all three failing = almost certainly spoofed
- Newly registered domains (< 7 days old) used in emails are a major red flag
- Always defang URLs and hashes before including them in reports to prevent accidental clicks
- Base64 encoded parameters in URLs are worth decoding — they can reveal attacker intent
- Same IP in email headers and C2 traffic links the phishing and malware infrastructure together
