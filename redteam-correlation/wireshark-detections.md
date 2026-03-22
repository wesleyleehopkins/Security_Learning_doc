# Wireshark Display & Capture Filters — Red Team Correlation

## Overview

Companion detection file for Wireshark, mapped to the pentest lab attack chain. All filters reference the lab network 192.168.56.0/24 with Kali attacker at .103, Ubuntu target at .102, and Windows target at .101.

---

## Capture Filters (BPF Syntax)

Apply these **before** starting a capture to reduce noise.

| Phase | BPF Capture Filter |
|---|---|
| All attacker traffic | `host 192.168.56.103` |
| Attacker to Ubuntu only | `host 192.168.56.103 and host 192.168.56.102` |
| Attacker to Windows only | `host 192.168.56.103 and host 192.168.56.101` |
| TCP only from attacker | `src host 192.168.56.103 and tcp` |
| UDP only from attacker | `src host 192.168.56.103 and udp` |
| Web traffic to targets | `host 192.168.56.103 and tcp port 80 or tcp port 443` |
| SMB traffic | `tcp port 445` |
| SSH traffic | `tcp port 22` |
| DNS traffic | `udp port 53 or tcp port 53` |
| High ports (reverse shells) | `host 192.168.56.103 and tcp portrange 4000-5000` |

---

## Display Filters by Phase

### Phase 2: Active Scanning

**1. Nmap SYN scan (half-open)**
```
tcp.flags.syn==1 && tcp.flags.ack==0 && ip.src==192.168.56.103
```

**2. SYN scan with RST responses (closed ports)**
```
tcp.flags.reset==1 && ip.dst==192.168.56.103
```

**3. Nmap service/version detection (-sV)**
```
ip.src==192.168.56.103 && tcp.flags.syn==1 && tcp.window_size<=1024
```

**4. Nmap aggressive scan banner grabs**
```
ip.src==192.168.56.103 && tcp.len>0 && tcp.flags.push==1
```

**5. UDP scan traffic**
```
ip.src==192.168.56.103 && udp
```

**6. ICMP unreachable (closed UDP ports)**
```
icmp.type==3 && icmp.code==3 && ip.dst==192.168.56.103
```

**7. SMB enumeration (enum4linux, smbclient)**
```
ip.src==192.168.56.103 && smb2 || ip.src==192.168.56.103 && smb
```

**8. SMB share listing**
```
smb2.cmd==3 && ip.src==192.168.56.103
```

**9. HTTP directory brute force (gobuster, dirb, feroxbuster)**
```
http.request.method=="GET" && ip.src==192.168.56.103 && http.response.code==404
```

**10. High-rate scanning detection (many SYNs in short time)**
```
tcp.flags.syn==1 && tcp.flags.ack==0 && ip.src==192.168.56.103 && tcp.analysis.retransmission
```

---

### Phase 3: Web Exploitation

**11. SQL injection in URI (UNION-based)**
```
http.request.uri contains "UNION" || http.request.uri contains "union" || http.request.uri contains "SELECT"
```

**12. SQL injection (OR-based auth bypass)**
```
http.request.uri contains "OR+1" || http.request.uri contains "or+1%3D1" || http.request.uri contains "%27OR"
```

**13. SQL injection in POST body**
```
http.request.method=="POST" && ip.src==192.168.56.103 && (http contains "UNION" || http contains "SELECT" || http contains "DROP")
```

**14. XSS payloads in requests**
```
http.request.uri contains "<script" || http.request.uri contains "%3Cscript" || http.request.uri contains "onerror"
```

**15. Command injection patterns**
```
http.request.uri contains "%3B" || http.request.uri contains "%7C" || http.request.uri contains "%60"
```

**16. File upload via POST (web shell delivery)**
```
http.request.method=="POST" && http.content_type contains "multipart/form-data" && ip.src==192.168.56.103
```

**17. Local file inclusion (LFI)**
```
http.request.uri contains "..%2F" || http.request.uri contains "../" || http.request.uri contains "/etc/passwd"
```

**18. Remote file inclusion (RFI)**
```
http.request.uri contains "http%3A%2F%2F192.168.56.103" || http.request.uri contains "http://192.168.56.103"
```

---

### Phase 4: Password Attacks

**19. SSH brute force (many auth attempts)**
```
tcp.dstport==22 && ip.src==192.168.56.103 && ssh.message_code==50
```

**20. SSH auth failures (server side)**
```
tcp.srcport==22 && ip.dst==192.168.56.103 && ssh.message_code==51
```

**21. SMB authentication failures**
```
smb2.nt_status==0xc000006d && ip.src==192.168.56.103
```

**22. SMB login attempts (NTLMSSP negotiate)**
```
ntlmssp.messagetype==0x00000001 && ip.src==192.168.56.103
```

**23. HTTP POST brute force (login forms)**
```
http.request.method=="POST" && ip.src==192.168.56.103 && (http.request.uri contains "login" || http.request.uri contains "auth")
```

---

### Phase 5: Metasploit / Exploitation

**24. Meterpreter reverse TCP (default port 4444)**
```
tcp.port==4444 && ip.addr==192.168.56.103
```

**25. Meterpreter HTTPS callback**
```
tls && tcp.dstport==8443 && ip.dst==192.168.56.103
```

**26. Reverse shell connections to common attacker ports**
```
(tcp.dstport>=4440 && tcp.dstport<=4450) && ip.dst==192.168.56.103
```

**27. Payload download via HTTP from attacker**
```
http.request.method=="GET" && ip.dst==192.168.56.103 && (http.request.uri contains ".elf" || http.request.uri contains ".exe" || http.request.uri contains ".ps1")
```

**28. Metasploit HTTP stager traffic**
```
http && ip.dst==192.168.56.103 && tcp.len>0 && http.request.uri matches "^/[a-zA-Z0-9]{4}$"
```

---

### Phase 8: Post-Exploitation

**29. Reverse shell over non-standard port**
```
ip.dst==192.168.56.103 && tcp.dstport>=1024 && tcp.flags.push==1 && tcp.len<200
```

**30. Chisel tunneling / SOCKS proxy**
```
ip.addr==192.168.56.103 && tcp.port==8080 && tcp.len>0
```

**31. DNS exfiltration (long subdomain queries)**
```
dns.qry.name.len>50 && ip.src!=192.168.56.103
```

**32. DNS TXT record exfiltration**
```
dns.qry.type==16 && ip.src==192.168.56.102
```

**33. SMB file exfiltration (large writes)**
```
smb2.cmd==9 && ip.src==192.168.56.102 && ip.dst==192.168.56.103
```

**34. Tool staging via wget/curl from attacker HTTP server**
```
http.request.method=="GET" && ip.dst==192.168.56.103 && ip.src==192.168.56.102
```

**35. ICMP tunneling (oversized ICMP packets)**
```
icmp && data.len>64
```

---

## Protocol-Specific Analysis Techniques

### Follow TCP Stream
Right-click any packet in a suspicious conversation and select **Follow > TCP Stream** to reconstruct the full session. Useful for:
- Reverse shell command history: filter to `tcp.port==4444 && ip.addr==192.168.56.103`, then follow the stream to see all typed commands and output.
- SQL injection results: follow HTTP streams where the URI contained injection patterns to see exfiltrated database content in responses.
- File transfers: follow streams on port 80 to the attacker IP to reconstruct downloaded payloads.

### IO Graphs
Go to **Statistics > IO Graphs** to visualize traffic volume over time.
- Add a graph line for `ip.src==192.168.56.103 && tcp.flags.syn==1` to see scanning spikes.
- Add a line for `tcp.port==4444` to see when Meterpreter sessions were active.
- Compare attacker outbound vs inbound byte counts to spot exfiltration.

### Statistics > Conversations
Go to **Statistics > Conversations > TCP** tab:
- Sort by packets or bytes to find the most active connections from .103.
- Connections with sustained bidirectional traffic to high ports indicate interactive shells.
- Large byte counts from target to attacker suggest exfiltration.

### Expert Info
Go to **Analyze > Expert Information**:
- Look for a high count of RSTs (scan activity).
- Connection timeouts to the attacker IP indicate blocked reverse shell attempts.
- TCP retransmissions on shell ports may indicate an unstable C2 channel.

---

## Coloring Rules

Add these via **View > Coloring Rules** in Wireshark. Paste the filter into a new rule with the specified color.

| Rule Name | Filter | Color |
|---|---|---|
| Attacker SYN Scan | `tcp.flags.syn==1 && tcp.flags.ack==0 && ip.src==192.168.56.103` | Red background |
| Reverse Shell | `tcp.port==4444 && ip.addr==192.168.56.103` | Orange background |
| Meterpreter HTTPS | `tls && tcp.dstport==8443 && ip.dst==192.168.56.103` | Orange background |
| SQL Injection | `http.request.uri contains "UNION" \|\| http.request.uri contains "SELECT"` | Yellow background |
| Brute Force SSH | `tcp.dstport==22 && ip.src==192.168.56.103` | Magenta background |
| Brute Force SMB | `ntlmssp.messagetype==0x00000001 && ip.src==192.168.56.103` | Magenta background |
| File Download from Attacker | `http.request.method=="GET" && ip.dst==192.168.56.103` | Cyan background |
| DNS Exfil | `dns.qry.name.len>50` | Purple background |
| SMB Exfil | `smb2.cmd==9 && ip.dst==192.168.56.103` | Purple background |
| Command Injection | `http.request.uri contains "%3B" \|\| http.request.uri contains "%7C"` | Yellow background |
