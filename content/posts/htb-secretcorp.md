---
title: "HackTheBox: SecretCorp Writeup"
date: 2025-11-03
draft: false
tags: ["CTF", "HackTheBox", "Web Exploitation"]
categories: ["HackTheBox"]
---

## 🧩 Challenge Overview
This challenge involved exploiting a misconfigured web app to gain unauthorized access to internal data.

---

## 🔍 Enumeration
\`\`\`bash
nmap -sC -sV 10.10.10.10
\`\`\`
Discovered ports:
- 80/tcp, HTTP (Apache 2.4.41)
- 22/tcp, SSH (OpenSSH 8.2p1)

---

## 💥 Exploitation
During directory fuzzing with \`ffuf\`, found \`/backup.zip\`. 
Unzipped credentials for \`admin:SuperSecure123\`. 
Login exposed an **LFI vulnerability** at \`index.php?file=...\`.

\`\`\`bash
curl "http://target/index.php?file=../../../../etc/passwd"
\`\`\`

---

## 🧑‍💻 Privilege Escalation
After gaining shell access:
\`\`\`bash
linpeas.sh | tee output.txt
\`\`\`
Found \`/usr/local/bin/backup\` with SUID bit. 
Exploited it via \`bash -p\` to spawn a root shell.

---

## 🧾 Lessons Learned
- Always check for exposed archives.
- Automate directory brute-forcing early.
- LFI → Config file disclosure → RCE chain is common in PHP apps.

---

## 📸 Screenshots
![LFI Exploit Screenshot](/images/lfi_exploit.png)
