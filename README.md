# TrustedInstaller Token Research

## ⚠️ Disclaimer
This project is for **educational and research purposes only**.

It demonstrates how Windows access tokens, impersonation,
and privilege boundaries work internally.

❌ Not intended for malicious use  
❌ Do not run on systems you do not own  
✅ Security research & learning only

## 🧠 Topics Covered
- Windows Access Tokens
- SeDebugPrivilege
- SYSTEM vs TrustedInstaller
- Service-based token acquisition
- Process impersonation

## 🧪 Environment
- Windows 10 / 11
- Visual Studio (Latest)
- x64

## Demo

![TrustedInstaller Token Demo](Token.gif)

---

## 🧠 MITRE ATT&CK Mapping

- **Privilege Escalation**  
  *(TA0004)*  
  https://attack.mitre.org/tactics/TA0004/

  └── **Access Token Manipulation**  
&nbsp;&nbsp;&nbsp;&nbsp;*(T1134)*  
&nbsp;&nbsp;&nbsp;&nbsp;https://attack.mitre.org/techniques/T1134/

&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;└── **Create Process with Token**  
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;*(T1134.002)*  
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;https://attack.mitre.org/techniques/T1134/002/


## 📚 Notes
This code is intentionally kept simple for learning purposes.
