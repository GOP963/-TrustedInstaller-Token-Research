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


## 🧨 Threat Actors Observed Using This Technique

The following APT groups have been observed leveraging **Access Token Manipulation (T1134)** and **Create Process with Token (T1134.002)** according to MITRE ATT&CK:

- **[APT28 – Fancy Bear](https://attack.mitre.org/groups/G0007/)**
- **[APT29 – Cozy Bear](https://attack.mitre.org/groups/G0016/)**
- **[FIN7](https://attack.mitre.org/groups/G0046/)**
- **[Turla](https://attack.mitre.org/groups/G0010/)**
- **[Lazarus Group](https://attack.mitre.org/groups/G0032/)**
- **[OilRig – APT34](https://attack.mitre.org/groups/G0049/)**

> ⚠️ **Disclaimer:**  
> This repository is intended strictly for **educational and defensive security research purposes**.  
> The inclusion of threat actor references does not imply endorsement or malicious intent.

## 📚 Notes
This code is intentionally kept simple for learning purposes.
