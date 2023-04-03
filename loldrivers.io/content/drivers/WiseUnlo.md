+++

description = "https://learn.microsoft.com/en-us/windows/security/threat-protection/windows-defender-application-control/microsoft-recommended-driver-block-rules"
title = "WiseUnlo.sys"
weight = 10

+++


{{< block "grid-1" >}}
{{< column "mt-2 pt-1">}}


# WiseUnlo.sys 


{{< tip "warning" >}}
We were not able to verify the hash of this driver successfully, it has not been confirmed.
{{< /tip >}}


### Description

WiseUnlo.sys is a vulnerable driver and more information will be added as found.

- **Created**: 2023-01-09
- **Author**: Michael Haag
- **Acknowledgement**:  | [](https://twitter.com/)

### Commands

```
sc.exe create WiseUnlo.sys binPath=C:\windows\temp\WiseUnlo.sys type=kernel
sc.exe start WiseUnlo.sys
```

| Use Case | Privilages | Operating System | 
|:---- | ---- | ---- |
| Elevate privileges | kernel | Windows 10 |

### Resources
<br>
<li><a href=" https://learn.microsoft.com/en-us/windows/security/threat-protection/windows-defender-application-control/microsoft-recommended-driver-block-rules"> https://learn.microsoft.com/en-us/windows/security/threat-protection/windows-defender-application-control/microsoft-recommended-driver-block-rules</a></li>
<br>

### Known Vulnerable Samples

| Filename | WiseUnlo.sys |
|:---- | ---- | 
| MD5 | <a href="https://www.virustotal.com/gui/file/356bda2bf0f6899a2c08b2da3ec69f13">356bda2bf0f6899a2c08b2da3ec69f13</a> |
| SHA1 | <a href="https://www.virustotal.com/gui/file/b9807b8840327c6d7fbdde45fc27de921f1f1a82">b9807b8840327c6d7fbdde45fc27de921f1f1a82</a> |
| SHA256 | <a href="https://www.virustotal.com/gui/file/358ac54be252673841a1d65bfc2fb6d549c1a4c877fa7f5e1bfa188f30375d69">358ac54be252673841a1d65bfc2fb6d549c1a4c877fa7f5e1bfa188f30375d69</a> |
| Signature | Lespeed Technology Co., Ltd, COMODO RSA Extended Validation Code Signing CA, Sectigo (formerly Comodo CA)   |


[*source*](https://github.com/magicsword-io/LOLDrivers/tree/main/yaml/wiseunlo.sys.yml)

*last_updated:* 2023-04-03








{{< /column >}}
{{< /block >}}
