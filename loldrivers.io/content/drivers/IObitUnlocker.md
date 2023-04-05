+++

description = ""
title = "IObitUnlocker.sys"
weight = 10

+++


{{< block "grid-1" >}}
{{< column "mt-2 pt-1">}}


# IObitUnlocker.sys 


{{< tip "warning" >}}
We were not able to verify the hash of this driver successfully, it has not been confirmed.
{{< /tip >}}


### Description

IObitUnlocker.sys is a vulnerable driver and more information will be added as found.

- **Created**: 2023-01-09
- **Author**: Michael Haag
- **Acknowledgement**:  | [](https://twitter.com/)

### Commands

```
sc.exe create IObitUnlocker.sys binPath=C:\windows\temp\IObitUnlocker.sys type=kernel
sc.exe start IObitUnlocker.sys
```

| Use Case | Privilages | Operating System | 
|:---- | ---- | ---- |
| Elevate privileges | kernel | Windows 10 |

### Resources
<br>
<li><a href=" https://learn.microsoft.com/en-us/windows/security/threat-protection/windows-defender-application-control/microsoft-recommended-driver-block-rules"> https://learn.microsoft.com/en-us/windows/security/threat-protection/windows-defender-application-control/microsoft-recommended-driver-block-rules</a></li>
<li><a href="https://learn.microsoft.com/en-us/windows/security/threat-protection/windows-defender-application-control/microsoft-recommended-driver-block-rules">https://learn.microsoft.com/en-us/windows/security/threat-protection/windows-defender-application-control/microsoft-recommended-driver-block-rules</a></li>
<br>

### Known Vulnerable Samples

| Filename | IObitUnlocker.sys |
|:---- | ---- | 
| MD5 | <a href="https://www.virustotal.com/gui/file/2391fb461b061d0e5fccb050d4af7941">2391fb461b061d0e5fccb050d4af7941</a> |
| SHA1 | <a href="https://www.virustotal.com/gui/file/7c6cad6a268230f6e08417d278dda4d66bb00d13">7c6cad6a268230f6e08417d278dda4d66bb00d13</a> |
| SHA256 | <a href="https://www.virustotal.com/gui/file/f85cca4badff17d1aa90752153ccec77a68ad282b69e3985fdc4743eaea85004">f85cca4badff17d1aa90752153ccec77a68ad282b69e3985fdc4743eaea85004</a> |
| Signature | IObit CO., LTD, DigiCert EV Code Signing CA, DigiCert   |


[*source*](https://github.com/magicsword-io/LOLDrivers/tree/main/yaml/iobitunlocker.sys.yml)

*last_updated:* 2023-04-04








{{< /column >}}
{{< /block >}}
