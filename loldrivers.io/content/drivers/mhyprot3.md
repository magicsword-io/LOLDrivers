+++

description = ""
title = "mhyprot3.sys"
weight = 10

+++


{{< block "grid-1" >}}
{{< column "mt-2 pt-1">}}


# mhyprot3.sys 


{{< tip "warning" >}}
We were not able to verify the hash of this driver successfully, it has not been confirmed.
{{< /tip >}}


### Description

mhyprot3.sys is a vulnerable driver and more information will be added as found.

- **Created**: 2023-01-09
- **Author**: Michael Haag
- **Acknowledgement**:  | [](https://twitter.com/)

### Commands

```
sc.exe create mhyprot3.sys binPath=C:\windows\temp\mhyprot3.sys type=kernel &amp;&amp; sc.exe start mhyprot3.sys
```

| Use Case | Privileges | Operating System | 
|:---- | ---- | ---- |
| Elevate privileges | kernel | Windows 10 |

### Resources
<br>
<li><a href=" https://learn.microsoft.com/en-us/windows/security/threat-protection/windows-defender-application-control/microsoft-recommended-driver-block-rules"> https://learn.microsoft.com/en-us/windows/security/threat-protection/windows-defender-application-control/microsoft-recommended-driver-block-rules</a></li>
<li><a href="https://learn.microsoft.com/en-us/windows/security/threat-protection/windows-defender-application-control/microsoft-recommended-driver-block-rules">https://learn.microsoft.com/en-us/windows/security/threat-protection/windows-defender-application-control/microsoft-recommended-driver-block-rules</a></li>
<br>

### Known Vulnerable Samples

| Filename | mhyprot3.sys |
|:---- | ---- | 
| MD5 | <a href="https://www.virustotal.com/gui/file/5cc5c26fc99175997d84fe95c61ab2c2">5cc5c26fc99175997d84fe95c61ab2c2</a> |
| SHA1 | <a href="https://www.virustotal.com/gui/file/a197a02025946aca96d6e74746f84774df31249e">a197a02025946aca96d6e74746f84774df31249e</a> |
| SHA256 | <a href="https://www.virustotal.com/gui/file/475e5016c9c0f5a127896f9179a1b1577a67b357f399ab5a1e68aab07134729a">475e5016c9c0f5a127896f9179a1b1577a67b357f399ab5a1e68aab07134729a</a> |
| Signature | miHoYo Co.,Ltd., DigiCert SHA2 Assured ID Code Signing CA, DigiCert   |


[*source*](https://github.com/magicsword-io/LOLDrivers/tree/main/yaml/mhyprot3.yaml)

*last_updated:* 2023-04-14








{{< /column >}}
{{< /block >}}
