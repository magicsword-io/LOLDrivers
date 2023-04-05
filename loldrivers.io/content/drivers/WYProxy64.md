+++

description = ""
title = "WYProxy64.sys"
weight = 10

+++


{{< block "grid-1" >}}
{{< column "mt-2 pt-1">}}


# WYProxy64.sys 


{{< tip "warning" >}}
We were not able to verify the hash of this driver successfully, it has not been confirmed.
{{< /tip >}}


### Description

WYProxy64.sys is a vulnerable driver and more information will be added as found.

- **Created**: 2023-01-09
- **Author**: Michael Haag
- **Acknowledgement**:  | [](https://twitter.com/)

### Commands

```
sc.exe create WYProxy64.sys binPath=C:\windows\temp\WYProxy64.sys type=kernel
sc.exe start WYProxy64.sys
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

| Filename | WYProxy64.sys |
|:---- | ---- | 
| MD5 | <a href="https://www.virustotal.com/gui/file/-">-</a> |
| SHA1 | <a href="https://www.virustotal.com/gui/file/-">-</a> |
| SHA256 | <a href="https://www.virustotal.com/gui/file/fafa1bb36f0ac34b762a10e9f327dcab2152a6d0b16a19697362d49a31e7f566">fafa1bb36f0ac34b762a10e9f327dcab2152a6d0b16a19697362d49a31e7f566</a> |
| Signature | -   |


[*source*](https://github.com/magicsword-io/LOLDrivers/tree/main/yaml/wyproxy64.sys.yml)

*last_updated:* 2023-04-04








{{< /column >}}
{{< /block >}}
