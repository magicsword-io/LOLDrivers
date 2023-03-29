+++

description = "https://learn.microsoft.com/en-us/windows/security/threat-protection/windows-defender-application-control/microsoft-recommended-driver-block-rules"
title = "nt4.sys"
weight = 10

+++


{{< block "grid-1" >}}
{{< column "mt-2 pt-1">}}


# nt4.sys 


{{< tip "warning" >}}
We were not able to verify the hash of this driver successfully, it has not been confirmed.
{{< /tip >}}


### Description

nt4.sys is a vulnerable driver and more information will be added as found.

- **Created**: 2023-01-09
- **Author**: Michael Haag
- **Acknowledgement**:  | [](https://twitter.com/)

### Commands

```
sc.exe create nt4.sys binPath=C:\windows\temp\nt4.sys type=kernel
sc.exe start nt4.sys
```

| Use Case | Privilages | Operating System | 
|:---- | ---- | ---- |
| Elevate privileges | kernel | Windows 10 |

### Resources
<br>
<li><a href=" https://learn.microsoft.com/en-us/windows/security/threat-protection/windows-defender-application-control/microsoft-recommended-driver-block-rules"> https://learn.microsoft.com/en-us/windows/security/threat-protection/windows-defender-application-control/microsoft-recommended-driver-block-rules</a></li>
<br>

### Known Vulnerable Samples

| Filename | nt4.sys |
|:---- | ---- | 
| MD5 | <a href="https://www.virustotal.com/gui/file/-">-</a> |
| SHA1 | <a href="https://www.virustotal.com/gui/file/-">-</a> |
| SHA256 | <a href="https://www.virustotal.com/gui/file/d7bc7306cb489fe4c285bbeddc6d1a09e814ef55cf30bd5b8daf87a52396f102">d7bc7306cb489fe4c285bbeddc6d1a09e814ef55cf30bd5b8daf87a52396f102</a> |
| Publisher |  |
| Signature | -   |
| Date |  |
| Company |  |
| Description |  |
| Product |  |
| ProductVersion |  |
| FileVersion |  |
| MachineType |  |
| OriginalFilename |  |



[*source*](https://github.com/magicsword-io/LOLDrivers/tree/main/yaml/nt4.sys.yml)

*last_updated:* 2023-03-29








{{< /column >}}
{{< /block >}}
