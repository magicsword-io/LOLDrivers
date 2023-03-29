+++

description = "https://learn.microsoft.com/en-us/windows/security/threat-protection/windows-defender-application-control/microsoft-recommended-driver-block-rules"
title = "bwrs.sys"
weight = 10

+++


{{< block "grid-1" >}}
{{< column "mt-2 pt-1">}}


# bwrs.sys 


{{< tip "warning" >}}
We were not able to verify the hash of this driver successfully, it has not been confirmed.
{{< /tip >}}


### Description

bwrs.sys is a vulnerable driver and more information will be added as found.

- **Created**: 2023-01-09
- **Author**: Michael Haag
- **Acknowledgement**:  | [](https://twitter.com/)

### Commands

```
sc.exe create bwrs.sys binPath=C:\windows\temp\bwrs.sys type=kernel
sc.exe start bwrs.sys
```

| Use Case | Privilages | Operating System | 
|:---- | ---- | ---- |
| Elevate privileges | kernel | Windows 10 |

### Resources
<br>
<li><a href=" https://learn.microsoft.com/en-us/windows/security/threat-protection/windows-defender-application-control/microsoft-recommended-driver-block-rules"> https://learn.microsoft.com/en-us/windows/security/threat-protection/windows-defender-application-control/microsoft-recommended-driver-block-rules</a></li>
<br>

### Known Vulnerable Samples

| Filename | bwrs.sys |
|:---- | ---- | 
| MD5 | <a href="https://www.virustotal.com/gui/file/-">-</a> |
| SHA1 | <a href="https://www.virustotal.com/gui/file/-">-</a> |
| SHA256 | <a href="https://www.virustotal.com/gui/file/221dfbc74bbb255b0879360ccc71a74b756b2e0f16e9386b38a9ce9d4e2e34f9">221dfbc74bbb255b0879360ccc71a74b756b2e0f16e9386b38a9ce9d4e2e34f9</a> |
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



[*source*](https://github.com/magicsword-io/LOLDrivers/tree/main/yaml/bwrs.sys.yml)

*last_updated:* 2023-03-29








{{< /column >}}
{{< /block >}}
