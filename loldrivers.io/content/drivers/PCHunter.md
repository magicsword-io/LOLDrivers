+++

description = "https://learn.microsoft.com/en-us/windows/security/threat-protection/windows-defender-application-control/microsoft-recommended-driver-block-rules"
title = "PCHunter.sys"
weight = 10

+++


{{< block "grid-1" >}}
{{< column "mt-2 pt-1">}}


# PCHunter.sys 


{{< tip "warning" >}}
We were not able to verify the hash of this driver successfully, it has not been confirmed.
{{< /tip >}}


### Description

PCHunter.sys is a vulnerable driver and more information will be added as found.

- **Created**: 2023-01-09
- **Author**: Michael Haag
- **Acknowledgement**:  | [](https://twitter.com/)

### Commands

```
sc.exe create PCHunter.sys binPath=C:\windows\temp\PCHunter.sys type=kernel
sc.exe start PCHunter.sys
```

| Use Case | Privilages | Operating System | 
|:---- | ---- | ---- |
| Elevate privileges | kernel | Windows 10 |

### Resources
<br>
<li><a href=" https://learn.microsoft.com/en-us/windows/security/threat-protection/windows-defender-application-control/microsoft-recommended-driver-block-rules"> https://learn.microsoft.com/en-us/windows/security/threat-protection/windows-defender-application-control/microsoft-recommended-driver-block-rules</a></li>
<br>

### Known Vulnerable Samples

| Filename | PCHunter.sys |
|:---- | ---- | 
| MD5 | <a href="https://www.virustotal.com/gui/file/c2c1b8c00b99e913d992a870ed478a24">c2c1b8c00b99e913d992a870ed478a24</a> |
| SHA1 | <a href="https://www.virustotal.com/gui/file/a64354aac2d68b4fa74b5829a9d42d90d83b040c">a64354aac2d68b4fa74b5829a9d42d90d83b040c</a> |
| SHA256 | <a href="https://www.virustotal.com/gui/file/1b7fb154a7b7903a3c81f12f4b094f24a3c60a6a8cffca894c67c264ab7545fa">1b7fb154a7b7903a3c81f12f4b094f24a3c60a6a8cffca894c67c264ab7545fa</a> |
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



[*source*](https://github.com/magicsword-io/LOLDrivers/tree/main/yaml/pchunter.sys.yml)

*last_updated:* 2023-03-30








{{< /column >}}
{{< /block >}}
