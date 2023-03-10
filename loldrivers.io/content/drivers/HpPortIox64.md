+++

description = "https://github.com/elastic/protections-artifacts/search?q=VulnDriver"
title = "HpPortIox64.sys"
weight = 10

+++


{{< block "grid-1" >}}
{{< column "mt-2 pt-1">}}


# HpPortIox64.sys ![:inline](/images/twitter_verified.png) 


### Description

HpPortIox64.sys is a vulnerable driver and more information will be added as found.

- **Created**: 2023-01-09
- **Author**: Michael Haag
- **Acknowledgement**:  | [](https://twitter.com/)

### Commands

```
sc.exe create HpPortIox64.sys binPath=C:\windows\temp\HpPortIox64.sys type=kernel
sc.exe start HpPortIox64.sys
```

| Use Case | Privilages | Operating System | 
|:---- | ---- | ---- |
| Elevate privileges | kernel | Windows 10 |

### Resources
<br>
<li><a href=" https://github.com/elastic/protections-artifacts/search?q=VulnDriver"> https://github.com/elastic/protections-artifacts/search?q=VulnDriver</a></li>
<br>

### Known Vulnerable Samples

| Filename | HpPortIox64.sys |
|:---- | ---- | 
| MD5 | <a href="https://www.virustotal.com/gui/file/"></a> |
| SHA1 | <a href="https://www.virustotal.com/gui/file/"></a> |
| SHA256 | <a href="https://www.virustotal.com/gui/file/c5050a2017490fff7aa53c73755982b339ddb0fd7cef2cde32c81bc9834331c5">c5050a2017490fff7aa53c73755982b339ddb0fd7cef2cde32c81bc9834331c5</a> |
| Publisher |  |
| Signature |  |
| Date |  |
| Company |  |
| Description |  |
| Product |  |
| ProductVersion |  |
| FileVersion |  |
| MachineType |  |
| SOriginalFilename |  |



[*source*](https://github.com/magicsword-io/LOLDrivers/tree/main/yaml/hpportiox64.sys.yml)

*last_updated:* 2023-03-10








{{< /column >}}
{{< /block >}}
