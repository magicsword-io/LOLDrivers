+++

description = "https://github.com/elastic/protections-artifacts/search?q=VulnDriver"
title = "RTCore64.sys"
weight = 10

+++


{{< block "grid-1" >}}
{{< column "mt-2 pt-1">}}


# RTCore64.sys ![:inline](/images/twitter_verified.png) 


### Description

The driver in Micro-Star MSI Afterburner 4.6.2.15658 (aka RTCore64.sys and RTCore32.sys) allows any authenticated user to read and write to arbitrary memory, I/O ports, and MSRs. This can be exploited for privilege escalation, code execution under high privileges, and information disclosure. These signed drivers can also be used to bypass the Microsoft driver-signing policy to deploy malicious code.

- **Created**: 2023-01-09
- **Author**: Michael Haag
- **Acknowledgement**:  | [](https://twitter.com/)

### Commands

```
sc.exe create RTCore64.sys binPath=C:\windows\temp\RTCore64.sys type=kernel
sc.exe start RTCore64.sys
```

| Use Case | Privilages | Operating System | 
|:---- | ---- | ---- |
| Elevate privileges | kernel | Windows 10 |

### Resources
<br>
<li><a href=" https://github.com/elastic/protections-artifacts/search?q=VulnDriver"> https://github.com/elastic/protections-artifacts/search?q=VulnDriver</a></li>
<li><a href="https://news.sophos.com/en-us/2022/10/04/blackbyte-ransomware-returns/">https://news.sophos.com/en-us/2022/10/04/blackbyte-ransomware-returns/</a></li>
<br>

### Known Vulnerable Samples

| Filename | RTCore64.sys |
|:---- | ---- | 
| MD5 | <a href="https://www.virustotal.com/gui/file/"></a> |
| SHA1 | <a href="https://www.virustotal.com/gui/file/"></a> |
| SHA256 | <a href="https://www.virustotal.com/gui/file/01aa278b07b58dc46c84bd0b1b5c8e9ee4e62ea0bf7a695862444af32e87f1fd">01aa278b07b58dc46c84bd0b1b5c8e9ee4e62ea0bf7a695862444af32e87f1fd</a> |
| Publisher | N/A |
| Signature | N/A |
| Date | N/A |
| Company | N/A |
| Description | N/A |
| Product | N/A |
| ProductVersion |  |
| FileVersion |  |
| MachineType |  |
| SOriginalFilename |  |
| Filename | RTCore64.sys |
|:---- | ---- | 
| MD5 | <a href="https://www.virustotal.com/gui/file/"></a> |
| SHA1 | <a href="https://www.virustotal.com/gui/file/"></a> |
| SHA256 | <a href="https://www.virustotal.com/gui/file/CDD2A4575A46BADA4837A6153A79C14D60EE3129830717EF09E0E3EFD9D00812">CDD2A4575A46BADA4837A6153A79C14D60EE3129830717EF09E0E3EFD9D00812</a> |
| Publisher | N/A |
| Signature | N/A |
| Date | N/A |
| Company | N/A |
| Description | N/A |
| Product | N/A |
| ProductVersion |  |
| FileVersion |  |
| MachineType |  |
| SOriginalFilename |  |



[*source*](https://github.com/magicsword-io/LOLDrivers/tree/main/yaml/rtcore64.sys.yml)

*last_updated:* 2023-03-10








{{< /column >}}
{{< /block >}}
