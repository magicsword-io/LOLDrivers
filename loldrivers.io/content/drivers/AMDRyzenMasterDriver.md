+++

description = "https://github.com/elastic/protections-artifacts/search?q=VulnDriver"
title = "AMDRyzenMasterDriver.sys"
weight = 10

+++


{{< block "grid-1" >}}
{{< column "mt-2 pt-1">}}


# AMDRyzenMasterDriver.sys ![:inline](/images/twitter_verified.png) 


### Description

AMDRyzenMasterDriver.sys is a vulnerable driver and more information will be added as found.

- **Created**: 2023-01-09
- **Author**: Michael Haag
- **Acknowledgement**:  | [](https://twitter.com/)

### Commands

```
sc.exe create AMDRyzenMasterDriver.sys binPath=C:\windows\temp\AMDRyzenMasterDriver.sys type=kernel
sc.exe start AMDRyzenMasterDriver.sys
```

| Use Case | Privilages | Operating System | 
|:---- | ---- | ---- |
| Elevate privileges | kernel | Windows 10 |

### Resources
<br>
<li><a href=" https://github.com/elastic/protections-artifacts/search?q=VulnDriver"> https://github.com/elastic/protections-artifacts/search?q=VulnDriver</a></li>
<br>

### Known Vulnerable Samples

| Filename | AMDRyzenMasterDriver.sys |
|:---- | ---- | 
| MD5 | <a href="https://www.virustotal.com/gui/file/13ee349c15ee5d6cf640b3d0111ffc0e">13ee349c15ee5d6cf640b3d0111ffc0e</a> |
| SHA1 | <a href="https://www.virustotal.com/gui/file/4f7a8e26a97980544be634b26899afbefb0a833c">4f7a8e26a97980544be634b26899afbefb0a833c</a> |
| SHA256 | <a href="https://www.virustotal.com/gui/file/a13054f349b7baa8c8a3fcbd31789807a493cc52224bbff5e412eb2bd52a6433">a13054f349b7baa8c8a3fcbd31789807a493cc52224bbff5e412eb2bd52a6433</a> |
| Publisher |  |
| Signature | Advanced Micro Devices INC., Symantec Class 3 SHA256 Code Signing CA, VeriSign   |
| Date |  |
| Company |  |
| Description |  |
| Product |  |
| ProductVersion |  |
| FileVersion |  |
| MachineType |  |
| OriginalFilename |  |



[*source*](https://github.com/magicsword-io/LOLDrivers/tree/main/yaml/amdryzenmasterdriver.sys.yml)

*last_updated:* 2023-04-02








{{< /column >}}
{{< /block >}}
