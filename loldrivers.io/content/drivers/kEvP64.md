+++

description = "https://github.com/elastic/protections-artifacts/search?q=VulnDriver"
title = "kEvP64.sys"
weight = 10

+++


{{< block "grid-1" >}}
{{< column "mt-2 pt-1">}}


# kEvP64.sys ![:inline](/images/twitter_verified.png) 


### Description

kEvP64.sys is a vulnerable driver and more information will be added as found.

- **Created**: 2023-01-09
- **Author**: Michael Haag
- **Acknowledgement**:  | [](https://twitter.com/)

### Commands

```
sc.exe create kEvP64.sys binPath=C:\windows\temp\kEvP64.sys type=kernel
sc.exe start kEvP64.sys
```

| Use Case | Privilages | Operating System | 
|:---- | ---- | ---- |
| Elevate privileges | kernel | Windows 10 |

### Resources
<br>
<li><a href=" https://github.com/elastic/protections-artifacts/search?q=VulnDriver"> https://github.com/elastic/protections-artifacts/search?q=VulnDriver</a></li>
<br>

### Known Vulnerable Samples

| Filename | kEvP64.sys |
|:---- | ---- | 
| MD5 | <a href="https://www.virustotal.com/gui/file/20125794b807116617d43f02b616e092">20125794b807116617d43f02b616e092</a> |
| SHA1 | <a href="https://www.virustotal.com/gui/file/f3db629cfe37a73144d5258e64d9dd8b38084cf4">f3db629cfe37a73144d5258e64d9dd8b38084cf4</a> |
| SHA256 | <a href="https://www.virustotal.com/gui/file/1aaa9aef39cb3c0a854ecb4ca7d3b213458f302025e0ec5bfbdef973cca9111c">1aaa9aef39cb3c0a854ecb4ca7d3b213458f302025e0ec5bfbdef973cca9111c</a> |
| Publisher |  |
| Signature | 北京华林保软件技术有限公司, VeriSign Class 3 Code Signing 2010 CA, VeriSign   |
| Date |  |
| Company |  |
| Description |  |
| Product |  |
| ProductVersion |  |
| FileVersion |  |
| MachineType |  |
| OriginalFilename |  |



[*source*](https://github.com/magicsword-io/LOLDrivers/tree/main/yaml/kevp64.sys.yml)

*last_updated:* 2023-03-30








{{< /column >}}
{{< /block >}}
