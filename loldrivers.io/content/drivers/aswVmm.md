+++

description = "https://github.com/elastic/protections-artifacts/search?q=VulnDriver"
title = "aswVmm.sys"
weight = 10

+++


{{< block "grid-1" >}}
{{< column "mt-2 pt-1">}}


# aswVmm.sys ![:inline](/images/twitter_verified.png) 


### Description

aswVmm.sys is a vulnerable driver and more information will be added as found.

- **Created**: 2023-01-09
- **Author**: Michael Haag
- **Acknowledgement**:  | [](https://twitter.com/)

### Commands

```
sc.exe create aswVmm.sys binPath=C:\windows\temp\aswVmm.sys type=kernel
sc.exe start aswVmm.sys
```

| Use Case | Privilages | Operating System | 
|:---- | ---- | ---- |
| Elevate privileges | kernel | Windows 10 |

### Resources
<br>
<li><a href=" https://github.com/elastic/protections-artifacts/search?q=VulnDriver"> https://github.com/elastic/protections-artifacts/search?q=VulnDriver</a></li>
<li><a href="https://github.com/tanduRE/AvastHV">https://github.com/tanduRE/AvastHV</a></li>
<br>

### Known Vulnerable Samples

| Filename | aswVmm.sys |
|:---- | ---- | 
| MD5 | <a href="https://www.virustotal.com/gui/file/a5f637d61719d37a5b4868c385e363c0">a5f637d61719d37a5b4868c385e363c0</a> |
| SHA1 | <a href="https://www.virustotal.com/gui/file/34c85afe6d84cd3deec02c0a72e5abfa7a2886c3">34c85afe6d84cd3deec02c0a72e5abfa7a2886c3</a> |
| SHA256 | <a href="https://www.virustotal.com/gui/file/36505921af5a09175395ebaea29c72b2a69a3a9204384a767a5be8a721f31b10">36505921af5a09175395ebaea29c72b2a69a3a9204384a767a5be8a721f31b10</a> |
| Signature | AVAST Software, VeriSign Class 3 Code Signing 2010 CA, VeriSign   |


[*source*](https://github.com/magicsword-io/LOLDrivers/tree/main/yaml/aswvmm.sys.yml)

*last_updated:* 2023-04-02








{{< /column >}}
{{< /block >}}
