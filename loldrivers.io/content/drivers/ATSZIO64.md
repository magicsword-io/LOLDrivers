+++

description = "https://github.com/elastic/protections-artifacts/search?q=VulnDriver"
title = "ATSZIO64.sys"
weight = 10

+++


{{< block "grid-1" >}}
{{< column "mt-2 pt-1">}}


# ATSZIO64.sys ![:inline](/images/twitter_verified.png) 


### Description

ATSZIO64.sys is a vulnerable driver and more information will be added as found.

- **Created**: 2023-01-09
- **Author**: Michael Haag
- **Acknowledgement**:  | [](https://twitter.com/)

### Commands

```
sc.exe create ATSZIO64.sys binPath=C:\windows\temp\ATSZIO64.sys type=kernel
sc.exe start ATSZIO64.sys
```

| Use Case | Privilages | Operating System | 
|:---- | ---- | ---- |
| Elevate privileges | kernel | Windows 10 |

### Resources
<br>
<li><a href=" https://github.com/elastic/protections-artifacts/search?q=VulnDriver"> https://github.com/elastic/protections-artifacts/search?q=VulnDriver</a></li>
<br>

### Known Vulnerable Samples

| Filename | ATSZIO64.sys |
|:---- | ---- | 
| MD5 | <a href="https://www.virustotal.com/gui/file/b12d1630fd50b2a21fd91e45d522ba3a">b12d1630fd50b2a21fd91e45d522ba3a</a> |
| SHA1 | <a href="https://www.virustotal.com/gui/file/490109fa6739f114651f4199196c5121d1c6bdf2">490109fa6739f114651f4199196c5121d1c6bdf2</a> |
| SHA256 | <a href="https://www.virustotal.com/gui/file/01e024cb14b34b6d525c642a710bfa14497ea20fd287c39ba404b10a8b143ece">01e024cb14b34b6d525c642a710bfa14497ea20fd287c39ba404b10a8b143ece</a> |
| Signature | ASUSTeK Computer Inc., VeriSign Class 3 Code Signing 2010 CA, VeriSign   |


[*source*](https://github.com/magicsword-io/LOLDrivers/tree/main/yaml/atszio64.sys.yml)

*last_updated:* 2023-04-03








{{< /column >}}
{{< /block >}}
