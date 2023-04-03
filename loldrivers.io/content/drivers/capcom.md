+++

description = "https://github.com/elastic/protections-artifacts/search?q=VulnDriver"
title = "capcom.sys"
weight = 10

+++


{{< block "grid-1" >}}
{{< column "mt-2 pt-1">}}


# capcom.sys ![:inline](/images/twitter_verified.png) 


### Description

capcom.sys is a vulnerable driver and more information will be added as found.

- **Created**: 2023-01-09
- **Author**: Michael Haag
- **Acknowledgement**:  | [](https://twitter.com/)

### Commands

```
sc.exe create capcom.sys binPath=C:\windows\temp\capcom.sys type=kernel
sc.exe start capcom.sys
```

| Use Case | Privilages | Operating System | 
|:---- | ---- | ---- |
| Elevate privileges | kernel | Windows 10 |

### Resources
<br>
<li><a href=" https://github.com/elastic/protections-artifacts/search?q=VulnDriver"> https://github.com/elastic/protections-artifacts/search?q=VulnDriver</a></li>
<br>

### Known Vulnerable Samples

| Filename | capcom.sys |
|:---- | ---- | 
| MD5 | <a href="https://www.virustotal.com/gui/file/73c98438ac64a68e88b7b0afd11ba140">73c98438ac64a68e88b7b0afd11ba140</a> |
| SHA1 | <a href="https://www.virustotal.com/gui/file/c1d5cf8c43e7679b782630e93f5e6420ca1749a7">c1d5cf8c43e7679b782630e93f5e6420ca1749a7</a> |
| SHA256 | <a href="https://www.virustotal.com/gui/file/da6ca1fb539f825ca0f012ed6976baf57ef9c70143b7a1e88b4650bf7a925e24">da6ca1fb539f825ca0f012ed6976baf57ef9c70143b7a1e88b4650bf7a925e24</a> |
| Signature | CAPCOM Co.,Ltd., Symantec Class 3 SHA256 Code Signing CA, VeriSign   |


[*source*](https://github.com/magicsword-io/LOLDrivers/tree/main/yaml/capcom.sys.yml)

*last_updated:* 2023-04-02








{{< /column >}}
{{< /block >}}
