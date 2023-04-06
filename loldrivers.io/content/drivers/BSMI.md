+++

description = ""
title = "BSMI.sys"
weight = 10

+++


{{< block "grid-1" >}}
{{< column "mt-2 pt-1">}}


# BSMI.sys ![:inline](/images/twitter_verified.png) 


### Description

BSMI.sys is a vulnerable driver and more information will be added as found.

- **Created**: 2023-01-09
- **Author**: Michael Haag
- **Acknowledgement**:  | [](https://twitter.com/)

### Commands

```
sc.exe create BSMI.sys binPath=C:\windows\temp\BSMI.sys type=kernel
sc.exe start BSMI.sys
```

| Use Case | Privileges | Operating System | 
|:---- | ---- | ---- |
| Elevate privileges | kernel | Windows 10 |

### Resources
<br>
<li><a href=" https://github.com/elastic/protections-artifacts/search?q=VulnDriver"> https://github.com/elastic/protections-artifacts/search?q=VulnDriver</a></li>
<li><a href="https://github.com/elastic/protections-artifacts/search?q=VulnDriver">https://github.com/elastic/protections-artifacts/search?q=VulnDriver</a></li>
<br>

### Known Vulnerable Samples

| Filename | BSMI.sys |
|:---- | ---- | 
| MD5 | <a href="https://www.virustotal.com/gui/file/fac8eb49e2fd541b81fcbdeb98a199cb">fac8eb49e2fd541b81fcbdeb98a199cb</a> |
| SHA1 | <a href="https://www.virustotal.com/gui/file/9a35ae9a1f95ce4be64adc604c80079173e4a676">9a35ae9a1f95ce4be64adc604c80079173e4a676</a> |
| SHA256 | <a href="https://www.virustotal.com/gui/file/59626cac380d8fe0b80a6d4c4406d62ba0683a2f0f68d50ad506ca1b1cf25347">59626cac380d8fe0b80a6d4c4406d62ba0683a2f0f68d50ad506ca1b1cf25347</a> |
| Signature | BIOSTAR MICROTECH INT&#39;L CORP, VeriSign Class 3 Code Signing 2009-2 CA, VeriSign Class 3 Public Primary CA   |


[*source*](https://github.com/magicsword-io/LOLDrivers/tree/main/yaml/bsmi.yaml)

*last_updated:* 2023-04-06








{{< /column >}}
{{< /block >}}
