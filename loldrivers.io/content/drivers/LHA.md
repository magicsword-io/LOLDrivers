+++

description = ""
title = "LHA.sys"
weight = 10

+++


{{< block "grid-1" >}}
{{< column "mt-2 pt-1">}}


# LHA.sys ![:inline](/images/twitter_verified.png) 


### Description

LHA.sys is a vulnerable driver and more information will be added as found.

- **Created**: 2023-01-09
- **Author**: Michael Haag
- **Acknowledgement**:  | [](https://twitter.com/)

### Commands

```
sc.exe create LHA.sys binPath=C:\windows\temp\LHA.sys type=kernel
sc.exe start LHA.sys
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

| Filename | LHA.sys |
|:---- | ---- | 
| MD5 | <a href="https://www.virustotal.com/gui/file/748cf64b95ca83abc35762ad2c25458f">748cf64b95ca83abc35762ad2c25458f</a> |
| SHA1 | <a href="https://www.virustotal.com/gui/file/fcd615df88645d1f57ff5702bd6758b77efea6d0">fcd615df88645d1f57ff5702bd6758b77efea6d0</a> |
| SHA256 | <a href="https://www.virustotal.com/gui/file/e75714f8e0ff45605f6fc7689a1a89c7dcd34aab66c6131c63fefaca584539cf">e75714f8e0ff45605f6fc7689a1a89c7dcd34aab66c6131c63fefaca584539cf</a> |
| Signature | Microsoft Windows Hardware Compatibility Publisher, Microsoft Windows Third Party Component CA 2014, Microsoft Root Certificate Authority 2010   |


[*source*](https://github.com/magicsword-io/LOLDrivers/tree/main/yaml/lha.yaml)

*last_updated:* 2023-04-06








{{< /column >}}
{{< /block >}}
