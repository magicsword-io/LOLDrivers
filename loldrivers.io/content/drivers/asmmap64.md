+++

description = ""
title = "asmmap64.sys"
weight = 10

+++


{{< block "grid-1" >}}
{{< column "mt-2 pt-1">}}


# asmmap64.sys ![:inline](/images/twitter_verified.png) 


### Description

asmmap64.sys is a vulnerable driver and more information will be added as found.

- **Created**: 2023-01-09
- **Author**: Michael Haag
- **Acknowledgement**:  | [](https://twitter.com/)

### Commands

```
sc.exe create asmmap64.sys binPath=C:\windows\temp\asmmap64.sys type=kernel &amp;&amp; sc.exe start asmmap64.sys
```

| Use Case | Privileges | Operating System | 
|:---- | ---- | ---- |
| Elevate privileges | kernel | Windows 10 |

### Resources
<br>
<li><a href=" https://github.com/namazso/physmem_drivers"> https://github.com/namazso/physmem_drivers</a></li>
<li><a href="https://github.com/namazso/physmem_drivers">https://github.com/namazso/physmem_drivers</a></li>
<br>

### Known Vulnerable Samples

| Filename | asmmap64.sys |
|:---- | ---- | 
| MD5 | <a href="https://www.virustotal.com/gui/file/4c016fd76ed5c05e84ca8cab77993961">4c016fd76ed5c05e84ca8cab77993961</a> |
| SHA1 | <a href="https://www.virustotal.com/gui/file/00a442a4305c62cefa8105c0b4c4a9a5f4d1e93b">00a442a4305c62cefa8105c0b4c4a9a5f4d1e93b</a> |
| SHA256 | <a href="https://www.virustotal.com/gui/file/025e7be9fcefd6a83f4471bba0c11f1c11bd5047047d26626da24ee9a419cdc4">025e7be9fcefd6a83f4471bba0c11f1c11bd5047047d26626da24ee9a419cdc4</a> |
| Publisher | ASUSTeK Computer Inc. || Signature | ASUSTeK Computer Inc., VeriSign Class 3 Code Signing 2004 CA, VeriSign Class 3 Public Primary CA   || Company | ASUS || Description | Memory mapping Driver || Product | ATK Generic Function Service || OriginalFilename | asmmap.sys |


[*source*](https://github.com/magicsword-io/LOLDrivers/tree/main/yaml/asmmap64.yaml)

*last_updated:* 2023-04-15








{{< /column >}}
{{< /block >}}
