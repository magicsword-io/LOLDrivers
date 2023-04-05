+++

description = ""
title = "WCPU.sys"
weight = 10

+++


{{< block "grid-1" >}}
{{< column "mt-2 pt-1">}}


# WCPU.sys ![:inline](/images/twitter_verified.png) 


### Description

WCPU.sys is a vulnerable driver and more information will be added as found.

- **Created**: 2023-01-09
- **Author**: Michael Haag
- **Acknowledgement**:  | [](https://twitter.com/)

### Commands

```
sc.exe create WCPU.sys binPath=C:\windows\temp\WCPU.sys type=kernel
sc.exe start WCPU.sys
```

| Use Case | Privilages | Operating System | 
|:---- | ---- | ---- |
| Elevate privileges | kernel | Windows 10 |

### Resources
<br>
<li><a href=" https://github.com/namazso/physmem_drivers"> https://github.com/namazso/physmem_drivers</a></li>
<li><a href="https://github.com/namazso/physmem_drivers">https://github.com/namazso/physmem_drivers</a></li>
<br>

### Known Vulnerable Samples

| Filename | WCPU.sys |
|:---- | ---- | 
| MD5 | <a href="https://www.virustotal.com/gui/file/c1d063c9422a19944cdaa6714623f2ec">c1d063c9422a19944cdaa6714623f2ec</a> |
| SHA1 | <a href="https://www.virustotal.com/gui/file/f36a47edfacd85e0c6d4d22133dd386aee4eec15">f36a47edfacd85e0c6d4d22133dd386aee4eec15</a> |
| SHA256 | <a href="https://www.virustotal.com/gui/file/159e7c5a12157af92e0d14a0d3ea116f91c09e21a9831486e6dc592c93c10980">159e7c5a12157af92e0d14a0d3ea116f91c09e21a9831486e6dc592c93c10980</a> |
| Signature | ASUSTeK Computer Inc., VeriSign Class 3 Code Signing 2004 CA, VeriSign Class 3 Public Primary CA   |


[*source*](https://github.com/magicsword-io/LOLDrivers/tree/main/yaml/wcpu.sys.yml)

*last_updated:* 2023-04-05








{{< /column >}}
{{< /block >}}
