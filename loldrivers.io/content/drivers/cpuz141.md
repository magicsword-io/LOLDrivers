+++

description = ""
title = "cpuz141.sys"
weight = 10

+++


{{< block "grid-1" >}}
{{< column "mt-2 pt-1">}}


# cpuz141.sys ![:inline](/images/twitter_verified.png) 


### Description

cpuz141.sys is a vulnerable driver and more information will be added as found.

- **Created**: 2023-01-09
- **Author**: Michael Haag
- **Acknowledgement**:  | [](https://twitter.com/)

### Commands

```
sc.exe create cpuz141.sys binPath=C:\windows\temp\cpuz141.sys type=kernel
sc.exe start cpuz141.sys
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

| Filename | cpuz141.sys |
|:---- | ---- | 
| MD5 | <a href="https://www.virustotal.com/gui/file/db72def618cbc3c5f9aa82f091b54250">db72def618cbc3c5f9aa82f091b54250</a> |
| SHA1 | <a href="https://www.virustotal.com/gui/file/f5696fb352a3fbd14fb1a89ad21a71776027f9ab">f5696fb352a3fbd14fb1a89ad21a71776027f9ab</a> |
| SHA256 | <a href="https://www.virustotal.com/gui/file/ded2927f9a4e64eefd09d0caba78e94f309e3a6292841ae81d5528cab109f95d">ded2927f9a4e64eefd09d0caba78e94f309e3a6292841ae81d5528cab109f95d</a> |
| Publisher | CPUID || Signature | CPUID, VeriSign Class 3 Code Signing 2010 CA, VeriSign   || Description | CPUID Driver |


[*source*](https://github.com/magicsword-io/LOLDrivers/tree/main/yaml/cpuz141.yaml)

*last_updated:* 2023-04-10








{{< /column >}}
{{< /block >}}
