+++

description = "https://github.com/namazso/physmem_drivers"
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

| Use Case | Privilages | Operating System | 
|:---- | ---- | ---- |
| Elevate privileges | kernel | Windows 10 |

### Resources
<br>
<li><a href=" https://github.com/namazso/physmem_drivers"> https://github.com/namazso/physmem_drivers</a></li>
<br>

### Known Vulnerable Samples

| Filename | cpuz141.sys |
|:---- | ---- | 
| MD5 | <a href="https://www.virustotal.com/gui/file/"></a> |
| SHA1 | <a href="https://www.virustotal.com/gui/file/"></a> |
| SHA256 | <a href="https://www.virustotal.com/gui/file/DED2927F9A4E64EEFD09D0CABA78E94F309E3A6292841AE81D5528CAB109F95D">DED2927F9A4E64EEFD09D0CABA78E94F309E3A6292841AE81D5528CAB109F95D</a> |
| Publisher | CPUID |
| Signature |  |
| Date |  |
| Company |  |
| Description | CPUID Driver |
| Product |  |
| ProductVersion |  |
| FileVersion |  |
| MachineType |  |
| SOriginalFilename |  |



[*source*](https://github.com/magicsword-io/LOLDrivers/tree/main/yaml/cpuz141.sys.yml)

*last_updated:* 2023-03-10








{{< /column >}}
{{< /block >}}
