+++

description = "https://github.com/namazso/physmem_drivers"
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
<br>

### Known Vulnerable Samples

| Filename | WCPU.sys |
|:---- | ---- | 
| MD5 | <a href="https://www.virustotal.com/gui/file/"></a> |
| SHA1 | <a href="https://www.virustotal.com/gui/file/"></a> |
| SHA256 | <a href="https://www.virustotal.com/gui/file/159E7C5A12157AF92E0D14A0D3EA116F91C09E21A9831486E6DC592C93C10980">159E7C5A12157AF92E0D14A0D3EA116F91C09E21A9831486E6DC592C93C10980</a> |
| Publisher |  |
| Signature |  |
| Date |  |
| Company |  |
| Description |  |
| Product |  |
| ProductVersion |  |
| FileVersion |  |
| MachineType |  |
| SOriginalFilename |  |



[*source*](https://github.com/magicsword-io/LOLDrivers/tree/main/yaml/wcpu.sys.yml)

*last_updated:* 2023-03-10








{{< /column >}}
{{< /block >}}
