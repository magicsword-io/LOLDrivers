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
| SHA256 | <a href="https://www.virustotal.com/gui/file/159e7c5a12157af92e0d14a0d3ea116f91c09e21a9831486e6dc592c93c10980">159e7c5a12157af92e0d14a0d3ea116f91c09e21a9831486e6dc592c93c10980</a> |
| Publisher |  |
| Signature |  |
| Date |  |
| Company |  |
| Description |  |
| Product |  |
| ProductVersion |  |
| FileVersion |  |
| MachineType |  |
| OriginalFilename |  |



[*source*](https://github.com/magicsword-io/LOLDrivers/tree/main/yaml/wcpu.sys.yml)

*last_updated:* 2023-03-21








{{< /column >}}
{{< /block >}}
