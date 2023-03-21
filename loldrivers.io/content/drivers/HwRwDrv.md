+++

description = "https://github.com/namazso/physmem_drivers"
title = "HwRwDrv.sys"
weight = 10

+++


{{< block "grid-1" >}}
{{< column "mt-2 pt-1">}}


# HwRwDrv.sys ![:inline](/images/twitter_verified.png) 


### Description

HwRwDrv.sys is a vulnerable driver and more information will be added as found.

- **Created**: 2023-01-09
- **Author**: Michael Haag
- **Acknowledgement**:  | [](https://twitter.com/)

### Commands

```
sc.exe create HwRwDrv.sys binPath=C:\windows\temp\HwRwDrv.sys type=kernel
sc.exe start HwRwDrv.sys
```

| Use Case | Privilages | Operating System | 
|:---- | ---- | ---- |
| Elevate privileges | kernel | Windows 10 |

### Resources
<br>
<li><a href=" https://github.com/namazso/physmem_drivers"> https://github.com/namazso/physmem_drivers</a></li>
<br>

### Known Vulnerable Samples

| Filename | HwRwDrv.sys |
|:---- | ---- | 
| MD5 | <a href="https://www.virustotal.com/gui/file/"></a> |
| SHA1 | <a href="https://www.virustotal.com/gui/file/"></a> |
| SHA256 | <a href="https://www.virustotal.com/gui/file/21ccdd306b5183c00ecfd0475b3152e7d94b921e858e59b68a03e925d1715f21">21ccdd306b5183c00ecfd0475b3152e7d94b921e858e59b68a03e925d1715f21</a> |
| Publisher | Shuttle Inc. |
| Signature |  |
| Date |  |
| Company |  |
| Description | Hardware read &amp; write driver |
| Product |  |
| ProductVersion |  |
| FileVersion |  |
| MachineType |  |
| OriginalFilename |  |



[*source*](https://github.com/magicsword-io/LOLDrivers/tree/main/yaml/hwrwdrv.sys.yml)

*last_updated:* 2023-03-21








{{< /column >}}
{{< /block >}}
