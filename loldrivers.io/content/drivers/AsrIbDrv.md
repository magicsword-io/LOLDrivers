+++

description = "https://github.com/namazso/physmem_drivers"
title = "AsrIbDrv.sys"
weight = 10

+++


{{< block "grid-1" >}}
{{< column "mt-2 pt-1">}}


# AsrIbDrv.sys ![:inline](/images/twitter_verified.png) 


### Description

AsrIbDrv.sys is a vulnerable driver and more information will be added as found.

- **Created**: 2023-01-09
- **Author**: Michael Haag
- **Acknowledgement**:  | [](https://twitter.com/)

### Commands

```
sc.exe create AsrIbDrv.sys binPath=C:\windows\temp\AsrIbDrv.sys type=kernel
sc.exe start AsrIbDrv.sys
```

| Use Case | Privilages | Operating System | 
|:---- | ---- | ---- |
| Elevate privileges | kernel | Windows 10 |

### Resources
<br>
<li><a href=" https://github.com/namazso/physmem_drivers"> https://github.com/namazso/physmem_drivers</a></li>
<br>

### Known Vulnerable Samples

| Filename | AsrIbDrv.sys |
|:---- | ---- | 
| MD5 | <a href="https://www.virustotal.com/gui/file/"></a> |
| SHA1 | <a href="https://www.virustotal.com/gui/file/"></a> |
| SHA256 | <a href="https://www.virustotal.com/gui/file/2A652DE6B680D5AD92376AD323021850DAB2C653ABF06EDF26120F7714B8E08A">2A652DE6B680D5AD92376AD323021850DAB2C653ABF06EDF26120F7714B8E08A</a> |
| Publisher | ASROCK Incorporation |
| Signature |  |
| Date |  |
| Company |  |
| Description | RW-Everything Read &amp; Write Driver |
| Product |  |
| ProductVersion |  |
| FileVersion |  |
| MachineType |  |
| SOriginalFilename |  |



[*source*](https://github.com/magicsword-io/LOLDrivers/tree/main/yaml/asribdrv.sys.yml)

*last_updated:* 2023-03-10








{{< /column >}}
{{< /block >}}
