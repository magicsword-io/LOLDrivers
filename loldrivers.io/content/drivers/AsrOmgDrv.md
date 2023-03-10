+++

description = "https://github.com/namazso/physmem_drivers"
title = "AsrOmgDrv.sys"
weight = 10

+++


{{< block "grid-1" >}}
{{< column "mt-2 pt-1">}}


# AsrOmgDrv.sys ![:inline](/images/twitter_verified.png) 


### Description

AsrOmgDrv.sys is a vulnerable driver and more information will be added as found.

- **Created**: 2023-01-09
- **Author**: Michael Haag
- **Acknowledgement**:  | [](https://twitter.com/)

### Commands

```
sc.exe create AsrOmgDrv.sys binPath=C:\windows\temp\AsrOmgDrv.sys type=kernel
sc.exe start AsrOmgDrv.sys
```

| Use Case | Privilages | Operating System | 
|:---- | ---- | ---- |
| Elevate privileges | kernel | Windows 10 |

### Resources
<br>
<li><a href=" https://github.com/namazso/physmem_drivers"> https://github.com/namazso/physmem_drivers</a></li>
<br>

### Known Vulnerable Samples

| Filename | AsrOmgDrv.sys |
|:---- | ---- | 
| MD5 | <a href="https://www.virustotal.com/gui/file/"></a> |
| SHA1 | <a href="https://www.virustotal.com/gui/file/"></a> |
| SHA256 | <a href="https://www.virustotal.com/gui/file/950A4C0C772021CEE26011A92194F0E58D61588F77F2873AA0599DFF52A160C9">950A4C0C772021CEE26011A92194F0E58D61588F77F2873AA0599DFF52A160C9</a> |
| Publisher | ASROCK Incorporation |
| Signature |  |
| Date |  |
| Company |  |
| Description | ASRock IO Driver |
| Product |  |
| ProductVersion |  |
| FileVersion |  |
| MachineType |  |
| SOriginalFilename |  |



[*source*](https://github.com/magicsword-io/LOLDrivers/tree/main/yaml/asromgdrv.sys.yml)

*last_updated:* 2023-03-10








{{< /column >}}
{{< /block >}}
