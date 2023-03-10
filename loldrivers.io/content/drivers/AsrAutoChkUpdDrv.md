+++

description = "https://github.com/namazso/physmem_drivers"
title = "AsrAutoChkUpdDrv.sys"
weight = 10

+++


{{< block "grid-1" >}}
{{< column "mt-2 pt-1">}}


# AsrAutoChkUpdDrv.sys ![:inline](/images/twitter_verified.png) 


### Description

AsrAutoChkUpdDrv.sys is a vulnerable driver and more information will be added as found.

- **Created**: 2023-01-09
- **Author**: Michael Haag
- **Acknowledgement**:  | [](https://twitter.com/)

### Commands

```
sc.exe create AsrAutoChkUpdDrv.sys binPath=C:\windows\temp\AsrAutoChkUpdDrv.sys type=kernel
sc.exe start AsrAutoChkUpdDrv.sys
```

| Use Case | Privilages | Operating System | 
|:---- | ---- | ---- |
| Elevate privileges | kernel | Windows 10 |

### Resources
<br>
<li><a href=" https://github.com/namazso/physmem_drivers"> https://github.com/namazso/physmem_drivers</a></li>
<br>

### Known Vulnerable Samples

| Filename | AsrAutoChkUpdDrv.sys |
|:---- | ---- | 
| MD5 | <a href="https://www.virustotal.com/gui/file/"></a> |
| SHA1 | <a href="https://www.virustotal.com/gui/file/"></a> |
| SHA256 | <a href="https://www.virustotal.com/gui/file/2AA1B08F47FBB1E2BD2E4A492F5D616968E703E1359A921F62B38B8E4662F0C4">2AA1B08F47FBB1E2BD2E4A492F5D616968E703E1359A921F62B38B8E4662F0C4</a> |
| Publisher | ASROCK Incorporation |
| Signature |  |
| Date |  |
| Company |  |
| Description | AsrAutoChkUpdDrv Driver |
| Product |  |
| ProductVersion |  |
| FileVersion |  |
| MachineType |  |
| SOriginalFilename |  |



[*source*](https://github.com/magicsword-io/LOLDrivers/tree/main/yaml/asrautochkupddrv.sys.yml)

*last_updated:* 2023-03-10








{{< /column >}}
{{< /block >}}
