+++

description = "https://github.com/namazso/physmem_drivers"
title = "AsrDrv101.sys"
weight = 10

+++


{{< block "grid-1" >}}
{{< column "mt-2 pt-1">}}


# AsrDrv101.sys ![:inline](/images/twitter_verified.png) 


### Description

AsrDrv101.sys is a vulnerable driver and more information will be added as found.

- **Created**: 2023-01-09
- **Author**: Michael Haag
- **Acknowledgement**:  | [](https://twitter.com/)

### Commands

```
sc.exe create AsrDrv101.sys binPath=C:\windows\temp\AsrDrv101.sys type=kernel
sc.exe start AsrDrv101.sys
```

| Use Case | Privilages | Operating System | 
|:---- | ---- | ---- |
| Elevate privileges | kernel | Windows 10 |

### Resources
<br>
<li><a href=" https://github.com/namazso/physmem_drivers"> https://github.com/namazso/physmem_drivers</a></li>
<br>

### Known Vulnerable Samples

| Filename | AsrDrv101.sys |
|:---- | ---- | 
| MD5 | <a href="https://www.virustotal.com/gui/file/"></a> |
| SHA1 | <a href="https://www.virustotal.com/gui/file/"></a> |
| SHA256 | <a href="https://www.virustotal.com/gui/file/f40435488389b4fb3b945ca21a8325a51e1b5f80f045ab019748d0ec66056a8b">f40435488389b4fb3b945ca21a8325a51e1b5f80f045ab019748d0ec66056a8b</a> |
| Publisher | ASROCK Incorporation |
| Signature |  |
| Date |  |
| Company |  |
| Description | ASRock IO Driver |
| Product |  |
| ProductVersion |  |
| FileVersion |  |
| MachineType |  |
| OriginalFilename |  |



[*source*](https://github.com/magicsword-io/LOLDrivers/tree/main/yaml/asrdrv101.sys.yml)

*last_updated:* 2023-03-21








{{< /column >}}
{{< /block >}}
