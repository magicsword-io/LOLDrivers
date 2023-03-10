+++

description = "https://github.com/namazso/physmem_drivers"
title = "AsrDrv10.sys"
weight = 10

+++


{{< block "grid-1" >}}
{{< column "mt-2 pt-1">}}


# AsrDrv10.sys ![:inline](/images/twitter_verified.png) 


### Description

AsrDrv10.sys is a vulnerable driver and more information will be added as found.

- **Created**: 2023-01-09
- **Author**: Michael Haag
- **Acknowledgement**:  | [](https://twitter.com/)

### Commands

```
sc.exe create AsrDrv10.sys binPath=C:\windows\temp\AsrDrv10.sys type=kernel
sc.exe start AsrDrv10.sys
```

| Use Case | Privilages | Operating System | 
|:---- | ---- | ---- |
| Elevate privileges | kernel | Windows 10 |

### Resources
<br>
<li><a href=" https://github.com/namazso/physmem_drivers"> https://github.com/namazso/physmem_drivers</a></li>
<br>

### Known Vulnerable Samples

| Filename | AsrDrv10.sys |
|:---- | ---- | 
| MD5 | <a href="https://www.virustotal.com/gui/file/"></a> |
| SHA1 | <a href="https://www.virustotal.com/gui/file/"></a> |
| SHA256 | <a href="https://www.virustotal.com/gui/file/ECE0A900EA089E730741499614C0917432246CEB5E11599EE3A1BB679E24FD2C">ECE0A900EA089E730741499614C0917432246CEB5E11599EE3A1BB679E24FD2C</a> |
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



[*source*](https://github.com/magicsword-io/LOLDrivers/tree/main/yaml/asrdrv10.sys.yml)

*last_updated:* 2023-03-10








{{< /column >}}
{{< /block >}}
