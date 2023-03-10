+++

description = "https://github.com/namazso/physmem_drivers"
title = "SysInfo.sys"
weight = 10

+++


{{< block "grid-1" >}}
{{< column "mt-2 pt-1">}}


# SysInfo.sys ![:inline](/images/twitter_verified.png) 


### Description

SysInfo.sys is a vulnerable driver and more information will be added as found.

- **Created**: 2023-01-09
- **Author**: Michael Haag
- **Acknowledgement**:  | [](https://twitter.com/)

### Commands

```
sc.exe create SysInfo.sys binPath=C:\windows\temp\SysInfo.sys type=kernel
sc.exe start SysInfo.sys
```

| Use Case | Privilages | Operating System | 
|:---- | ---- | ---- |
| Elevate privileges | kernel | Windows 10 |

### Resources
<br>
<li><a href=" https://github.com/namazso/physmem_drivers"> https://github.com/namazso/physmem_drivers</a></li>
<br>

### Known Vulnerable Samples

| Filename | SysInfo.sys |
|:---- | ---- | 
| MD5 | <a href="https://www.virustotal.com/gui/file/"></a> |
| SHA1 | <a href="https://www.virustotal.com/gui/file/"></a> |
| SHA256 | <a href="https://www.virustotal.com/gui/file/7049F3C939EFE76A5556C2A2C04386DB51DAF61D56B679F4868BB0983C996EBB">7049F3C939EFE76A5556C2A2C04386DB51DAF61D56B679F4868BB0983C996EBB</a> |
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



[*source*](https://github.com/magicsword-io/LOLDrivers/tree/main/yaml/sysinfo.sys.yml)

*last_updated:* 2023-03-10








{{< /column >}}
{{< /block >}}
