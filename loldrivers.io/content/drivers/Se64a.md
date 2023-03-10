+++

description = "https://github.com/namazso/physmem_drivers"
title = "Se64a.sys"
weight = 10

+++


{{< block "grid-1" >}}
{{< column "mt-2 pt-1">}}


# Se64a.sys ![:inline](/images/twitter_verified.png) 


### Description

Se64a.sys is a vulnerable driver and more information will be added as found.

- **Created**: 2023-01-09
- **Author**: Michael Haag
- **Acknowledgement**:  | [](https://twitter.com/)

### Commands

```
sc.exe create Se64a.sys binPath=C:\windows\temp\Se64a.sys type=kernel
sc.exe start Se64a.sys
```

| Use Case | Privilages | Operating System | 
|:---- | ---- | ---- |
| Elevate privileges | kernel | Windows 10 |

### Resources
<br>
<li><a href=" https://github.com/namazso/physmem_drivers"> https://github.com/namazso/physmem_drivers</a></li>
<br>

### Known Vulnerable Samples

| Filename | Se64a.sys |
|:---- | ---- | 
| MD5 | <a href="https://www.virustotal.com/gui/file/"></a> |
| SHA1 | <a href="https://www.virustotal.com/gui/file/"></a> |
| SHA256 | <a href="https://www.virustotal.com/gui/file/6CB51AE871FBD5D07C5AAD6FF8EEA43D34063089528603CA9CEB8B4F52F68DDC">6CB51AE871FBD5D07C5AAD6FF8EEA43D34063089528603CA9CEB8B4F52F68DDC</a> |
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



[*source*](https://github.com/magicsword-io/LOLDrivers/tree/main/yaml/se64a.sys.yml)

*last_updated:* 2023-03-10








{{< /column >}}
{{< /block >}}
