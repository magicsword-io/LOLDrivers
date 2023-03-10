+++

description = "https://github.com/namazso/physmem_drivers"
title = "msrhook.sys"
weight = 10

+++


{{< block "grid-1" >}}
{{< column "mt-2 pt-1">}}


# msrhook.sys ![:inline](/images/twitter_verified.png) 


### Description

msrhook.sys is a vulnerable driver and more information will be added as found.

- **Created**: 2023-01-09
- **Author**: Michael Haag
- **Acknowledgement**:  | [](https://twitter.com/)

### Commands

```
sc.exe create msrhook.sys binPath=C:\windows\temp\msrhook.sys type=kernel
sc.exe start msrhook.sys
```

| Use Case | Privilages | Operating System | 
|:---- | ---- | ---- |
| Elevate privileges | kernel | Windows 10 |

### Resources
<br>
<li><a href=" https://github.com/namazso/physmem_drivers"> https://github.com/namazso/physmem_drivers</a></li>
<br>

### Known Vulnerable Samples

| Filename | msrhook.sys |
|:---- | ---- | 
| MD5 | <a href="https://www.virustotal.com/gui/file/"></a> |
| SHA1 | <a href="https://www.virustotal.com/gui/file/"></a> |
| SHA256 | <a href="https://www.virustotal.com/gui/file/6DE84CAA2CA18673E01B91AF58220C60AECD5CCCF269725EC3C7F226B2167492">6DE84CAA2CA18673E01B91AF58220C60AECD5CCCF269725EC3C7F226B2167492</a> |
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



[*source*](https://github.com/magicsword-io/LOLDrivers/tree/main/yaml/msrhook.sys.yml)

*last_updated:* 2023-03-10








{{< /column >}}
{{< /block >}}
