+++

description = "https://github.com/namazso/physmem_drivers"
title = "Mhyprot2.sys"
weight = 10

+++


{{< block "grid-1" >}}
{{< column "mt-2 pt-1">}}


# Mhyprot2.sys ![:inline](/images/twitter_verified.png) 


### Description

Mhyprot2.sys is a vulnerable driver and more information will be added as found.

- **Created**: 2023-01-09
- **Author**: Michael Haag
- **Acknowledgement**:  | [](https://twitter.com/)

### Commands

```
sc.exe create Mhyprot2.sys binPath=C:\windows\temp\Mhyprot2.sys type=kernel
sc.exe start Mhyprot2.sys
```

| Use Case | Privilages | Operating System | 
|:---- | ---- | ---- |
| Elevate privileges | kernel | Windows 10 |

### Resources
<br>
<li><a href=" https://github.com/namazso/physmem_drivers"> https://github.com/namazso/physmem_drivers</a></li>
<br>

### Known Vulnerable Samples

| Filename | Mhyprot2.sys |
|:---- | ---- | 
| MD5 | <a href="https://www.virustotal.com/gui/file/"></a> |
| SHA1 | <a href="https://www.virustotal.com/gui/file/"></a> |
| SHA256 | <a href="https://www.virustotal.com/gui/file/509628B6D16D2428031311D7BD2ADD8D5F5160E9ECC0CD909F1E82BBBB3234D6">509628B6D16D2428031311D7BD2ADD8D5F5160E9ECC0CD909F1E82BBBB3234D6</a> |
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



[*source*](https://github.com/magicsword-io/LOLDrivers/tree/main/yaml/mhyprot2.sys.yml)

*last_updated:* 2023-03-10








{{< /column >}}
{{< /block >}}
