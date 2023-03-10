+++

description = "https://github.com/namazso/physmem_drivers"
title = "ALSysIO64.sys"
weight = 10

+++


{{< block "grid-1" >}}
{{< column "mt-2 pt-1">}}


# ALSysIO64.sys ![:inline](/images/twitter_verified.png) 


### Description

ALSysIO64.sys is a vulnerable driver and more information will be added as found.

- **Created**: 2023-01-09
- **Author**: Michael Haag
- **Acknowledgement**:  | [](https://twitter.com/)

### Commands

```
sc.exe create ALSysIO64.sys binPath=C:\windows\temp\ALSysIO64.sys type=kernel
sc.exe start ALSysIO64.sys
```

| Use Case | Privilages | Operating System | 
|:---- | ---- | ---- |
| Elevate privileges | kernel | Windows 10 |

### Resources
<br>
<li><a href=" https://github.com/namazso/physmem_drivers"> https://github.com/namazso/physmem_drivers</a></li>
<br>

### Known Vulnerable Samples

| Filename | ALSysIO64.sys |
|:---- | ---- | 
| MD5 | <a href="https://www.virustotal.com/gui/file/"></a> |
| SHA1 | <a href="https://www.virustotal.com/gui/file/"></a> |
| SHA256 | <a href="https://www.virustotal.com/gui/file/7196187FB1EF8D108B380D37B2AF8EFDEB3CA1F6EEFD37B5DC114C609147216D">7196187FB1EF8D108B380D37B2AF8EFDEB3CA1F6EEFD37B5DC114C609147216D</a> |
| Publisher | Artur Liberman |
| Signature |  |
| Date |  |
| Company |  |
| Description | ALSysIO |
| Product |  |
| ProductVersion |  |
| FileVersion |  |
| MachineType |  |
| SOriginalFilename |  |
| Filename | ALSysIO64.sys |
|:---- | ---- | 
| MD5 | <a href="https://www.virustotal.com/gui/file/"></a> |
| SHA1 | <a href="https://www.virustotal.com/gui/file/"></a> |
| SHA256 | <a href="https://www.virustotal.com/gui/file/7F375639A0DF7FE51E5518CF87C3F513C55BC117DB47D28DA8C615642EB18BFA">7F375639A0DF7FE51E5518CF87C3F513C55BC117DB47D28DA8C615642EB18BFA</a> |
| Publisher | Artur Liberman |
| Signature |  |
| Date |  |
| Company |  |
| Description | ALSysIO |
| Product |  |
| ProductVersion |  |
| FileVersion |  |
| MachineType |  |
| SOriginalFilename |  |



[*source*](https://github.com/magicsword-io/LOLDrivers/tree/main/yaml/alsysio64.sys.yml)

*last_updated:* 2023-03-10








{{< /column >}}
{{< /block >}}
