+++

description = "https://github.com/eclypsium/Screwed-Drivers/blob/master/DRIVERS.md"
title = "dbk64.sys"
weight = 10

+++


{{< block "grid-1" >}}
{{< column "mt-2 pt-1">}}


# dbk64.sys ![:inline](/images/twitter_verified.png) 


### Description

dbk64.sys is a vulnerable driver and more information will be added as found.

- **Created**: 2023-01-09
- **Author**: Michael Haag
- **Acknowledgement**:  | [](https://twitter.com/)

### Commands

```
sc.exe create dbk64.sys binPath=C:\windows\temp\dbk64.sys type=kernel
sc.exe start dbk64.sys
```

| Use Case | Privilages | Operating System | 
|:---- | ---- | ---- |
| Elevate privileges | kernel | Windows 10 |

### Resources
<br>
<li><a href=" https://github.com/eclypsium/Screwed-Drivers/blob/master/DRIVERS.md"> https://github.com/eclypsium/Screwed-Drivers/blob/master/DRIVERS.md</a></li>
<br>

### Known Vulnerable Samples

| Filename | dbk64.sys |
|:---- | ---- | 
| MD5 | <a href="https://www.virustotal.com/gui/file/1c294146fc77565030603878fd0106f9">1c294146fc77565030603878fd0106f9</a> |
| SHA1 | <a href="https://www.virustotal.com/gui/file/6053d258096bccb07cb0057d700fe05233ab1fbb">6053d258096bccb07cb0057d700fe05233ab1fbb</a> |
| SHA256 | <a href="https://www.virustotal.com/gui/file/18e1707b319c279c7e0204074088cc39286007a1cf6cb6e269d5067d8d0628c6">18e1707b319c279c7e0204074088cc39286007a1cf6cb6e269d5067d8d0628c6</a> |
| Publisher |  |
| Signature | Cheat Engine, GlobalSign Extended Validation CodeSigning CA - SHA256 - G3, GlobalSign, GlobalSign Root CA - R1   |
| Date |  |
| Company |  |
| Description |  |
| Product |  |
| ProductVersion |  |
| FileVersion |  |
| MachineType |  |
| OriginalFilename |  |



[*source*](https://github.com/magicsword-io/LOLDrivers/tree/main/yaml/dbk64.sys.yml)

*last_updated:* 2023-03-30








{{< /column >}}
{{< /block >}}
