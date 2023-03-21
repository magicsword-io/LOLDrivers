+++

description = "https://github.com/namazso/physmem_drivers"
title = "HOSTNT.sys"
weight = 10

+++


{{< block "grid-1" >}}
{{< column "mt-2 pt-1">}}


# HOSTNT.sys ![:inline](/images/twitter_verified.png) 


### Description

HOSTNT.sys is a vulnerable driver and more information will be added as found.

- **Created**: 2023-01-09
- **Author**: Michael Haag
- **Acknowledgement**:  | [](https://twitter.com/)

### Commands

```
sc.exe create HOSTNT.sys binPath=C:\windows\temp\HOSTNT.sys type=kernel
sc.exe start HOSTNT.sys
```

| Use Case | Privilages | Operating System | 
|:---- | ---- | ---- |
| Elevate privileges | kernel | Windows 10 |

### Resources
<br>
<li><a href=" https://github.com/namazso/physmem_drivers"> https://github.com/namazso/physmem_drivers</a></li>
<br>

### Known Vulnerable Samples

| Filename | HOSTNT.sys |
|:---- | ---- | 
| MD5 | <a href="https://www.virustotal.com/gui/file/"></a> |
| SHA1 | <a href="https://www.virustotal.com/gui/file/"></a> |
| SHA256 | <a href="https://www.virustotal.com/gui/file/07b6d69bafcfd767f1b63a490a8843c3bb1f8e1bbea56176109b5743c8f7d357">07b6d69bafcfd767f1b63a490a8843c3bb1f8e1bbea56176109b5743c8f7d357</a> |
| Publisher | &#34;SafeNet, Inc.&#34; |
| Signature |  |
| Date |  |
| Company |  |
| Description | Hostnt 64-bit driver |
| Product |  |
| ProductVersion |  |
| FileVersion |  |
| MachineType |  |
| OriginalFilename |  |



[*source*](https://github.com/magicsword-io/LOLDrivers/tree/main/yaml/hostnt.sys.yml)

*last_updated:* 2023-03-21








{{< /column >}}
{{< /block >}}
