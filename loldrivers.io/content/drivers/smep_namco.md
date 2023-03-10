+++

description = "https://github.com/namazso/physmem_drivers"
title = "smep_namco.sys"
weight = 10

+++


{{< block "grid-1" >}}
{{< column "mt-2 pt-1">}}


# smep_namco.sys ![:inline](/images/twitter_verified.png) 


### Description

smep_namco.sys is a vulnerable driver and more information will be added as found.

- **Created**: 2023-01-09
- **Author**: Michael Haag
- **Acknowledgement**:  | [](https://twitter.com/)

### Commands

```
sc.exe create smep_namco.sys binPath=C:\windows\temp\smep_namco.sys type=kernel
sc.exe start smep_namco.sys
```

| Use Case | Privilages | Operating System | 
|:---- | ---- | ---- |
| Elevate privileges | kernel | Windows 10 |

### Resources
<br>
<li><a href=" https://github.com/namazso/physmem_drivers"> https://github.com/namazso/physmem_drivers</a></li>
<br>

### Known Vulnerable Samples

| Filename | smep_namco.sys |
|:---- | ---- | 
| MD5 | <a href="https://www.virustotal.com/gui/file/"></a> |
| SHA1 | <a href="https://www.virustotal.com/gui/file/"></a> |
| SHA256 | <a href="https://www.virustotal.com/gui/file/7EC93F34EB323823EB199FBF8D06219086D517D0E8F4B9E348D7AFD41EC9FD5D">7EC93F34EB323823EB199FBF8D06219086D517D0E8F4B9E348D7AFD41EC9FD5D</a> |
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



[*source*](https://github.com/magicsword-io/LOLDrivers/tree/main/yaml/smep_namco.sys.yml)

*last_updated:* 2023-03-10








{{< /column >}}
{{< /block >}}
