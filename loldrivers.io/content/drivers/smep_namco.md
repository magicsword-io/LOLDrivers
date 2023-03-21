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
| SHA256 | <a href="https://www.virustotal.com/gui/file/7ec93f34eb323823eb199fbf8d06219086d517d0e8f4b9e348d7afd41ec9fd5d">7ec93f34eb323823eb199fbf8d06219086d517d0e8f4b9e348d7afd41ec9fd5d</a> |
| Publisher |  |
| Signature |  |
| Date |  |
| Company |  |
| Description |  |
| Product |  |
| ProductVersion |  |
| FileVersion |  |
| MachineType |  |
| OriginalFilename |  |



[*source*](https://github.com/magicsword-io/LOLDrivers/tree/main/yaml/smep_namco.sys.yml)

*last_updated:* 2023-03-21








{{< /column >}}
{{< /block >}}
