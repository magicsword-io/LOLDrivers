+++

description = "https://github.com/namazso/physmem_drivers"
title = "cpuz_x64.sys"
weight = 10

+++


{{< block "grid-1" >}}
{{< column "mt-2 pt-1">}}


# cpuz_x64.sys ![:inline](/images/twitter_verified.png) 


### Description

cpuz_x64.sys is a vulnerable driver and more information will be added as found.

- **Created**: 2023-01-09
- **Author**: Michael Haag
- **Acknowledgement**:  | [](https://twitter.com/)

### Commands

```
sc.exe create cpuz_x64.sys binPath=C:\windows\temp\cpuz_x64.sys type=kernel
sc.exe start cpuz_x64.sys
```

| Use Case | Privilages | Operating System | 
|:---- | ---- | ---- |
| Elevate privileges | kernel | Windows 10 |

### Resources
<br>
<li><a href=" https://github.com/namazso/physmem_drivers"> https://github.com/namazso/physmem_drivers</a></li>
<br>

### Known Vulnerable Samples

| Filename | cpuz_x64.sys |
|:---- | ---- | 
| MD5 | <a href="https://www.virustotal.com/gui/file/"></a> |
| SHA1 | <a href="https://www.virustotal.com/gui/file/"></a> |
| SHA256 | <a href="https://www.virustotal.com/gui/file/3871E16758A1778907667F78589359734F7F62F9DC953EC558946DCDBE6951E3">3871E16758A1778907667F78589359734F7F62F9DC953EC558946DCDBE6951E3</a> |
| Publisher | CPUID |
| Signature |  |
| Date |  |
| Company |  |
| Description | CPUID Driver |
| Product |  |
| ProductVersion |  |
| FileVersion |  |
| MachineType |  |
| SOriginalFilename |  |



[*source*](https://github.com/magicsword-io/LOLDrivers/tree/main/yaml/cpuz_x64.sys.yml)

*last_updated:* 2023-03-10








{{< /column >}}
{{< /block >}}
