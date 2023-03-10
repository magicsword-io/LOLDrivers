+++

description = "https://github.com/namazso/physmem_drivers"
title = "atillk64.sys"
weight = 10

+++


{{< block "grid-1" >}}
{{< column "mt-2 pt-1">}}


# atillk64.sys ![:inline](/images/twitter_verified.png) 


### Description

atillk64.sys is a vulnerable driver and more information will be added as found.

- **Created**: 2023-01-09
- **Author**: Michael Haag
- **Acknowledgement**:  | [](https://twitter.com/)

### Commands

```
sc.exe create atillk64.sys binPath=C:\windows\temp\atillk64.sys type=kernel
sc.exe start atillk64.sys
```

| Use Case | Privilages | Operating System | 
|:---- | ---- | ---- |
| Elevate privileges | kernel | Windows 10 |

### Resources
<br>
<li><a href=" https://github.com/namazso/physmem_drivers"> https://github.com/namazso/physmem_drivers</a></li>
<br>

### Known Vulnerable Samples

| Filename | atillk64.sys |
|:---- | ---- | 
| MD5 | <a href="https://www.virustotal.com/gui/file/"></a> |
| SHA1 | <a href="https://www.virustotal.com/gui/file/"></a> |
| SHA256 | <a href="https://www.virustotal.com/gui/file/5C04C274A708C9A7D993E33BE3EA9E6119DC29527A767410DBAF93996F87369A">5C04C274A708C9A7D993E33BE3EA9E6119DC29527A767410DBAF93996F87369A</a> |
| Publisher | &#34;ATI Technologies, Inc&#34; |
| Signature |  |
| Date |  |
| Company |  |
| Description | ATI Diagnostics Hardware Abstraction Sys |
| Product |  |
| ProductVersion |  |
| FileVersion |  |
| MachineType |  |
| SOriginalFilename |  |



[*source*](https://github.com/magicsword-io/LOLDrivers/tree/main/yaml/atillk64.sys.yml)

*last_updated:* 2023-03-10








{{< /column >}}
{{< /block >}}
