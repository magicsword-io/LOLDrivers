+++

description = "https://github.com/namazso/physmem_drivers"
title = "VProEventMonitor.sys"
weight = 10

+++


{{< block "grid-1" >}}
{{< column "mt-2 pt-1">}}


# VProEventMonitor.sys ![:inline](/images/twitter_verified.png) 


### Description

VProEventMonitor.sys is a vulnerable driver and more information will be added as found.

- **Created**: 2023-01-09
- **Author**: Michael Haag
- **Acknowledgement**:  | [](https://twitter.com/)

### Commands

```
sc.exe create VProEventMonitor.sys binPath=C:\windows\temp\VProEventMonitor.sys type=kernel
sc.exe start VProEventMonitor.sys
```

| Use Case | Privilages | Operating System | 
|:---- | ---- | ---- |
| Elevate privileges | kernel | Windows 10 |

### Resources
<br>
<li><a href=" https://github.com/namazso/physmem_drivers"> https://github.com/namazso/physmem_drivers</a></li>
<br>

### Known Vulnerable Samples

| Filename | VProEventMonitor.sys |
|:---- | ---- | 
| MD5 | <a href="https://www.virustotal.com/gui/file/"></a> |
| SHA1 | <a href="https://www.virustotal.com/gui/file/"></a> |
| SHA256 | <a href="https://www.virustotal.com/gui/file/7877C1B0E7429453B750218CA491C2825DAE684AD9616642EFF7B41715C70ACA">7877C1B0E7429453B750218CA491C2825DAE684AD9616642EFF7B41715C70ACA</a> |
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



[*source*](https://github.com/magicsword-io/LOLDrivers/tree/main/yaml/vproeventmonitor.sys.yml)

*last_updated:* 2023-03-10








{{< /column >}}
{{< /block >}}
