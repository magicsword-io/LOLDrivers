+++

description = "https://github.com/namazso/physmem_drivers"
title = "AsrIbDrv.sys"
weight = 10

+++


{{< block "grid-1" >}}
{{< column "mt-2 pt-1">}}


# AsrIbDrv.sys ![:inline](/images/twitter_verified.png) 


### Description

AsrIbDrv.sys is a vulnerable driver and more information will be added as found.

- **Created**: 2023-01-09
- **Author**: Michael Haag
- **Acknowledgement**:  | [](https://twitter.com/)

### Commands

```
sc.exe create AsrIbDrv.sys binPath=C:\windows\temp\AsrIbDrv.sys type=kernel
sc.exe start AsrIbDrv.sys
```

| Use Case | Privilages | Operating System | 
|:---- | ---- | ---- |
| Elevate privileges | kernel | Windows 10 |

### Resources
<br>
<li><a href=" https://github.com/namazso/physmem_drivers"> https://github.com/namazso/physmem_drivers</a></li>
<br>

### Known Vulnerable Samples

| Filename | AsrIbDrv.sys |
|:---- | ---- | 
| MD5 | <a href="https://www.virustotal.com/gui/file/5bab40019419a2713298a5c9173e5d30">5bab40019419a2713298a5c9173e5d30</a> |
| SHA1 | <a href="https://www.virustotal.com/gui/file/2d503a2457a787014a1fdd48a2ece2e6cbe98ea7">2d503a2457a787014a1fdd48a2ece2e6cbe98ea7</a> |
| SHA256 | <a href="https://www.virustotal.com/gui/file/2a652de6b680d5ad92376ad323021850dab2c653abf06edf26120f7714b8e08a">2a652de6b680d5ad92376ad323021850dab2c653abf06edf26120f7714b8e08a</a> |
| Publisher | ASROCK Incorporation || Signature | ASROCK Incorporation, VeriSign Class 3 Code Signing 2010 CA, VeriSign   || Description | RW-Everything Read &amp; Write Driver |


[*source*](https://github.com/magicsword-io/LOLDrivers/tree/main/yaml/asribdrv.sys.yml)

*last_updated:* 2023-04-02








{{< /column >}}
{{< /block >}}
