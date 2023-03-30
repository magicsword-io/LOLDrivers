+++

description = "https://github.com/namazso/physmem_drivers"
title = "AsrRapidStartDrv.sys"
weight = 10

+++


{{< block "grid-1" >}}
{{< column "mt-2 pt-1">}}


# AsrRapidStartDrv.sys ![:inline](/images/twitter_verified.png) 


### Description

AsrRapidStartDrv.sys is a vulnerable driver and more information will be added as found.

- **Created**: 2023-01-09
- **Author**: Michael Haag
- **Acknowledgement**:  | [](https://twitter.com/)

### Commands

```
sc.exe create AsrRapidStartDrv.sys binPath=C:\windows\temp\AsrRapidStartDrv.sys type=kernel
sc.exe start AsrRapidStartDrv.sys
```

| Use Case | Privilages | Operating System | 
|:---- | ---- | ---- |
| Elevate privileges | kernel | Windows 10 |

### Resources
<br>
<li><a href=" https://github.com/namazso/physmem_drivers"> https://github.com/namazso/physmem_drivers</a></li>
<br>

### Known Vulnerable Samples

| Filename | AsrRapidStartDrv.sys |
|:---- | ---- | 
| MD5 | <a href="https://www.virustotal.com/gui/file/31469f1313871690e8dc2e8ee4799b22">31469f1313871690e8dc2e8ee4799b22</a> |
| SHA1 | <a href="https://www.virustotal.com/gui/file/89cd760e8cb19d29ee08c430fb17a5fd4455c741">89cd760e8cb19d29ee08c430fb17a5fd4455c741</a> |
| SHA256 | <a href="https://www.virustotal.com/gui/file/0aafa9f47acf69d46c9542985994ff5321f00842a28df2396d4a3076776a83cb">0aafa9f47acf69d46c9542985994ff5321f00842a28df2396d4a3076776a83cb</a> |
| Publisher | ASROCK Incorporation |
| Signature | ASROCK Incorporation, VeriSign Class 3 Code Signing 2010 CA, VeriSign   |
| Date |  |
| Company |  |
| Description | RW-Everything Read &amp; Write Driver |
| Product |  |
| ProductVersion |  |
| FileVersion |  |
| MachineType |  |
| OriginalFilename |  |



[*source*](https://github.com/magicsword-io/LOLDrivers/tree/main/yaml/asrrapidstartdrv.sys.yml)

*last_updated:* 2023-03-30








{{< /column >}}
{{< /block >}}
