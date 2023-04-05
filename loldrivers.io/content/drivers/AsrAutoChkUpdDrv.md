+++

description = ""
title = "AsrAutoChkUpdDrv.sys"
weight = 10

+++


{{< block "grid-1" >}}
{{< column "mt-2 pt-1">}}


# AsrAutoChkUpdDrv.sys ![:inline](/images/twitter_verified.png) 


### Description

AsrAutoChkUpdDrv.sys is a vulnerable driver and more information will be added as found.

- **Created**: 2023-01-09
- **Author**: Michael Haag
- **Acknowledgement**:  | [](https://twitter.com/)

### Commands

```
sc.exe create AsrAutoChkUpdDrv.sys binPath=C:\windows\temp\AsrAutoChkUpdDrv.sys type=kernel
sc.exe start AsrAutoChkUpdDrv.sys
```

| Use Case | Privilages | Operating System | 
|:---- | ---- | ---- |
| Elevate privileges | kernel | Windows 10 |

### Resources
<br>
<li><a href=" https://github.com/namazso/physmem_drivers"> https://github.com/namazso/physmem_drivers</a></li>
<li><a href="https://github.com/namazso/physmem_drivers">https://github.com/namazso/physmem_drivers</a></li>
<br>

### Known Vulnerable Samples

| Filename | AsrAutoChkUpdDrv.sys |
|:---- | ---- | 
| MD5 | <a href="https://www.virustotal.com/gui/file/75d6c3469347de1cdfa3b1b9f1544208">75d6c3469347de1cdfa3b1b9f1544208</a> |
| SHA1 | <a href="https://www.virustotal.com/gui/file/6523b3fd87de39eb5db1332e4523ce99556077dc">6523b3fd87de39eb5db1332e4523ce99556077dc</a> |
| SHA256 | <a href="https://www.virustotal.com/gui/file/2aa1b08f47fbb1e2bd2e4a492f5d616968e703e1359a921f62b38b8e4662f0c4">2aa1b08f47fbb1e2bd2e4a492f5d616968e703e1359a921f62b38b8e4662f0c4</a> |
| Publisher | ASROCK Incorporation || Signature | ASROCK Incorporation, VeriSign Class 3 Code Signing 2010 CA, VeriSign   || Description | AsrAutoChkUpdDrv Driver |


[*source*](https://github.com/magicsword-io/LOLDrivers/tree/main/yaml/asrautochkupddrv.sys.yml)

*last_updated:* 2023-04-05








{{< /column >}}
{{< /block >}}
