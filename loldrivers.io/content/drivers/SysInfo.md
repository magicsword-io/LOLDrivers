+++

description = ""
title = "SysInfo.sys"
weight = 10

+++


{{< block "grid-1" >}}
{{< column "mt-2 pt-1">}}


# SysInfo.sys ![:inline](/images/twitter_verified.png) 


### Description

SysInfo.sys is a vulnerable driver and more information will be added as found.

- **Created**: 2023-01-09
- **Author**: Michael Haag
- **Acknowledgement**:  | [](https://twitter.com/)

### Commands

```
sc.exe create SysInfo.sys binPath=C:\windows\temp\SysInfo.sys type=kernel
sc.exe start SysInfo.sys
```

| Use Case | Privileges | Operating System | 
|:---- | ---- | ---- |
| Elevate privileges | kernel | Windows 10 |

### Resources
<br>
<li><a href=" https://github.com/namazso/physmem_drivers"> https://github.com/namazso/physmem_drivers</a></li>
<li><a href="https://github.com/namazso/physmem_drivers">https://github.com/namazso/physmem_drivers</a></li>
<br>

### Known Vulnerable Samples

| Filename | SysInfo.sys |
|:---- | ---- | 
| MD5 | <a href="https://www.virustotal.com/gui/file/5228b7a738dc90a06ae4f4a7412cb1e9">5228b7a738dc90a06ae4f4a7412cb1e9</a> |
| SHA1 | <a href="https://www.virustotal.com/gui/file/f0c463d29a5914b01e4607889094f1b7d95e7aaf">f0c463d29a5914b01e4607889094f1b7d95e7aaf</a> |
| SHA256 | <a href="https://www.virustotal.com/gui/file/7049f3c939efe76a5556c2a2c04386db51daf61d56b679f4868bb0983c996ebb">7049f3c939efe76a5556c2a2c04386db51daf61d56b679f4868bb0983c996ebb</a> |
| Signature | Noriyuki MIYAZAKI, GlobalSign ObjectSign CA, GlobalSign Primary Object Publishing CA, GlobalSign Root CA - R1   |


[*source*](https://github.com/magicsword-io/LOLDrivers/tree/main/yaml/sysinfo.yaml)

*last_updated:* 2023-04-06








{{< /column >}}
{{< /block >}}
