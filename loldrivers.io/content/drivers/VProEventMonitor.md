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
| MD5 | <a href="https://www.virustotal.com/gui/file/cd9f0fcecf1664facb3671c0130dc8bb">cd9f0fcecf1664facb3671c0130dc8bb</a> |
| SHA1 | <a href="https://www.virustotal.com/gui/file/0c26ab1299adcd9a385b541ef1653728270aa23e">0c26ab1299adcd9a385b541ef1653728270aa23e</a> |
| SHA256 | <a href="https://www.virustotal.com/gui/file/7877c1b0e7429453b750218ca491c2825dae684ad9616642eff7b41715c70aca">7877c1b0e7429453b750218ca491c2825dae684ad9616642eff7b41715c70aca</a> |
| Signature | Symantec Corporation, VeriSign Class 3 Code Signing 2010 CA, VeriSign   |


[*source*](https://github.com/magicsword-io/LOLDrivers/tree/main/yaml/vproeventmonitor.sys.yml)

*last_updated:* 2023-04-02








{{< /column >}}
{{< /block >}}
