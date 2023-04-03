+++

description = "https://github.com/eclypsium/Screwed-Drivers/blob/master/DRIVERS.md"
title = "GVCIDrv64.sys"
weight = 10

+++


{{< block "grid-1" >}}
{{< column "mt-2 pt-1">}}


# GVCIDrv64.sys ![:inline](/images/twitter_verified.png) 


### Description

GVCIDrv64.sys is a vulnerable driver and more information will be added as found.

- **Created**: 2023-01-09
- **Author**: Michael Haag
- **Acknowledgement**:  | [](https://twitter.com/)

### Commands

```
sc.exe create GVCIDrv64.sys binPath=C:\windows\temp\GVCIDrv64.sys type=kernel
sc.exe start GVCIDrv64.sys
```

| Use Case | Privilages | Operating System | 
|:---- | ---- | ---- |
| Elevate privileges | kernel | Windows 10 |

### Resources
<br>
<li><a href=" https://github.com/eclypsium/Screwed-Drivers/blob/master/DRIVERS.md"> https://github.com/eclypsium/Screwed-Drivers/blob/master/DRIVERS.md</a></li>
<br>

### Known Vulnerable Samples

| Filename | GVCIDrv64.sys |
|:---- | ---- | 
| MD5 | <a href="https://www.virustotal.com/gui/file/8b287636041792f640f92e77e560725e">8b287636041792f640f92e77e560725e</a> |
| SHA1 | <a href="https://www.virustotal.com/gui/file/e92817a8744ebc4e4fa5383cdce2b2977f01ecd4">e92817a8744ebc4e4fa5383cdce2b2977f01ecd4</a> |
| SHA256 | <a href="https://www.virustotal.com/gui/file/42f0b036687cbd7717c9efed6991c00d4e3e7b032dc965a2556c02177dfdad0f">42f0b036687cbd7717c9efed6991c00d4e3e7b032dc965a2556c02177dfdad0f</a> |
| Signature | GIGA-BYTE TECHNOLOGY CO., LTD., Symantec Class 3 SHA256 Code Signing CA, VeriSign   |


[*source*](https://github.com/magicsword-io/LOLDrivers/tree/main/yaml/gvcidrv64.sys.yml)

*last_updated:* 2023-04-02








{{< /column >}}
{{< /block >}}
