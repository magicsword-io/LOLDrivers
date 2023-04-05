+++

description = ""
title = "AsrDrv102.sys"
weight = 10

+++


{{< block "grid-1" >}}
{{< column "mt-2 pt-1">}}


# AsrDrv102.sys ![:inline](/images/twitter_verified.png) 


### Description

AsrDrv102.sys is a vulnerable driver and more information will be added as found.

- **Created**: 2023-01-09
- **Author**: Michael Haag
- **Acknowledgement**:  | [](https://twitter.com/)

### Commands

```
sc.exe create AsrDrv102.sys binPath=C:\windows\temp\AsrDrv102.sys type=kernel
sc.exe start AsrDrv102.sys
```

| Use Case | Privilages | Operating System | 
|:---- | ---- | ---- |
| Elevate privileges | kernel | Windows 10 |

### Resources
<br>
<li><a href=" https://github.com/eclypsium/Screwed-Drivers/blob/master/DRIVERS.md"> https://github.com/eclypsium/Screwed-Drivers/blob/master/DRIVERS.md</a></li>
<li><a href="https://github.com/eclypsium/Screwed-Drivers/blob/master/DRIVERS.md">https://github.com/eclypsium/Screwed-Drivers/blob/master/DRIVERS.md</a></li>
<br>

### Known Vulnerable Samples

| Filename | AsrDrv102.sys |
|:---- | ---- | 
| MD5 | <a href="https://www.virustotal.com/gui/file/76bb1a4332666222a8e3e1339e267179">76bb1a4332666222a8e3e1339e267179</a> |
| SHA1 | <a href="https://www.virustotal.com/gui/file/9923c8f1e565a05b3c738d283cf5c0ed61a0b90f">9923c8f1e565a05b3c738d283cf5c0ed61a0b90f</a> |
| SHA256 | <a href="https://www.virustotal.com/gui/file/a7c2e7910942dd5e43e2f4eb159bcd2b4e71366e34a68109548b9fb12ac0f7cc">a7c2e7910942dd5e43e2f4eb159bcd2b4e71366e34a68109548b9fb12ac0f7cc</a> |
| Signature | ASROCK Incorporation, VeriSign Class 3 Code Signing 2010 CA, VeriSign   |


[*source*](https://github.com/magicsword-io/LOLDrivers/tree/main/yaml/asrdrv102.yaml)

*last_updated:* 2023-04-05








{{< /column >}}
{{< /block >}}
