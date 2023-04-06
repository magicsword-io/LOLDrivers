+++

description = ""
title = "WinFlash64.sys"
weight = 10

+++


{{< block "grid-1" >}}
{{< column "mt-2 pt-1">}}


# WinFlash64.sys ![:inline](/images/twitter_verified.png) 


### Description

WinFlash64.sys is a vulnerable driver and more information will be added as found.

- **Created**: 2023-01-09
- **Author**: Michael Haag
- **Acknowledgement**:  | [](https://twitter.com/)

### Commands

```
sc.exe create WinFlash64.sys binPath=C:\windows\temp\WinFlash64.sys type=kernel
sc.exe start WinFlash64.sys
```

| Use Case | Privileges | Operating System | 
|:---- | ---- | ---- |
| Elevate privileges | kernel | Windows 10 |

### Resources
<br>
<li><a href=" https://github.com/eclypsium/Screwed-Drivers/blob/master/DRIVERS.md"> https://github.com/eclypsium/Screwed-Drivers/blob/master/DRIVERS.md</a></li>
<li><a href="https://github.com/eclypsium/Screwed-Drivers/blob/master/DRIVERS.md">https://github.com/eclypsium/Screwed-Drivers/blob/master/DRIVERS.md</a></li>
<br>

### Known Vulnerable Samples

| Filename | WinFlash64.sys |
|:---- | ---- | 
| MD5 | <a href="https://www.virustotal.com/gui/file/a4fda97f452b8f8705695a729f5969f7">a4fda97f452b8f8705695a729f5969f7</a> |
| SHA1 | <a href="https://www.virustotal.com/gui/file/8183a341ba6c3ce1948bf9be49ab5320e0ee324d">8183a341ba6c3ce1948bf9be49ab5320e0ee324d</a> |
| SHA256 | <a href="https://www.virustotal.com/gui/file/677c0b1add3990fad51f492553d3533115c50a242a919437ccb145943011d2bf">677c0b1add3990fad51f492553d3533115c50a242a919437ccb145943011d2bf</a> |
| Signature | Phoenix Technology Ltd., VeriSign Class 3 Code Signing 2004 CA, VeriSign Class 3 Public Primary CA   |


[*source*](https://github.com/magicsword-io/LOLDrivers/tree/main/yaml/winflash64.yaml)

*last_updated:* 2023-04-06








{{< /column >}}
{{< /block >}}
