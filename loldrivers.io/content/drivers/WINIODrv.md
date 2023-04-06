+++

description = ""
title = "WINIODrv.sys"
weight = 10

+++


{{< block "grid-1" >}}
{{< column "mt-2 pt-1">}}


# WINIODrv.sys ![:inline](/images/twitter_verified.png) 


### Description

WINIODrv.sys is a vulnerable driver and more information will be added as found.

- **Created**: 2023-01-09
- **Author**: Michael Haag
- **Acknowledgement**:  | [](https://twitter.com/)

### Commands

```
sc.exe create WINIODrv.sys binPath=C:\windows\temp\WINIODrv.sys type=kernel
sc.exe start WINIODrv.sys
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

| Filename | WINIODrv.sys |
|:---- | ---- | 
| MD5 | <a href="https://www.virustotal.com/gui/file/a86150f2e29b35369afa2cafd7aa9764">a86150f2e29b35369afa2cafd7aa9764</a> |
| SHA1 | <a href="https://www.virustotal.com/gui/file/460008b1ffd31792a6deadfa6280fb2a30c8a5d2">460008b1ffd31792a6deadfa6280fb2a30c8a5d2</a> |
| SHA256 | <a href="https://www.virustotal.com/gui/file/3243aab18e273a9b9c4280a57aecef278e10bfff19abb260d7a7820e41739099">3243aab18e273a9b9c4280a57aecef278e10bfff19abb260d7a7820e41739099</a> |
| Signature | Partner Tech(Shanghai)Co.,Ltd, VeriSign Class 3 Code Signing 2010 CA, VeriSign   || Filename | WINIODrv.sys |
|:---- | ---- | 
| MD5 | <a href="https://www.virustotal.com/gui/file/ad22a7b010de6f9c6f39c350a471a440">ad22a7b010de6f9c6f39c350a471a440</a> |
| SHA1 | <a href="https://www.virustotal.com/gui/file/738b7918d85e5cb4395df9e3f6fc94ddad90e939">738b7918d85e5cb4395df9e3f6fc94ddad90e939</a> |
| SHA256 | <a href="https://www.virustotal.com/gui/file/7cfa5e10dff8a99a5d544b011f676bc383991274c693e21e3af40cf6982adb8c">7cfa5e10dff8a99a5d544b011f676bc383991274c693e21e3af40cf6982adb8c</a> |
| Signature | Partner Tech(Shanghai)Co.,Ltd, VeriSign Class 3 Code Signing 2010 CA, VeriSign   || Filename | WINIODrv.sys |
|:---- | ---- | 
| MD5 | <a href="https://www.virustotal.com/gui/file/0761c357aed5f591142edaefdf0c89c8">0761c357aed5f591142edaefdf0c89c8</a> |
| SHA1 | <a href="https://www.virustotal.com/gui/file/43419df1f9a07430a18c5f3b3cc74de621be0f8e">43419df1f9a07430a18c5f3b3cc74de621be0f8e</a> |
| SHA256 | <a href="https://www.virustotal.com/gui/file/c9b49b52b493b53cd49c12c3fa9553e57c5394555b64e32d1208f5b96a5b8c6e">c9b49b52b493b53cd49c12c3fa9553e57c5394555b64e32d1208f5b96a5b8c6e</a> |
| Signature | Partner Tech(Shanghai)Co.,Ltd, VeriSign Class 3 Code Signing 2010 CA, VeriSign   |


[*source*](https://github.com/magicsword-io/LOLDrivers/tree/main/yaml/winiodrv.yaml)

*last_updated:* 2023-04-06








{{< /column >}}
{{< /block >}}
