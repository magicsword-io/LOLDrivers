+++

description = "https://github.com/eclypsium/Screwed-Drivers/blob/master/DRIVERS.md"
title = "BSMEMx64.sys"
weight = 10

+++


{{< block "grid-1" >}}
{{< column "mt-2 pt-1">}}


# BSMEMx64.sys ![:inline](/images/twitter_verified.png) 


### Description

BSMEMx64.sys is a vulnerable driver and more information will be added as found.

- **Created**: 2023-01-09
- **Author**: Michael Haag
- **Acknowledgement**:  | [](https://twitter.com/)

### Commands

```
sc.exe create BSMEMx64.sys binPath=C:\windows\temp\BSMEMx64.sys type=kernel
sc.exe start BSMEMx64.sys
```

| Use Case | Privilages | Operating System | 
|:---- | ---- | ---- |
| Elevate privileges | kernel | Windows 10 |

### Resources
<br>
<li><a href=" https://github.com/eclypsium/Screwed-Drivers/blob/master/DRIVERS.md"> https://github.com/eclypsium/Screwed-Drivers/blob/master/DRIVERS.md</a></li>
<br>

### Known Vulnerable Samples

| Filename | BSMEMx64.sys |
|:---- | ---- | 
| MD5 | <a href="https://www.virustotal.com/gui/file/49fe3d1f3d5c2e50a0df0f6e8436d778">49fe3d1f3d5c2e50a0df0f6e8436d778</a> |
| SHA1 | <a href="https://www.virustotal.com/gui/file/9d07df024ec457168bf0be7e0009619f6ac4f13c">9d07df024ec457168bf0be7e0009619f6ac4f13c</a> |
| SHA256 | <a href="https://www.virustotal.com/gui/file/f929bead59e9424ab90427b379dcdd63fbfe0c4fb5e1792e3a1685541cd5ec65">f929bead59e9424ab90427b379dcdd63fbfe0c4fb5e1792e3a1685541cd5ec65</a> |
| Signature | BIOSTAR MICROTECH INT&#39;L CORP, VeriSign Class 3 Code Signing 2009-2 CA, VeriSign Class 3 Public Primary CA   |


[*source*](https://github.com/magicsword-io/LOLDrivers/tree/main/yaml/bsmemx64.sys.yml)

*last_updated:* 2023-04-03








{{< /column >}}
{{< /block >}}
