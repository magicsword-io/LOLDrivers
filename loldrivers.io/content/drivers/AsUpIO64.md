+++

description = ""
title = "AsUpIO64.sys"
weight = 10

+++


{{< block "grid-1" >}}
{{< column "mt-2 pt-1">}}


# AsUpIO64.sys ![:inline](/images/twitter_verified.png) 


### Description

AsUpIO64.sys is a vulnerable driver and more information will be added as found.

- **Created**: 2023-01-09
- **Author**: Michael Haag
- **Acknowledgement**:  | [](https://twitter.com/)

### Commands

```
sc.exe create AsUpIO64.sys binPath=C:\windows\temp\AsUpIO64.sys type=kernel
sc.exe start AsUpIO64.sys
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

| Filename | AsUpIO64.sys |
|:---- | ---- | 
| MD5 | <a href="https://www.virustotal.com/gui/file/1392b92179b07b672720763d9b1028a5">1392b92179b07b672720763d9b1028a5</a> |
| SHA1 | <a href="https://www.virustotal.com/gui/file/8b6aa5b2bff44766ef7afbe095966a71bc4183fa">8b6aa5b2bff44766ef7afbe095966a71bc4183fa</a> |
| SHA256 | <a href="https://www.virustotal.com/gui/file/b4d47ea790920a4531e3df5a4b4b0721b7fea6b49a35679f0652f1e590422602">b4d47ea790920a4531e3df5a4b4b0721b7fea6b49a35679f0652f1e590422602</a> |
| Signature | ASUSTeK Computer Inc., VeriSign Class 3 Code Signing 2009-2 CA, VeriSign Class 3 Public Primary CA   |


[*source*](https://github.com/magicsword-io/LOLDrivers/tree/main/yaml/asupio64.yaml)

*last_updated:* 2023-04-05








{{< /column >}}
{{< /block >}}
