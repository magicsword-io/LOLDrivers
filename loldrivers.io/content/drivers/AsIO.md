+++

description = ""
title = "AsIO.sys"
weight = 10

+++


{{< block "grid-1" >}}
{{< column "mt-2 pt-1">}}


# AsIO.sys ![:inline](/images/twitter_verified.png) 


### Description

AsIO.sys is a vulnerable driver and more information will be added as found.

- **Created**: 2023-01-09
- **Author**: Michael Haag
- **Acknowledgement**:  | [](https://twitter.com/)

### Commands

```
sc.exe create AsIO.sys binPath=C:\windows\temp\AsIO.sys type=kernel
sc.exe start AsIO.sys
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

| Filename | AsIO.sys |
|:---- | ---- | 
| MD5 | <a href="https://www.virustotal.com/gui/file/1dc94a6a82697c62a04e461d7a94d0b0">1dc94a6a82697c62a04e461d7a94d0b0</a> |
| SHA1 | <a href="https://www.virustotal.com/gui/file/b97a8d506be2e7eaa4385f70c009b22adbd071ba">b97a8d506be2e7eaa4385f70c009b22adbd071ba</a> |
| SHA256 | <a href="https://www.virustotal.com/gui/file/2da330a2088409efc351118445a824f11edbe51cf3d653b298053785097fe40e">2da330a2088409efc351118445a824f11edbe51cf3d653b298053785097fe40e</a> |
| Publisher | ASUSTeK Computer Inc. || Signature | ASUSTeK Computer Inc., VeriSign Class 3 Code Signing 2009-2 CA, VeriSign Class 3 Public Primary CA   || Filename | AsIO.sys |
|:---- | ---- | 
| MD5 | <a href="https://www.virustotal.com/gui/file/798de15f187c1f013095bbbeb6fb6197">798de15f187c1f013095bbbeb6fb6197</a> |
| SHA1 | <a href="https://www.virustotal.com/gui/file/92f251358b3fe86fd5e7aa9b17330afa0d64a705">92f251358b3fe86fd5e7aa9b17330afa0d64a705</a> |
| SHA256 | <a href="https://www.virustotal.com/gui/file/436ccab6f62fa2d29827916e054ade7acae485b3de1d3e5c6c62d3debf1480e7">436ccab6f62fa2d29827916e054ade7acae485b3de1d3e5c6c62d3debf1480e7</a> |
| Publisher | ASUSTeK Computer Inc. || Signature | ASUSTeK Computer Inc., VeriSign Class 3 Code Signing 2010 CA, VeriSign   || Filename | AsIO.sys |
|:---- | ---- | 
| MD5 | <a href="https://www.virustotal.com/gui/file/1392b92179b07b672720763d9b1028a5">1392b92179b07b672720763d9b1028a5</a> |
| SHA1 | <a href="https://www.virustotal.com/gui/file/8b6aa5b2bff44766ef7afbe095966a71bc4183fa">8b6aa5b2bff44766ef7afbe095966a71bc4183fa</a> |
| SHA256 | <a href="https://www.virustotal.com/gui/file/b4d47ea790920a4531e3df5a4b4b0721b7fea6b49a35679f0652f1e590422602">b4d47ea790920a4531e3df5a4b4b0721b7fea6b49a35679f0652f1e590422602</a> |
| Publisher | ASUSTeK Computer Inc. || Signature | ASUSTeK Computer Inc., VeriSign Class 3 Code Signing 2009-2 CA, VeriSign Class 3 Public Primary CA   || Filename | AsIO.sys |
|:---- | ---- | 
| MD5 | <a href="https://www.virustotal.com/gui/file/fef9dd9ea587f8886ade43c1befbdafe">fef9dd9ea587f8886ade43c1befbdafe</a> |
| SHA1 | <a href="https://www.virustotal.com/gui/file/af6e1f2cfb230907476e8b2d676129b6d6657124">af6e1f2cfb230907476e8b2d676129b6d6657124</a> |
| SHA256 | <a href="https://www.virustotal.com/gui/file/dde6f28b3f7f2abbee59d4864435108791631e9cb4cdfb1f178e5aa9859956d8">dde6f28b3f7f2abbee59d4864435108791631e9cb4cdfb1f178e5aa9859956d8</a> |
| Publisher | ASUSTeK Computer Inc. || Signature | ASUSTeK Computer Inc., VeriSign Class 3 Code Signing 2009-2 CA, VeriSign Class 3 Public Primary CA   |


[*source*](https://github.com/magicsword-io/LOLDrivers/tree/main/yaml/asio.yaml)

*last_updated:* 2023-04-06








{{< /column >}}
{{< /block >}}
