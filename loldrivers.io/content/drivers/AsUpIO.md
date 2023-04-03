+++

description = "https://github.com/namazso/physmem_drivers"
title = "AsUpIO.sys"
weight = 10

+++


{{< block "grid-1" >}}
{{< column "mt-2 pt-1">}}


# AsUpIO.sys ![:inline](/images/twitter_verified.png) 


### Description

AsUpIO.sys is a vulnerable driver and more information will be added as found.

- **Created**: 2023-01-09
- **Author**: Michael Haag
- **Acknowledgement**:  | [](https://twitter.com/)

### Commands

```
sc.exe create AsUpIO.sys binPath=C:\windows\temp\AsUpIO.sys type=kernel
sc.exe start AsUpIO.sys
```

| Use Case | Privilages | Operating System | 
|:---- | ---- | ---- |
| Elevate privileges | kernel | Windows 10 |

### Resources
<br>
<li><a href=" https://github.com/namazso/physmem_drivers"> https://github.com/namazso/physmem_drivers</a></li>
<br>

### Known Vulnerable Samples

| Filename | AsUpIO.sys |
|:---- | ---- | 
| MD5 | <a href="https://www.virustotal.com/gui/file/6d4159694e1754f262e326b52a3b305a">6d4159694e1754f262e326b52a3b305a</a> |
| SHA1 | <a href="https://www.virustotal.com/gui/file/d5fd9fe10405c4f90235e583526164cd0902ed86">d5fd9fe10405c4f90235e583526164cd0902ed86</a> |
| SHA256 | <a href="https://www.virustotal.com/gui/file/b9a4e40a5d80fedd1037eaed958f9f9efed41eb01ada73d51b5dcd86e27e0cbf">b9a4e40a5d80fedd1037eaed958f9f9efed41eb01ada73d51b5dcd86e27e0cbf</a> |
| Publisher | ASUSTeK Computer Inc. || Signature | ASUSTeK Computer Inc., VeriSign Class 3 Code Signing 2009-2 CA, VeriSign Class 3 Public Primary CA   |


[*source*](https://github.com/magicsword-io/LOLDrivers/tree/main/yaml/asupio.sys.yml)

*last_updated:* 2023-04-02








{{< /column >}}
{{< /block >}}
