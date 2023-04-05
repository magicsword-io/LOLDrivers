+++

description = ""
title = "AsrOmgDrv.sys"
weight = 10

+++


{{< block "grid-1" >}}
{{< column "mt-2 pt-1">}}


# AsrOmgDrv.sys ![:inline](/images/twitter_verified.png) 


### Description

AsrOmgDrv.sys is a vulnerable driver and more information will be added as found.

- **Created**: 2023-01-09
- **Author**: Michael Haag
- **Acknowledgement**:  | [](https://twitter.com/)

### Commands

```
sc.exe create AsrOmgDrv.sys binPath=C:\windows\temp\AsrOmgDrv.sys type=kernel
sc.exe start AsrOmgDrv.sys
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

| Filename | AsrOmgDrv.sys |
|:---- | ---- | 
| MD5 | <a href="https://www.virustotal.com/gui/file/4f27c09cc8680e06b04d6a9c34ca1e08">4f27c09cc8680e06b04d6a9c34ca1e08</a> |
| SHA1 | <a href="https://www.virustotal.com/gui/file/400f833dcc2ef0a122dd0e0b1ec4ec929340d90e">400f833dcc2ef0a122dd0e0b1ec4ec929340d90e</a> |
| SHA256 | <a href="https://www.virustotal.com/gui/file/950a4c0c772021cee26011a92194f0e58d61588f77f2873aa0599dff52a160c9">950a4c0c772021cee26011a92194f0e58d61588f77f2873aa0599dff52a160c9</a> |
| Publisher | ASROCK Incorporation || Signature | ASROCK Incorporation, VeriSign Class 3 Code Signing 2010 CA, VeriSign   || Description | ASRock IO Driver |


[*source*](https://github.com/magicsword-io/LOLDrivers/tree/main/yaml/asromgdrv.yaml)

*last_updated:* 2023-04-05








{{< /column >}}
{{< /block >}}
