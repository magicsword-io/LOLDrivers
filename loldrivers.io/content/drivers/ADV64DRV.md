+++

description = ""
title = "ADV64DRV.sys"
weight = 10

+++


{{< block "grid-1" >}}
{{< column "mt-2 pt-1">}}


# ADV64DRV.sys ![:inline](/images/twitter_verified.png) 


### Description

ADV64DRV.sys is a vulnerable driver and more information will be added as found.

- **Created**: 2023-01-09
- **Author**: Michael Haag
- **Acknowledgement**:  | [](https://twitter.com/)

### Commands

```
sc.exe create ADV64DRV.sys binPath=C:\windows\temp\ADV64DRV.sys type=kernel
sc.exe start ADV64DRV.sys
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

| Filename | ADV64DRV.sys |
|:---- | ---- | 
| MD5 | <a href="https://www.virustotal.com/gui/file/778b7feea3c750d44745d3bf294bd4ce">778b7feea3c750d44745d3bf294bd4ce</a> |
| SHA1 | <a href="https://www.virustotal.com/gui/file/2261198385d62d2117f50f631652eded0ecc71db">2261198385d62d2117f50f631652eded0ecc71db</a> |
| SHA256 | <a href="https://www.virustotal.com/gui/file/04a85e359525d662338cae86c1e59b1d7aa9bd12b920e8067503723dc1e03162">04a85e359525d662338cae86c1e59b1d7aa9bd12b920e8067503723dc1e03162</a> |
| Publisher | FUJITSU LIMITED || Signature | FUJITSU LIMITED , VeriSign Class 3 Code Signing 2004 CA, VeriSign Class 3 Public Primary CA   || Date | 01:30 AM 08/29/2006 || OriginalFilename | ADV64DRV.sys |


[*source*](https://github.com/magicsword-io/LOLDrivers/tree/main/yaml/adv64drv.yaml)

*last_updated:* 2023-04-06








{{< /column >}}
{{< /block >}}
