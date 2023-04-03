+++

description = "https://github.com/eclypsium/Screwed-Drivers/blob/master/DRIVERS.md"
title = "PhlashNT.sys"
weight = 10

+++


{{< block "grid-1" >}}
{{< column "mt-2 pt-1">}}


# PhlashNT.sys ![:inline](/images/twitter_verified.png) 


### Description

PhlashNT.sys is a vulnerable driver and more information will be added as found.

- **Created**: 2023-01-09
- **Author**: Michael Haag
- **Acknowledgement**:  | [](https://twitter.com/)

### Commands

```
sc.exe create PhlashNT.sys binPath=C:\windows\temp\PhlashNT.sys type=kernel
sc.exe start PhlashNT.sys
```

| Use Case | Privilages | Operating System | 
|:---- | ---- | ---- |
| Elevate privileges | kernel | Windows 10 |

### Resources
<br>
<li><a href=" https://github.com/eclypsium/Screwed-Drivers/blob/master/DRIVERS.md"> https://github.com/eclypsium/Screwed-Drivers/blob/master/DRIVERS.md</a></li>
<br>

### Known Vulnerable Samples

| Filename | PhlashNT.sys |
|:---- | ---- | 
| MD5 | <a href="https://www.virustotal.com/gui/file/e9e786bdba458b8b4f9e93d034f73d00">e9e786bdba458b8b4f9e93d034f73d00</a> |
| SHA1 | <a href="https://www.virustotal.com/gui/file/c6d349823bbb1f5b44bae91357895dba653c5861">c6d349823bbb1f5b44bae91357895dba653c5861</a> |
| SHA256 | <a href="https://www.virustotal.com/gui/file/65db1b259e305a52042e07e111f4fa4af16542c8bacd33655f753ef642228890">65db1b259e305a52042e07e111f4fa4af16542c8bacd33655f753ef642228890</a> |
| Signature | Phoenix Technology Ltd., VeriSign Class 3 Code Signing 2004 CA, VeriSign Class 3 Public Primary CA   |


[*source*](https://github.com/magicsword-io/LOLDrivers/tree/main/yaml/phlashnt.sys.yml)

*last_updated:* 2023-04-02








{{< /column >}}
{{< /block >}}
