+++

description = ""
title = "Dh_Kernel.sys"
weight = 10

+++


{{< block "grid-1" >}}
{{< column "mt-2 pt-1">}}


# Dh_Kernel.sys ![:inline](/images/twitter_verified.png) 


### Description

Dh_Kernel.sys is a vulnerable driver and more information will be added as found.

- **Created**: 2023-01-09
- **Author**: Michael Haag
- **Acknowledgement**:  | [](https://twitter.com/)

### Commands

```
sc.exe create Dh_Kernel.sys binPath=C:\windows\temp\Dh_Kernel.sys type=kernel
sc.exe start Dh_Kernel.sys
```

| Use Case | Privilages | Operating System | 
|:---- | ---- | ---- |
| Elevate privileges | kernel | Windows 10 |

### Resources
<br>
<li><a href=" https://github.com/namazso/physmem_drivers"> https://github.com/namazso/physmem_drivers</a></li>
<li><a href=" https://github.com/namazso/physmem_drivers"> https://github.com/namazso/physmem_drivers</a></li>
<li><a href="https://github.com/namazso/physmem_drivers">https://github.com/namazso/physmem_drivers</a></li>
<br>

### Known Vulnerable Samples

| Filename | Dh_Kernel.sys |
|:---- | ---- | 
| MD5 | <a href="https://www.virustotal.com/gui/file/98763a3dee3cf03de334f00f95fc071a">98763a3dee3cf03de334f00f95fc071a</a> |
| SHA1 | <a href="https://www.virustotal.com/gui/file/745bad097052134548fe159f158c04be5616afc2">745bad097052134548fe159f158c04be5616afc2</a> |
| SHA256 | <a href="https://www.virustotal.com/gui/file/bb50818a07b0eb1bd317467139b7eb4bad6cd89053fecdabfeae111689825955">bb50818a07b0eb1bd317467139b7eb4bad6cd89053fecdabfeae111689825955</a> |
| Publisher | YY Inc. || Signature | YY Inc., VeriSign Class 3 Code Signing 2010 CA, VeriSign   |


[*source*](https://github.com/magicsword-io/LOLDrivers/tree/main/yaml/dh_kernel.yaml)

*last_updated:* 2023-04-05








{{< /column >}}
{{< /block >}}
