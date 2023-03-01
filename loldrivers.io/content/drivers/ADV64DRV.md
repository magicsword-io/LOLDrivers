+++

description = "https://github.com/namazso/physmem_drivers"
title = "ADV64DRV.sys"
weight = 10

+++


{{< block "grid-1" >}}
{{< column "mt-2 pt-1">}}


# ADV64DRV.sys

#### Description

ADV64DRV.sys is a vulnerable driver.

- **Created**: 2023-01-09
- **Author**: Michael Haag
- **Acknowledgement**:  | [](https://twitter.com/)

#### Command

```
sc.exe create ADV64DRV binPath= C:\windows\temp\ADV64DRV.sys type= kernel
sc.exe start ADV64DRV.sys
```

#### Resources
<br>


<li><a href=" https://github.com/namazso/physmem_drivers"> https://github.com/namazso/physmem_drivers</a></li>


<br>


#### Binary Metadata
<br>



<li><a href="https://www.virustotal.com/gui/file/04A85E359525D662338CAE86C1E59B1D7AA9BD12B920E8067503723DC1E03162">04A85E359525D662338CAE86C1E59B1D7AA9BD12B920E8067503723DC1E03162</a></li>



- binary: 
- Verified: TRUE
- Date: 44896
- Publisher: FUJITSU LIMITED
- Company: 
- Description: 
- Product: 
- ProductVersion: 
- FileVersion: 
- MachineType: 
- OriginalFilename: 

[*source*](https://github.com/magicsword-io/LOLDrivers/tree/main/yaml/adv64drv.sys.yml)

*last_updated:* 2023-02-28


{{< /column >}}
{{< /block >}}
