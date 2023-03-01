+++

description = "https://github.com/namazso/physmem_drivers"
title = "HwRwDrv.sys"
weight = 10

+++


{{< block "grid-1" >}}
{{< column "mt-2 pt-1">}}


# HwRwDrv.sys

#### Description

HwRwDrv.sys is a vulnerable driver.

- **Created**: 2023-01-09
- **Author**: Michael Haag
- **Acknowledgement**:  | [](https://twitter.com/)

#### Command

```
sc.exe create HwRwDrv binPath= C:\windows\temp\HwRwDrv.sys type= kernel
sc.exe start HwRwDrv.sys
```

#### Resources
<br>


<li><a href=" https://github.com/namazso/physmem_drivers"> https://github.com/namazso/physmem_drivers</a></li>


<br>


#### Binary Metadata
<br>



<li><a href="https://www.virustotal.com/gui/file/21CCDD306B5183C00ECFD0475B3152E7D94B921E858E59B68A03E925D1715F21">21CCDD306B5183C00ECFD0475B3152E7D94B921E858E59B68A03E925D1715F21</a></li>



- binary: 
- Verified: 
- Date: 
- Publisher: Shuttle Inc.
- Company: 
- Description: Hardware read &amp; write driver
- Product: 
- ProductVersion: 
- FileVersion: 
- MachineType: 
- OriginalFilename: 

[*source*](https://github.com/magicsword-io/LOLDrivers/tree/main/yaml/hwrwdrv.sys.yml)

*last_updated:* 2023-02-28


{{< /column >}}
{{< /block >}}
