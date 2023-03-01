+++

description = "https://github.com/namazso/physmem_drivers"
title = "Dh_Kernel_10.sys"
weight = 10

+++


{{< block "grid-1" >}}
{{< column "mt-2 pt-1">}}


# Dh_Kernel_10.sys

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



<li><a href="https://www.virustotal.com/gui/file/80CBBA9F404DF3E642F22C476664D63D7C229D45D34F5CD0E19C65EB41BECEC3">80CBBA9F404DF3E642F22C476664D63D7C229D45D34F5CD0E19C65EB41BECEC3</a></li>



- binary: 
- Verified: 
- Date: 
- Publisher: YY Inc.
- Company: 
- Description: dianhu
- Product: 
- ProductVersion: 
- FileVersion: 
- MachineType: 
- OriginalFilename: 

[*source*](https://github.com/magicsword-io/LOLDrivers/tree/main/yaml/dh_kernel_10.sys.yml)

*last_updated:* 2023-02-28


{{< /column >}}
{{< /block >}}
