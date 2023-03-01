+++

description = "https://github.com/namazso/physmem_drivers"
title = "Dh_Kernel.sys"
weight = 10

+++


{{< block "grid-1" >}}
{{< column "mt-2 pt-1">}}


# Dh_Kernel.sys

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

<li><a href=" https://github.com/namazso/physmem_drivers"> https://github.com/namazso/physmem_drivers</a></li>


<br>


#### Binary Metadata
<br>



<li><a href="https://www.virustotal.com/gui/file/BB50818A07B0EB1BD317467139B7EB4BAD6CD89053FECDABFEAE111689825955">BB50818A07B0EB1BD317467139B7EB4BAD6CD89053FECDABFEAE111689825955</a></li>



- binary: 
- Verified: 
- Date: 
- Publisher: YY Inc.
- Company: 
- Description: 
- Product: 
- ProductVersion: 
- FileVersion: 
- MachineType: 
- OriginalFilename: 

[*source*](https://github.com/magicsword-io/LOLDrivers/tree/main/yaml/dh_kernel.sys.yml)

*last_updated:* 2023-02-28


{{< /column >}}
{{< /block >}}
