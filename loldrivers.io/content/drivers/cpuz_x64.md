+++

description = "https://github.com/namazso/physmem_drivers"
title = "cpuz_x64.sys"
weight = 10

+++


{{< block "grid-1" >}}
{{< column "mt-2 pt-1">}}


# cpuz_x64.sys

#### Description

cpuz_x64.sys is a vulnerable driver.

- **Created**: 2023-01-09
- **Author**: Michael Haag
- **Acknowledgement**:  | [](https://twitter.com/)

#### Command

```
sc.exe create cpuz_x64 binPath= C:\windows\temp\cpuz_x64.sys type= kernel
sc.exe start cpuz_x64.sys
```

#### Resources
<br>


<li><a href=" https://github.com/namazso/physmem_drivers"> https://github.com/namazso/physmem_drivers</a></li>


<br>


#### Binary Metadata
<br>



<li><a href="https://www.virustotal.com/gui/file/3871E16758A1778907667F78589359734F7F62F9DC953EC558946DCDBE6951E3">3871E16758A1778907667F78589359734F7F62F9DC953EC558946DCDBE6951E3</a></li>



- binary: 
- Verified: 
- Date: 
- Publisher: CPUID
- Company: 
- Description: CPUID Driver
- Product: 
- ProductVersion: 
- FileVersion: 
- MachineType: 
- OriginalFilename: 

[*source*](https://github.com/magicsword-io/LOLDrivers/tree/main/yaml/cpuz_x64.sys.yml)

*last_updated:* 2023-02-28


{{< /column >}}
{{< /block >}}
