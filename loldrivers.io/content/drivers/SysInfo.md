+++

description = "https://github.com/namazso/physmem_drivers"
title = "SysInfo.sys"
weight = 10

+++


{{< block "grid-1" >}}
{{< column "mt-2 pt-1">}}


# SysInfo.sys

#### Description

SysInfo.sys is a vulnerable driver.

- **Created**: 2023-01-09
- **Author**: Michael Haag
- **Acknowledgement**:  | [](https://twitter.com/)

#### Command

```
sc.exe create SysInfo binPath= C:\windows\temp\SysInfo.sys type= kernel
sc.exe start SysInfo.sys
```

#### Resources
<br>


<li><a href=" https://github.com/namazso/physmem_drivers"> https://github.com/namazso/physmem_drivers</a></li>


<br>


#### Binary Metadata
<br>



<li><a href="https://www.virustotal.com/gui/file/7049F3C939EFE76A5556C2A2C04386DB51DAF61D56B679F4868BB0983C996EBB">7049F3C939EFE76A5556C2A2C04386DB51DAF61D56B679F4868BB0983C996EBB</a></li>



- binary: 
- Verified: 
- Date: 
- Publisher: 
- Company: 
- Description: 
- Product: 
- ProductVersion: 
- FileVersion: 
- MachineType: 
- OriginalFilename: 

[*source*](https://github.com/magicsword-io/LOLDrivers/tree/main/yaml/sysinfo.sys.yml)

*last_updated:* 2023-02-28


{{< /column >}}
{{< /block >}}
