+++

description = "https://github.com/namazso/physmem_drivers"
title = "AsrIbDrv.sys"
weight = 10

+++


{{< block "grid-1" >}}
{{< column "mt-2 pt-1">}}


# AsrIbDrv.sys

#### Description

AsrIbDrv.sys is a vulnerable driver.

- **Created**: 2023-01-09
- **Author**: Michael Haag
- **Acknowledgement**:  | [](https://twitter.com/)

#### Command

```
sc.exe create AsrIbDrv binPath= C:\windows\temp\AsrIbDrv.sys type= kernel
sc.exe start AsrIbDrv.sys
```

#### Resources
<br>


<li><a href=" https://github.com/namazso/physmem_drivers"> https://github.com/namazso/physmem_drivers</a></li>


<br>


#### Binary Metadata
<br>



<li><a href="https://www.virustotal.com/gui/file/2A652DE6B680D5AD92376AD323021850DAB2C653ABF06EDF26120F7714B8E08A">2A652DE6B680D5AD92376AD323021850DAB2C653ABF06EDF26120F7714B8E08A</a></li>



- binary: 
- Verified: 
- Date: 
- Publisher: ASROCK Incorporation
- Company: 
- Description: RW-Everything Read &amp; Write Driver
- Product: 
- ProductVersion: 
- FileVersion: 
- MachineType: 
- OriginalFilename: 

[*source*](https://github.com/magicsword-io/LOLDrivers/tree/main/yaml/asribdrv.sys.yml)

*last_updated:* 2023-02-28


{{< /column >}}
{{< /block >}}
