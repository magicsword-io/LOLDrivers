+++

description = "https://github.com/namazso/physmem_drivers"
title = "AsrOmgDrv.sys"
weight = 10

+++


{{< block "grid-1" >}}
{{< column "mt-2 pt-1">}}


# AsrOmgDrv.sys

#### Description

AsrOmgDrv.sys is a vulnerable driver.

- **Created**: 2023-01-09
- **Author**: Michael Haag
- **Acknowledgement**:  | [](https://twitter.com/)

#### Command

```
sc.exe create AsrOmgDrv binPath= C:\windows\temp\AsrOmgDrv.sys type= kernel
sc.exe start AsrOmgDrv.sys
```

#### Resources
<br>


<li><a href=" https://github.com/namazso/physmem_drivers"> https://github.com/namazso/physmem_drivers</a></li>


<br>


#### Binary Metadata
<br>



<li><a href="https://www.virustotal.com/gui/file/950A4C0C772021CEE26011A92194F0E58D61588F77F2873AA0599DFF52A160C9">950A4C0C772021CEE26011A92194F0E58D61588F77F2873AA0599DFF52A160C9</a></li>



- binary: 
- Verified: 
- Date: 
- Publisher: ASROCK Incorporation
- Company: 
- Description: ASRock IO Driver
- Product: 
- ProductVersion: 
- FileVersion: 
- MachineType: 
- OriginalFilename: 

[*source*](https://github.com/magicsword-io/LOLDrivers/tree/main/yaml/asromgdrv.sys.yml)

*last_updated:* 2023-02-28


{{< /column >}}
{{< /block >}}
