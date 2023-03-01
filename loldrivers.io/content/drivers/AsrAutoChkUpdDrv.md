+++

description = "https://github.com/namazso/physmem_drivers"
title = "AsrAutoChkUpdDrv.sys"
weight = 10

+++


{{< block "grid-1" >}}
{{< column "mt-2 pt-1">}}


# AsrAutoChkUpdDrv.sys

#### Description

AsrAutoChkUpdDrv.sys is a vulnerable driver.

- **Created**: 2023-01-09
- **Author**: Michael Haag
- **Acknowledgement**:  | [](https://twitter.com/)

#### Command

```
sc.exe create AsrAutoChkUpdDrv.sys binPath= C:\windows\temp\AsrAutoChkUpdDrv.sys type= kernel
sc.exe start AsrAutoChkUpdDrv.sys
```

#### Resources
<br>


<li><a href=" https://github.com/namazso/physmem_drivers"> https://github.com/namazso/physmem_drivers</a></li>


<br>


#### Binary Metadata
<br>



<li><a href="https://www.virustotal.com/gui/file/2AA1B08F47FBB1E2BD2E4A492F5D616968E703E1359A921F62B38B8E4662F0C4">2AA1B08F47FBB1E2BD2E4A492F5D616968E703E1359A921F62B38B8E4662F0C4</a></li>



- binary: 
- Verified: 
- Date: 
- Publisher: ASROCK Incorporation
- Company: 
- Description: AsrAutoChkUpdDrv Driver
- Product: 
- ProductVersion: 
- FileVersion: 
- MachineType: 
- OriginalFilename: 

[*source*](https://github.com/magicsword-io/LOLDrivers/tree/main/yaml/asrautochkupddrv.sys.yml)

*last_updated:* 2023-02-28


{{< /column >}}
{{< /block >}}
