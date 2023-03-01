+++

description = "https://github.com/namazso/physmem_drivers"
title = "dbutil_2_3.sys"
weight = 10

+++


{{< block "grid-1" >}}
{{< column "mt-2 pt-1">}}


# dbutil_2_3.sys

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



<li><a href="https://www.virustotal.com/gui/file/0296E2CE999E67C76352613A718E11516FE1B0EFC3FFDB8918FC999DD76A73A5">0296E2CE999E67C76352613A718E11516FE1B0EFC3FFDB8918FC999DD76A73A5</a></li>

<li><a href="https://www.virustotal.com/gui/file/c948ae14761095e4d76b55d9de86412258be7afd">c948ae14761095e4d76b55d9de86412258be7afd</a></li>



- binary: 
- Verified: 
- Date: 
- Publisher: Dell Inc.
- Company: 
- Description: dianhu
- Product: 
- ProductVersion: 
- FileVersion: 
- MachineType: 
- OriginalFilename: 

[*source*](https://github.com/magicsword-io/LOLDrivers/tree/main/yaml/dbutil_2_3.sys.yml)

*last_updated:* 2023-02-28


{{< /column >}}
{{< /block >}}
