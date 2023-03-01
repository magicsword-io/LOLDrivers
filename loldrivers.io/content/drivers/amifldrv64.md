+++

description = "https://github.com/namazso/physmem_drivers"
title = "amifldrv64.sys"
weight = 10

+++


{{< block "grid-1" >}}
{{< column "mt-2 pt-1">}}


# amifldrv64.sys

#### Description

amifldrv64.sys is a vulnerable driver.

- **Created**: 2023-01-09
- **Author**: Michael Haag
- **Acknowledgement**:  | [](https://twitter.com/)

#### Command

```
sc.exe create amifldrv64 binPath= C:\windows\temp\amifldrv64.sys type= kernel
sc.exe start amifldrv64.sys
```

#### Resources
<br>


<li><a href=" https://github.com/namazso/physmem_drivers"> https://github.com/namazso/physmem_drivers</a></li>


<br>


#### Binary Metadata
<br>



<li><a href="https://www.virustotal.com/gui/file/42579A759F3F95F20A2C51D5AC2047A2662A2675B3FB9F46C1ED7F23393A0F00">42579A759F3F95F20A2C51D5AC2047A2662A2675B3FB9F46C1ED7F23393A0F00</a></li>



- binary: 
- Verified: 
- Date: 
- Publisher: &#34;American Megatrends, Inc.&#34;
- Company: 
- Description: 
- Product: 
- ProductVersion: 
- FileVersion: 
- MachineType: 
- OriginalFilename: 

[*source*](https://github.com/magicsword-io/LOLDrivers/tree/main/yaml/amifldrv64.sys.yml)

*last_updated:* 2023-02-28


{{< /column >}}
{{< /block >}}
