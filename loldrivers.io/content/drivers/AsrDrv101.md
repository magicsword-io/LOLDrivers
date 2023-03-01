+++

description = "https://github.com/namazso/physmem_drivers"
title = "AsrDrv101.sys"
weight = 10

+++


{{< block "grid-1" >}}
{{< column "mt-2 pt-1">}}


# AsrDrv101.sys

#### Description

AsrDrv101.sys is a vulnerable driver.

- **Created**: 2023-01-09
- **Author**: Michael Haag
- **Acknowledgement**:  | [](https://twitter.com/)

#### Command

```
sc.exe create AsrDrv101 binPath= C:\windows\temp\AsrDrv101.sys type= kernel
sc.exe start AsrDrv101.sys
```

#### Resources
<br>


<li><a href=" https://github.com/namazso/physmem_drivers"> https://github.com/namazso/physmem_drivers</a></li>


<br>


#### Binary Metadata
<br>



<li><a href="https://www.virustotal.com/gui/file/F40435488389B4FB3B945CA21A8325A51E1B5F80F045AB019748D0EC66056A8B">F40435488389B4FB3B945CA21A8325A51E1B5F80F045AB019748D0EC66056A8B</a></li>



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

[*source*](https://github.com/magicsword-io/LOLDrivers/tree/main/yaml/asrdrv101.sys.yml)

*last_updated:* 2023-02-28


{{< /column >}}
{{< /block >}}
