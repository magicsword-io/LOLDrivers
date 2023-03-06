+++

description = "https://github.com/namazso/physmem_drivers"
title = "AsrDrv101.sys"
weight = 10

+++


{{< block "grid-1" >}}
{{< column "mt-2 pt-1">}}




# AsrDrv101.sys 


{{< tip "warning" >}}
We were not able to verify the hash of this driver successfully, it has not been confirmed.
{{< /tip >}}




### Description


AsrDrv101.sys is a vulnerable driver and more information will be added as found.


- **Created**: 2023-01-09
- **Author**: Michael Haag
- **Acknowledgement**:  | [](https://twitter.com/)

### Commands

| Use Case | Privilages | Operating System | 
|:---- | ---- | ---- |
| Elevate privileges | kernel | Windows 10 |

```
sc.exe create AsrDrv101.sys binPath=C:\windows\temp\AsrDrv101.sys type=kernel
sc.exe start AsrDrv101.sys
```

### Resources
<br>


<li><a href=" https://github.com/namazso/physmem_drivers"> https://github.com/namazso/physmem_drivers</a></li>


<br>


### Binary Metadata
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

*last_updated:* 2023-03-06


{{< /column >}}
{{< /block >}}
