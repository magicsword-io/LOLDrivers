+++

description = "https://github.com/namazso/physmem_drivers"
title = "HwRwDrv.sys"
weight = 10

+++


{{< block "grid-1" >}}
{{< column "mt-2 pt-1">}}




# HwRwDrv.sys 


{{< tip "warning" >}}
We were not able to verify the hash of this driver successfully, it has not been confirmed.
{{< /tip >}}




### Description


HwRwDrv.sys is a vulnerable driver and more information will be added as found.


- **Created**: 2023-01-09
- **Author**: Michael Haag
- **Acknowledgement**:  | [](https://twitter.com/)

### Commands

| Use Case | Privilages | Operating System | 
|:---- | ---- | ---- |
| Elevate privileges | kernel | Windows 10 |

```
sc.exe create HwRwDrv.sys binPath=C:\windows\temp\HwRwDrv.sys type=kernel
sc.exe start HwRwDrv.sys
```

### Resources
<br>


<li><a href=" https://github.com/namazso/physmem_drivers"> https://github.com/namazso/physmem_drivers</a></li>


<br>


### Binary Metadata
<br>



<li><a href="https://www.virustotal.com/gui/file/21CCDD306B5183C00ECFD0475B3152E7D94B921E858E59B68A03E925D1715F21">21CCDD306B5183C00ECFD0475B3152E7D94B921E858E59B68A03E925D1715F21</a></li>



- binary: 
- Verified: 
- Date: 
- Publisher: Shuttle Inc.
- Company: 
- Description: Hardware read &amp; write driver
- Product: 
- ProductVersion: 
- FileVersion: 
- MachineType: 
- OriginalFilename: 

[*source*](https://github.com/magicsword-io/LOLDrivers/tree/main/yaml/hwrwdrv.sys.yml)

*last_updated:* 2023-03-07


{{< /column >}}
{{< /block >}}
