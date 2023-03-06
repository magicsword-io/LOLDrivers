+++

description = "https://github.com/namazso/physmem_drivers"
title = "msrhook.sys"
weight = 10

+++


{{< block "grid-1" >}}
{{< column "mt-2 pt-1">}}




# msrhook.sys 


{{< tip "warning" >}}
We were not able to verify the hash of this driver successfully, it has not been confirmed.
{{< /tip >}}




### Description


msrhook.sys is a vulnerable driver and more information will be added as found.


- **Created**: 2023-01-09
- **Author**: Michael Haag
- **Acknowledgement**:  | [](https://twitter.com/)

### Commands

| Use Case | Privilages | Operating System | 
|:---- | ---- | ---- |
| Elevate privileges | kernel | Windows 10 |

```
sc.exe create msrhook.sys binPath=C:\windows\temp\msrhook.sys type=kernel
sc.exe start msrhook.sys
```

### Resources
<br>


<li><a href=" https://github.com/namazso/physmem_drivers"> https://github.com/namazso/physmem_drivers</a></li>


<br>


### Binary Metadata
<br>



<li><a href="https://www.virustotal.com/gui/file/6DE84CAA2CA18673E01B91AF58220C60AECD5CCCF269725EC3C7F226B2167492">6DE84CAA2CA18673E01B91AF58220C60AECD5CCCF269725EC3C7F226B2167492</a></li>



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

[*source*](https://github.com/magicsword-io/LOLDrivers/tree/main/yaml/msrhook.sys.yml)

*last_updated:* 2023-03-06


{{< /column >}}
{{< /block >}}
