+++

description = "https://github.com/namazso/physmem_drivers"
title = "Dh_Kernel_10.sys"
weight = 10

+++


{{< block "grid-1" >}}
{{< column "mt-2 pt-1">}}




# Dh_Kernel_10.sys 


{{< tip "warning" >}}
We were not able to verify the hash of this driver successfully, it has not been confirmed.
{{< /tip >}}




### Description


Dh_Kernel_10.sys is a vulnerable driver and more information will be added as found.


- **Created**: 2023-01-09
- **Author**: Michael Haag
- **Acknowledgement**:  | [](https://twitter.com/)

### Commands

| Use Case | Privilages | Operating System | 
|:---- | ---- | ---- |
| Elevate privileges | kernel | Windows 10 |

```
sc.exe create Dh_Kernel_10.sys binPath=C:\windows\temp\Dh_Kernel_10.sys type=kernel
sc.exe start Dh_Kernel_10.sys
```

### Resources
<br>


<li><a href=" https://github.com/namazso/physmem_drivers"> https://github.com/namazso/physmem_drivers</a></li>


<br>


### Binary Metadata
<br>



<li><a href="https://www.virustotal.com/gui/file/80CBBA9F404DF3E642F22C476664D63D7C229D45D34F5CD0E19C65EB41BECEC3">80CBBA9F404DF3E642F22C476664D63D7C229D45D34F5CD0E19C65EB41BECEC3</a></li>



- binary: 
- Verified: 
- Date: 
- Publisher: YY Inc.
- Company: 
- Description: dianhu
- Product: 
- ProductVersion: 
- FileVersion: 
- MachineType: 
- OriginalFilename: 

[*source*](https://github.com/magicsword-io/LOLDrivers/tree/main/yaml/dh_kernel_10.sys.yml)

*last_updated:* 2023-03-07


{{< /column >}}
{{< /block >}}
