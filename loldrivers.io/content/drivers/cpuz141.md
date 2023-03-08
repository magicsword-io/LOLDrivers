+++

description = "https://github.com/namazso/physmem_drivers"
title = "cpuz141.sys"
weight = 10

+++


{{< block "grid-1" >}}
{{< column "mt-2 pt-1">}}




# cpuz141.sys 


{{< tip "warning" >}}
We were not able to verify the hash of this driver successfully, it has not been confirmed.
{{< /tip >}}




### Description


cpuz141.sys is a vulnerable driver and more information will be added as found.


- **Created**: 2023-01-09
- **Author**: Michael Haag
- **Acknowledgement**:  | [](https://twitter.com/)

### Commands

| Use Case | Privilages | Operating System | 
|:---- | ---- | ---- |
| Elevate privileges | kernel | Windows 10 |

```
sc.exe create cpuz141.sys binPath=C:\windows\temp\cpuz141.sys type=kernel
sc.exe start cpuz141.sys
```

### Resources
<br>


<li><a href=" https://github.com/namazso/physmem_drivers"> https://github.com/namazso/physmem_drivers</a></li>


<br>


### Binary Metadata
<br>



<li><a href="https://www.virustotal.com/gui/file/DED2927F9A4E64EEFD09D0CABA78E94F309E3A6292841AE81D5528CAB109F95D">DED2927F9A4E64EEFD09D0CABA78E94F309E3A6292841AE81D5528CAB109F95D</a></li>



- binary: 
- Verified: 
- Date: 
- Publisher: CPUID
- Company: 
- Description: CPUID Driver
- Product: 
- ProductVersion: 
- FileVersion: 
- MachineType: 
- OriginalFilename: 

[*source*](https://github.com/magicsword-io/LOLDrivers/tree/main/yaml/cpuz141.sys.yml)

*last_updated:* 2023-03-07


{{< /column >}}
{{< /block >}}
