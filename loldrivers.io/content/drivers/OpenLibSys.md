+++

description = "https://github.com/namazso/physmem_drivers"
title = "OpenLibSys.sys"
weight = 10

+++


{{< block "grid-1" >}}
{{< column "mt-2 pt-1">}}




# OpenLibSys.sys 


{{< tip "warning" >}}
We were not able to verify the hash of this driver successfully, it has not been confirmed.
{{< /tip >}}




### Description


OpenLibSys.sys is a vulnerable driver and more information will be added as found.


- **Created**: 2023-01-09
- **Author**: Michael Haag
- **Acknowledgement**:  | [](https://twitter.com/)

### Commands

| Use Case | Privilages | Operating System | 
|:---- | ---- | ---- |
| Elevate privileges | kernel | Windows 10 |

```
sc.exe create OpenLibSys.sys binPath=C:\windows\temp\OpenLibSys.sys type=kernel
sc.exe start OpenLibSys.sys
```

### Resources
<br>


<li><a href=" https://github.com/namazso/physmem_drivers"> https://github.com/namazso/physmem_drivers</a></li>


<br>


### Binary Metadata
<br>



<li><a href="https://www.virustotal.com/gui/file/91314768DA140999E682D2A290D48B78BB25A35525EA12C1B1F9634D14602B2C">91314768DA140999E682D2A290D48B78BB25A35525EA12C1B1F9634D14602B2C</a></li>

<li><a href="https://www.virustotal.com/gui/file/F0605DDA1DEF240DC7E14EFA73927D6C6D89988C01EA8647B671667B2B167008">F0605DDA1DEF240DC7E14EFA73927D6C6D89988C01EA8647B671667B2B167008</a></li>



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

[*source*](https://github.com/magicsword-io/LOLDrivers/tree/main/yaml/openlibsys.sys.yml)

*last_updated:* 2023-03-07


{{< /column >}}
{{< /block >}}
