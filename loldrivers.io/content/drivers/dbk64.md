+++

description = "https://github.com/eclypsium/Screwed-Drivers/blob/master/DRIVERS.md"
title = "dbk64.sys"
weight = 10

+++


{{< block "grid-1" >}}
{{< column "mt-2 pt-1">}}


# dbk64.sys

#### Description

dbk64.sys is a vulnerable driver.

- **Created**: 2023-01-09
- **Author**: Michael Haag
- **Acknowledgement**:  | [](https://twitter.com/)

#### Command

```
sc.exe create dbk64.sys binPath= C:\windows\temp\dbk64.sys type= kernel
sc.exe start dbk64.sys
```

#### Resources
<br>


<li><a href=" https://github.com/eclypsium/Screwed-Drivers/blob/master/DRIVERS.md"> https://github.com/eclypsium/Screwed-Drivers/blob/master/DRIVERS.md</a></li>


<br>


#### Binary Metadata
<br>



<li><a href="https://www.virustotal.com/gui/file/18e1707b319c279c7e0204074088cc39286007a1cf6cb6e269d5067d8d0628c6">18e1707b319c279c7e0204074088cc39286007a1cf6cb6e269d5067d8d0628c6</a></li>



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

[*source*](https://github.com/magicsword-io/LOLDrivers/tree/main/yaml/dbk64.sys.yml)

*last_updated:* 2023-02-28


{{< /column >}}
{{< /block >}}
