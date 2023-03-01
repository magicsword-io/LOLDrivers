+++

description = "https://github.com/eclypsium/Screwed-Drivers/blob/master/DRIVERS.md"
title = "BSMEMx64.sys"
weight = 10

+++


{{< block "grid-1" >}}
{{< column "mt-2 pt-1">}}


# BSMEMx64.sys

#### Description

BSMEMx64.sys is a vulnerable driver.

- **Created**: 2023-01-09
- **Author**: Michael Haag
- **Acknowledgement**:  | [](https://twitter.com/)

#### Command

```
sc.exe create BSMEMx64 binPath= C:\windows\temp\BSMEMx64.sys type= kernel
sc.exe start BSMEMx64.sys
```

#### Resources
<br>


<li><a href=" https://github.com/eclypsium/Screwed-Drivers/blob/master/DRIVERS.md"> https://github.com/eclypsium/Screwed-Drivers/blob/master/DRIVERS.md</a></li>


<br>


#### Binary Metadata
<br>



<li><a href="https://www.virustotal.com/gui/file/f929bead59e9424ab90427b379dcdd63fbfe0c4fb5e1792e3a1685541cd5ec65">f929bead59e9424ab90427b379dcdd63fbfe0c4fb5e1792e3a1685541cd5ec65</a></li>



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

[*source*](https://github.com/magicsword-io/LOLDrivers/tree/main/yaml/bsmemx64.sys.yml)

*last_updated:* 2023-02-28


{{< /column >}}
{{< /block >}}
