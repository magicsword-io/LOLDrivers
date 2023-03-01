+++

description = "https://github.com/eclypsium/Screwed-Drivers/blob/master/DRIVERS.md"
title = "AsrDrv103.sys"
weight = 10

+++


{{< block "grid-1" >}}
{{< column "mt-2 pt-1">}}


# AsrDrv103.sys

#### Description

AsrDrv103.sys is a vulnerable driver.

- **Created**: 2023-01-09
- **Author**: Michael Haag
- **Acknowledgement**:  | [](https://twitter.com/)

#### Command

```
sc.exe create AsrDrv103 binPath= C:\windows\temp\AsrDrv103.sys type= kernel
sc.exe start AsrDrv103.sys
```

#### Resources
<br>


<li><a href=" https://github.com/eclypsium/Screwed-Drivers/blob/master/DRIVERS.md"> https://github.com/eclypsium/Screwed-Drivers/blob/master/DRIVERS.md</a></li>


<br>


#### Binary Metadata
<br>



<li><a href="https://www.virustotal.com/gui/file/2003b478b9fd1b3d76ec5bf4172c2e8915babbbee7ad1783794acbf8d4c2519d">2003b478b9fd1b3d76ec5bf4172c2e8915babbbee7ad1783794acbf8d4c2519d</a></li>



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

[*source*](https://github.com/magicsword-io/LOLDrivers/tree/main/yaml/asrdrv103.sys.yml)

*last_updated:* 2023-02-28


{{< /column >}}
{{< /block >}}
