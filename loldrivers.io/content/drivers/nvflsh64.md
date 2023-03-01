+++

description = "https://github.com/eclypsium/Screwed-Drivers/blob/master/DRIVERS.md"
title = "nvflsh64.sys"
weight = 10

+++


{{< block "grid-1" >}}
{{< column "mt-2 pt-1">}}


# nvflsh64.sys

#### Description

nvflsh64.sys is a vulnerable driver.

- **Created**: 2023-01-09
- **Author**: Michael Haag
- **Acknowledgement**:  | [](https://twitter.com/)

#### Command

```
sc.exe create nvflsh64 binPath= C:\windows\temp\nvflsh64.sys type= kernel
sc.exe start nvflsh64.sys
```

#### Resources
<br>


<li><a href=" https://github.com/eclypsium/Screwed-Drivers/blob/master/DRIVERS.md"> https://github.com/eclypsium/Screwed-Drivers/blob/master/DRIVERS.md</a></li>


<br>


#### Binary Metadata
<br>



<li><a href="https://www.virustotal.com/gui/file/a899b659b08fbae30b182443be8ffb6a6471c1d0497b52293061754886a937a3">a899b659b08fbae30b182443be8ffb6a6471c1d0497b52293061754886a937a3</a></li>



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

[*source*](https://github.com/magicsword-io/LOLDrivers/tree/main/yaml/nvflsh64.sys.yml)

*last_updated:* 2023-02-28


{{< /column >}}
{{< /block >}}
