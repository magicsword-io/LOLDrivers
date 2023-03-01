+++

description = "https://github.com/eclypsium/Screwed-Drivers/blob/master/DRIVERS.md"
title = "BS_HWMIo64.sys"
weight = 10

+++


{{< block "grid-1" >}}
{{< column "mt-2 pt-1">}}


# BS_HWMIo64.sys

#### Description

BS_HWMIo64.sys is a vulnerable driver.

- **Created**: 2023-01-09
- **Author**: Michael Haag
- **Acknowledgement**:  | [](https://twitter.com/)

#### Command

```
sc.exe create BS_HWMIo64 binPath= C:\windows\temp\BS_HWMIo64.sys type= kernel
sc.exe start BS_HWMIo64.sys
```

#### Resources
<br>


<li><a href=" https://github.com/eclypsium/Screwed-Drivers/blob/master/DRIVERS.md"> https://github.com/eclypsium/Screwed-Drivers/blob/master/DRIVERS.md</a></li>


<br>


#### Binary Metadata
<br>



<li><a href="https://www.virustotal.com/gui/file/60c6f4f34c7319cb3f9ca682e59d92711a05a2688badbae4891b1303cd384813">60c6f4f34c7319cb3f9ca682e59d92711a05a2688badbae4891b1303cd384813</a></li>



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

[*source*](https://github.com/magicsword-io/LOLDrivers/tree/main/yaml/bs_hwmio64.sys.yml)

*last_updated:* 2023-02-28


{{< /column >}}
{{< /block >}}
