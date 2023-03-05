+++

description = "https://eclypsium.com/2019/11/12/mother-of-all-drivers/"
title = "OpenHardwareMonitor.sys"
weight = 10

+++


{{< block "grid-1" >}}
{{< column "mt-2 pt-1">}}


# OpenHardwareMonitor.sys

#### Description


CapCom.sys is a vulnerable driver that has been abused over the years.


- **Created**: 2023-01-09
- **Author**: Michael Haag
- **Acknowledgement**:  | [](https://twitter.com/)

#### Testing

```
sc.exe create OpenHardwareMonitor.sys binPath= C:\windows\temp\OpenHardwareMonitor.sys type= kernel
sc.exe start OpenHardwareMonitor.sys
```

#### Resources
<br>


<li><a href=" https://eclypsium.com/2019/11/12/mother-of-all-drivers/"> https://eclypsium.com/2019/11/12/mother-of-all-drivers/</a></li>


<br>


#### Binary Metadata
<br>



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

[*source*](https://github.com/magicsword-io/LOLDrivers/tree/main/yaml/openhardwaremonitor.sys.yml)

*last_updated:* 2023-03-04


{{< /column >}}
{{< /block >}}
