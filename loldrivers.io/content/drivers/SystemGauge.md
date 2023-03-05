+++

description = "https://eclypsium.com/2019/11/12/mother-of-all-drivers/"
title = "SystemGauge.sys"
weight = 10

+++


{{< block "grid-1" >}}
{{< column "mt-2 pt-1">}}


# SystemGauge.sys

#### Description


CapCom.sys is a vulnerable driver that has been abused over the years.


- **Created**: 2023-01-09
- **Author**: Michael Haag
- **Acknowledgement**:  | [](https://twitter.com/)

#### Testing

```
sc.exe create SystemGauge.sys binPath= C:\windows\temp\SystemGauge.sys type= kernel
sc.exe start SystemGauge.sys
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

[*source*](https://github.com/magicsword-io/LOLDrivers/tree/main/yaml/systemgauge.sys.yml)

*last_updated:* 2023-03-04


{{< /column >}}
{{< /block >}}
