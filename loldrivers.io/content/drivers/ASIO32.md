+++

description = "https://learn.microsoft.com/en-us/windows/security/threat-protection/windows-defender-application-control/microsoft-recommended-driver-block-rules"
title = "ASIO32.sys"
weight = 10

+++


{{< block "grid-1" >}}
{{< column "mt-2 pt-1">}}


# ASIO32.sys

#### Description


ASIO32.sys is a vulnerable driver and more information will be added as found.


- **Created**: 2023-01-09
- **Author**: Michael Haag
- **Acknowledgement**:  | [](https://twitter.com/)

#### Testing

```
sc.exe create ASIO32.sys binPath= C:\windows\temp\ASIO32.sys type= kernel
sc.exe start ASIO32.sys
```

#### Resources
<br>


<li><a href=" https://learn.microsoft.com/en-us/windows/security/threat-protection/windows-defender-application-control/microsoft-recommended-driver-block-rules"> https://learn.microsoft.com/en-us/windows/security/threat-protection/windows-defender-application-control/microsoft-recommended-driver-block-rules</a></li>


<br>


#### Binary Metadata
<br>



<li><a href="https://www.virustotal.com/gui/file/D569D4BAB86E70EFBCDFDAC9D822139D6F477B7C">D569D4BAB86E70EFBCDFDAC9D822139D6F477B7C</a></li>

<li><a href="https://www.virustotal.com/gui/file/80FA962BDFB76DFCB9E5D13EFC38BB3D392F2E77">80FA962BDFB76DFCB9E5D13EFC38BB3D392F2E77</a></li>

<li><a href="https://www.virustotal.com/gui/file/5A7DD0DA0AEE0BDEDC14C1B7831B9CE9178A0346">5A7DD0DA0AEE0BDEDC14C1B7831B9CE9178A0346</a></li>

<li><a href="https://www.virustotal.com/gui/file/1ACC7A486B52C5EE6619DBDC3B4210B5F48B936F">1ACC7A486B52C5EE6619DBDC3B4210B5F48B936F</a></li>

<li><a href="https://www.virustotal.com/gui/file/55AB7E27412ECA433D76513EDC7E6E03BCDD7EDA">55AB7E27412ECA433D76513EDC7E6E03BCDD7EDA</a></li>

<li><a href="https://www.virustotal.com/gui/file/1E7C241B9A9EA79061B50FB19B3D141DEE175C27">1E7C241B9A9EA79061B50FB19B3D141DEE175C27</a></li>



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

[*source*](https://github.com/magicsword-io/LOLDrivers/tree/main/yaml/asio32.sys.yml)

*last_updated:* 2023-03-04


{{< /column >}}
{{< /block >}}
