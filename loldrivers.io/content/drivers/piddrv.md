+++

description = "https://learn.microsoft.com/en-us/windows/security/threat-protection/windows-defender-application-control/microsoft-recommended-driver-block-rules"
title = "piddrv.sys"
weight = 10

+++


{{< block "grid-1" >}}
{{< column "mt-2 pt-1">}}


# piddrv.sys

#### Description


piddrv.sys is a vulnerable driver and more information will be added as found.


- **Created**: 2023-01-09
- **Author**: Michael Haag
- **Acknowledgement**:  | [](https://twitter.com/)

#### Testing

```
sc.exe create piddrv.sys binPath= C:\windows\temp\piddrv.sys type= kernel
sc.exe start piddrv.sys
```

#### Resources
<br>


<li><a href=" https://learn.microsoft.com/en-us/windows/security/threat-protection/windows-defender-application-control/microsoft-recommended-driver-block-rules"> https://learn.microsoft.com/en-us/windows/security/threat-protection/windows-defender-application-control/microsoft-recommended-driver-block-rules</a></li>


<br>


#### Binary Metadata
<br>



<li><a href="https://www.virustotal.com/gui/file/A7D827A41B2C4B7638495CD1D77926F1BA902978">A7D827A41B2C4B7638495CD1D77926F1BA902978</a></li>

<li><a href="https://www.virustotal.com/gui/file/ 877C6C36A155109888FE1F9797B93CB30B4957EF"> 877C6C36A155109888FE1F9797B93CB30B4957EF</a></li>



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

[*source*](https://github.com/magicsword-io/LOLDrivers/tree/main/yaml/piddrv.sys.yml)

*last_updated:* 2023-03-04


{{< /column >}}
{{< /block >}}
