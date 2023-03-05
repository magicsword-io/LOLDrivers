+++

description = "https://learn.microsoft.com/en-us/windows/security/threat-protection/windows-defender-application-control/microsoft-recommended-driver-block-rules"
title = "GameTerSafe.sys"
weight = 10

+++


{{< block "grid-1" >}}
{{< column "mt-2 pt-1">}}


# GameTerSafe.sys

#### Description


GameTerSafe.sys is a vulnerable driver and more information will be added as found.


- **Created**: 2023-01-09
- **Author**: Michael Haag
- **Acknowledgement**:  | [](https://twitter.com/)

#### Testing

```
sc.exe create GameTerSafe.sys binPath= C:\windows\temp\GameTerSafe.sys type= kernel
sc.exe start GameTerSafe.sys
```

#### Resources
<br>


<li><a href=" https://learn.microsoft.com/en-us/windows/security/threat-protection/windows-defender-application-control/microsoft-recommended-driver-block-rules"> https://learn.microsoft.com/en-us/windows/security/threat-protection/windows-defender-application-control/microsoft-recommended-driver-block-rules</a></li>


<br>


#### Binary Metadata
<br>



<li><a href="https://www.virustotal.com/gui/file/3E9B62D2EA2BE50A2DA670746C4DBE807DB9601980AF3A1014BCD72D0248D84C">3E9B62D2EA2BE50A2DA670746C4DBE807DB9601980AF3A1014BCD72D0248D84C</a></li>



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

[*source*](https://github.com/magicsword-io/LOLDrivers/tree/main/yaml/gametersafe.sys.yml)

*last_updated:* 2023-03-04


{{< /column >}}
{{< /block >}}
