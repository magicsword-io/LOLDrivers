+++

description = "https://learn.microsoft.com/en-us/windows/security/threat-protection/windows-defender-application-control/microsoft-recommended-driver-block-rules"
title = "bandai.sys"
weight = 10

+++


{{< block "grid-1" >}}
{{< column "mt-2 pt-1">}}


# bandai.sys

#### Description


bandai.sys is a vulnerable driver and more information will be added as found.


- **Created**: 2023-01-09
- **Author**: Michael Haag
- **Acknowledgement**:  | [](https://twitter.com/)

#### Testing

```
sc.exe create bandai.sys binPath= C:\windows\temp\bandai.sys type= kernel
sc.exe start bandai.sys
```

#### Resources
<br>


<li><a href=" https://learn.microsoft.com/en-us/windows/security/threat-protection/windows-defender-application-control/microsoft-recommended-driver-block-rules"> https://learn.microsoft.com/en-us/windows/security/threat-protection/windows-defender-application-control/microsoft-recommended-driver-block-rules</a></li>


<br>


#### Binary Metadata
<br>



<li><a href="https://www.virustotal.com/gui/file/0F780B7ADA5DD8464D9F2CC537D973F5AC804E9C">0F780B7ADA5DD8464D9F2CC537D973F5AC804E9C</a></li>

<li><a href="https://www.virustotal.com/gui/file/EA360A9F23BB7CF67F08B88E6A185A699F0C5410">EA360A9F23BB7CF67F08B88E6A185A699F0C5410</a></li>



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

[*source*](https://github.com/magicsword-io/LOLDrivers/tree/main/yaml/bandai.sys.yml)

*last_updated:* 2023-03-04


{{< /column >}}
{{< /block >}}
