+++

description = "https://learn.microsoft.com/en-us/windows/security/threat-protection/windows-defender-application-control/microsoft-recommended-driver-block-rules"
title = "asrdrv104.sys"
weight = 10

+++


{{< block "grid-1" >}}
{{< column "mt-2 pt-1">}}


# asrdrv104.sys

#### Description


asrdrv104.sys is a vulnerable driver and more information will be added as found.


- **Created**: 2023-01-09
- **Author**: Michael Haag
- **Acknowledgement**:  | [](https://twitter.com/)

#### Testing

```
sc.exe create asrdrv104.sys binPath= C:\windows\temp\asrdrv104.sys type= kernel
sc.exe start asrdrv104.sys
```

#### Resources
<br>


<li><a href=" https://learn.microsoft.com/en-us/windows/security/threat-protection/windows-defender-application-control/microsoft-recommended-driver-block-rules"> https://learn.microsoft.com/en-us/windows/security/threat-protection/windows-defender-application-control/microsoft-recommended-driver-block-rules</a></li>


<br>


#### Binary Metadata
<br>



<li><a href="https://www.virustotal.com/gui/file/6C1BB3A72EBFB5359B9E22CA44D0A1FF825A68F2">6C1BB3A72EBFB5359B9E22CA44D0A1FF825A68F2</a></li>

<li><a href="https://www.virustotal.com/gui/file/E039C9DD21494DBD073B4823FC3A17FBB951EC6C">E039C9DD21494DBD073B4823FC3A17FBB951EC6C</a></li>

<li><a href="https://www.virustotal.com/gui/file/7EEC3A1EDF3B021883A4B5DA450DB63F7C0AFEEB">7EEC3A1EDF3B021883A4B5DA450DB63F7C0AFEEB</a></li>

<li><a href="https://www.virustotal.com/gui/file/E5021A98E55D514E2376AA573D143631E5EE1C13">E5021A98E55D514E2376AA573D143631E5EE1C13</a></li>

<li><a href="https://www.virustotal.com/gui/file/729A8675665C61824F22F06C7B954BE4D14B52C4">729A8675665C61824F22F06C7B954BE4D14B52C4</a></li>

<li><a href="https://www.virustotal.com/gui/file/2B4D0DEAD4C1A7CC95543748B3565CFA802E5256">2B4D0DEAD4C1A7CC95543748B3565CFA802E5256</a></li>

<li><a href="https://www.virustotal.com/gui/file/4A7D66874A0472A47087FABAA033A85D47413379">4A7D66874A0472A47087FABAA033A85D47413379</a></li>



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

[*source*](https://github.com/magicsword-io/LOLDrivers/tree/main/yaml/asrdrv104.sys.yml)

*last_updated:* 2023-03-04


{{< /column >}}
{{< /block >}}
