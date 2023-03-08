+++

description = "https://learn.microsoft.com/en-us/windows/security/threat-protection/windows-defender-application-control/microsoft-recommended-driver-block-rules"
title = "AsrSetupDrv103.sys"
weight = 10

+++


{{< block "grid-1" >}}
{{< column "mt-2 pt-1">}}




# AsrSetupDrv103.sys 


{{< tip "warning" >}}
We were not able to verify the hash of this driver successfully, it has not been confirmed.
{{< /tip >}}




### Description


AsrSetupDrv103.sys is a vulnerable driver and more information will be added as found.


- **Created**: 2023-01-09
- **Author**: Michael Haag
- **Acknowledgement**:  | [](https://twitter.com/)

### Commands

| Use Case | Privilages | Operating System | 
|:---- | ---- | ---- |
| Elevate privileges | kernel | Windows 10 |

```
sc.exe create AsrSetupDrv103.sys binPath=C:\windows\temp\AsrSetupDrv103.sys type=kernel
sc.exe start AsrSetupDrv103.sys
```

### Resources
<br>


<li><a href=" https://learn.microsoft.com/en-us/windows/security/threat-protection/windows-defender-application-control/microsoft-recommended-driver-block-rules"> https://learn.microsoft.com/en-us/windows/security/threat-protection/windows-defender-application-control/microsoft-recommended-driver-block-rules</a></li>


<br>


### Binary Metadata
<br>



<li><a href="https://www.virustotal.com/gui/file/0B6EC2AEDC518849A1C61A70B1F9FB068EDE2BC3">0B6EC2AEDC518849A1C61A70B1F9FB068EDE2BC3</a></li>

<li><a href="https://www.virustotal.com/gui/file/461882BD59887617CADC1C7B2B22D0A45458C070">461882BD59887617CADC1C7B2B22D0A45458C070</a></li>

<li><a href="https://www.virustotal.com/gui/file/A7948A4E9A3A1A9ED0E4E41350E422464D8313CD">A7948A4E9A3A1A9ED0E4E41350E422464D8313CD</a></li>

<li><a href="https://www.virustotal.com/gui/file/F3CCE7E79AB5BD055F311BB3AC44A838779270B6">F3CCE7E79AB5BD055F311BB3AC44A838779270B6</a></li>



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

[*source*](https://github.com/magicsword-io/LOLDrivers/tree/main/yaml/asrsetupdrv103.sys.yml)

*last_updated:* 2023-03-07


{{< /column >}}
{{< /block >}}
