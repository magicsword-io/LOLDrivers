+++

description = "https://learn.microsoft.com/en-us/windows/security/threat-protection/windows-defender-application-control/microsoft-recommended-driver-block-rules"
title = "windows8-10-32.sys"
weight = 10

+++


{{< block "grid-1" >}}
{{< column "mt-2 pt-1">}}


# windows8-10-32.sys

#### Description


windows8-10-32.sys is a vulnerable driver and more information will be added as found.


- **Created**: 2023-01-09
- **Author**: Michael Haag
- **Acknowledgement**:  | [](https://twitter.com/)

#### Testing

```
sc.exe create windows8-10-32.sys binPath= C:\windows\temp\windows8-10-32.sys type= kernel
sc.exe start windows8-10-32.sys
```

#### Resources
<br>


<li><a href=" https://learn.microsoft.com/en-us/windows/security/threat-protection/windows-defender-application-control/microsoft-recommended-driver-block-rules"> https://learn.microsoft.com/en-us/windows/security/threat-protection/windows-defender-application-control/microsoft-recommended-driver-block-rules</a></li>


<br>


#### Binary Metadata
<br>



<li><a href="https://www.virustotal.com/gui/file/5B9623DA9BA8E5C80C49473F40FFE7AD315DCADFFC3230AFDC9D9226D60A715A">5B9623DA9BA8E5C80C49473F40FFE7AD315DCADFFC3230AFDC9D9226D60A715A</a></li>



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

[*source*](https://github.com/magicsword-io/LOLDrivers/tree/main/yaml/windows8-10-32.sys.yml)

*last_updated:* 2023-03-04


{{< /column >}}
{{< /block >}}
