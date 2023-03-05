+++

description = "https://learn.microsoft.com/en-us/windows/security/threat-protection/windows-defender-application-control/microsoft-recommended-driver-block-rules"
title = "fiddrv64.sys"
weight = 10

+++


{{< block "grid-1" >}}
{{< column "mt-2 pt-1">}}


# fiddrv64.sys

#### Description


fiddrv64.sys is a vulnerable driver and more information will be added as found.


- **Created**: 2023-01-09
- **Author**: Michael Haag
- **Acknowledgement**:  | [](https://twitter.com/)

#### Testing

```
sc.exe create fiddrv64.sys binPath= C:\windows\temp\fiddrv64.sys type= kernel
sc.exe start fiddrv64.sys
```

#### Resources
<br>


<li><a href=" https://learn.microsoft.com/en-us/windows/security/threat-protection/windows-defender-application-control/microsoft-recommended-driver-block-rules"> https://learn.microsoft.com/en-us/windows/security/threat-protection/windows-defender-application-control/microsoft-recommended-driver-block-rules</a></li>


<br>


#### Binary Metadata
<br>



<li><a href="https://www.virustotal.com/gui/file/10E15BA8FF8ED926DDD3636CEC66A0F08C9860A4">10E15BA8FF8ED926DDD3636CEC66A0F08C9860A4</a></li>

<li><a href="https://www.virustotal.com/gui/file/E4436C8C42BA5FFABD58A3B2256F6E86CCC907AB">E4436C8C42BA5FFABD58A3B2256F6E86CCC907AB</a></li>



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

[*source*](https://github.com/magicsword-io/LOLDrivers/tree/main/yaml/fiddrv64.sys.yml)

*last_updated:* 2023-03-04


{{< /column >}}
{{< /block >}}
