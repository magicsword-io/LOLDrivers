+++

description = "https://learn.microsoft.com/en-us/windows/security/threat-protection/windows-defender-application-control/microsoft-recommended-driver-block-rules"
title = "fiddrv64.sys"
weight = 10

+++


{{< block "grid-1" >}}
{{< column "mt-2 pt-1">}}




# fiddrv64.sys 


{{< tip "warning" >}}
We were not able to verify the hash of this driver successfully, it has not been confirmed.
{{< /tip >}}




### Description


fiddrv64.sys is a vulnerable driver and more information will be added as found.


- **Created**: 2023-01-09
- **Author**: Michael Haag
- **Acknowledgement**:  | [](https://twitter.com/)

### Commands

| Use Case | Privilages | Operating System | 
|:---- | ---- | ---- |
| Elevate privileges | kernel | Windows 10 |

```
sc.exe create fiddrv64.sys binPath=C:\windows\temp\fiddrv64.sys type=kernel
sc.exe start fiddrv64.sys
```

### Resources
<br>


<li><a href=" https://learn.microsoft.com/en-us/windows/security/threat-protection/windows-defender-application-control/microsoft-recommended-driver-block-rules"> https://learn.microsoft.com/en-us/windows/security/threat-protection/windows-defender-application-control/microsoft-recommended-driver-block-rules</a></li>


<br>


### Binary Metadata
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

*last_updated:* 2023-03-06


{{< /column >}}
{{< /block >}}
