+++

description = "https://learn.microsoft.com/en-us/windows/security/threat-protection/windows-defender-application-control/microsoft-recommended-driver-block-rules"
title = "ProtectS.sys"
weight = 10

+++


{{< block "grid-1" >}}
{{< column "mt-2 pt-1">}}




# ProtectS.sys 


{{< tip "warning" >}}
We were not able to verify the hash of this driver successfully, it has not been confirmed.
{{< /tip >}}




### Description


ProtectS.sys is a vulnerable driver and more information will be added as found.


- **Created**: 2023-01-09
- **Author**: Michael Haag
- **Acknowledgement**:  | [](https://twitter.com/)

### Commands

| Use Case | Privilages | Operating System | 
|:---- | ---- | ---- |
| Elevate privileges | kernel | Windows 10 |

```
sc.exe create ProtectS.sys binPath=C:\windows\temp\ProtectS.sys type=kernel
sc.exe start ProtectS.sys
```

### Resources
<br>


<li><a href=" https://learn.microsoft.com/en-us/windows/security/threat-protection/windows-defender-application-control/microsoft-recommended-driver-block-rules"> https://learn.microsoft.com/en-us/windows/security/threat-protection/windows-defender-application-control/microsoft-recommended-driver-block-rules</a></li>


<br>


### Binary Metadata
<br>



<li><a href="https://www.virustotal.com/gui/file/9D58F640C7295952B71BDCB456CAE37213BACCDCD3032C1E3AEB54E79081F395">9D58F640C7295952B71BDCB456CAE37213BACCDCD3032C1E3AEB54E79081F395</a></li>

<li><a href="https://www.virustotal.com/gui/file/4A9093E8DBCB867E1B97A0A67CE99A8511900658F5201C34FFB8035881F2DBBE">4A9093E8DBCB867E1B97A0A67CE99A8511900658F5201C34FFB8035881F2DBBE</a></li>



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

[*source*](https://github.com/magicsword-io/LOLDrivers/tree/main/yaml/protects.sys.yml)

*last_updated:* 2023-03-06


{{< /column >}}
{{< /block >}}
