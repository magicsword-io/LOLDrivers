+++

description = "https://learn.microsoft.com/en-us/windows/security/threat-protection/windows-defender-application-control/microsoft-recommended-driver-block-rules"
title = "dbutil.sys"
weight = 10

+++


{{< block "grid-1" >}}
{{< column "mt-2 pt-1">}}




# dbutil.sys 


{{< tip "warning" >}}
We were not able to verify the hash of this driver successfully, it has not been confirmed.
{{< /tip >}}




### Description


dbutil.sys is a vulnerable driver and more information will be added as found.


- **Created**: 2023-01-09
- **Author**: Michael Haag
- **Acknowledgement**:  | [](https://twitter.com/)

### Commands

| Use Case | Privilages | Operating System | 
|:---- | ---- | ---- |
| Elevate privileges | kernel | Windows 10 |

```
sc.exe create dbutil.sys binPath=C:\windows\temp\dbutil.sys type=kernel
sc.exe start dbutil.sys
```

### Resources
<br>


<li><a href=" https://learn.microsoft.com/en-us/windows/security/threat-protection/windows-defender-application-control/microsoft-recommended-driver-block-rules"> https://learn.microsoft.com/en-us/windows/security/threat-protection/windows-defender-application-control/microsoft-recommended-driver-block-rules</a></li>


<br>


### Binary Metadata
<br>



<li><a href="https://www.virustotal.com/gui/file/485C0B9710A196C7177B99EE95E5DDB35B26DDD1">485C0B9710A196C7177B99EE95E5DDB35B26DDD1</a></li>

<li><a href="https://www.virustotal.com/gui/file/ 50E2BC41F0186FDCE970B80E2A2CB296353AF586"> 50E2BC41F0186FDCE970B80E2A2CB296353AF586</a></li>

<li><a href="https://www.virustotal.com/gui/file/ E3C1DD569AA4758552566B0213EE4D1FE6382C4B"> E3C1DD569AA4758552566B0213EE4D1FE6382C4B</a></li>

<li><a href="https://www.virustotal.com/gui/file/ E09B5E80805B8FE853EA27D8773E31BFF262E3F7"> E09B5E80805B8FE853EA27D8773E31BFF262E3F7</a></li>



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

[*source*](https://github.com/magicsword-io/LOLDrivers/tree/main/yaml/dbutil.sys.yml)

*last_updated:* 2023-03-06


{{< /column >}}
{{< /block >}}
