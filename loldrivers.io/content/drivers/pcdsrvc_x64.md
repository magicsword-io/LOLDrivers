+++

description = "https://github.com/elastic/protections-artifacts/search?q=VulnDriver"
title = "pcdsrvc_x64.pkms"
weight = 10

+++


{{< block "grid-1" >}}
{{< column "mt-2 pt-1">}}




# pcdsrvc_x64.pkms 


{{< tip "warning" >}}
We were not able to verify the hash of this driver successfully, it has not been confirmed.
{{< /tip >}}




### Description


CapCom.sys is a vulnerable driver that has been abused over the years.


- **Created**: 2023-01-09
- **Author**: Michael Haag
- **Acknowledgement**:  | [](https://twitter.com/)

### Commands

| Use Case | Privilages | Operating System | 
|:---- | ---- | ---- |
| Elevate privileges | kernel | Windows 10 |

```
sc.exe create AsrDrv103 binPath= C:\windows\temp\AsrDrv103.sys type= kernel
sc.exe start AsrDrv103.sys
```

### Resources
<br>


<li><a href=" https://github.com/elastic/protections-artifacts/search?q=VulnDriver"> https://github.com/elastic/protections-artifacts/search?q=VulnDriver</a></li>


<br>


### Binary Metadata
<br>



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

[*source*](https://github.com/magicsword-io/LOLDrivers/tree/main/yaml/pcdsrvc_x64.pkms.yml)

*last_updated:* 2023-03-06


{{< /column >}}
{{< /block >}}
