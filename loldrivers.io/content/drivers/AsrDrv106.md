+++

description = "https://github.com/elastic/protections-artifacts/search?q=VulnDriver"
title = "AsrDrv106.sys"
weight = 10

+++


{{< block "grid-1" >}}
{{< column "mt-2 pt-1">}}




# AsrDrv106.sys 


{{< tip "warning" >}}
We were not able to verify the hash of this driver successfully, it has not been confirmed.
{{< /tip >}}




### Description


AsrDrv106.sys is a vulnerable driver and more information will be added as found.


- **Created**: 2023-01-09
- **Author**: Michael Haag
- **Acknowledgement**:  | [](https://twitter.com/)

### Commands

| Use Case | Privilages | Operating System | 
|:---- | ---- | ---- |
| Elevate privileges | kernel | Windows 10 |

```
sc.exe create AsrDrv106.sys binPath=C:\windows\temp\AsrDrv106.sys type=kernel
sc.exe start AsrDrv106.sys
```

### Resources
<br>


<li><a href=" https://github.com/elastic/protections-artifacts/search?q=VulnDriver"> https://github.com/elastic/protections-artifacts/search?q=VulnDriver</a></li>


<br>


### Binary Metadata
<br>



<li><a href="https://www.virustotal.com/gui/file/3943a796cc7c5352aa57ccf544295bfd6fb69aae147bc8235a00202dc6ed6838">3943a796cc7c5352aa57ccf544295bfd6fb69aae147bc8235a00202dc6ed6838</a></li>



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

[*source*](https://github.com/magicsword-io/LOLDrivers/tree/main/yaml/asrdrv106.sys.yml)

*last_updated:* 2023-03-06


{{< /column >}}
{{< /block >}}
