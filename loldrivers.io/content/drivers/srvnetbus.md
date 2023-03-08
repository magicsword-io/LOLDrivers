+++

description = "https://github.com/elastic/protections-artifacts/search?q=VulnDriver"
title = "srvnetbus.sys"
weight = 10

+++


{{< block "grid-1" >}}
{{< column "mt-2 pt-1">}}




# srvnetbus.sys 


{{< tip "warning" >}}
We were not able to verify the hash of this driver successfully, it has not been confirmed.
{{< /tip >}}




### Description


This has been referenced as a vulnerable driver, but no hash has been found.


- **Created**: 2023-01-09
- **Author**: Michael Haag
- **Acknowledgement**:  | [](https://twitter.com/)

### Commands

| Use Case | Privilages | Operating System | 
|:---- | ---- | ---- |
| Elevate privileges | kernel | Windows 10 |

```
sc.exe create srvnetbus.sys binPath=C:\windows\temp\srvnetbus.sys type=kernel
sc.exe start srvnetbus.sys
```

### Resources
<br>

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

[*source*](https://github.com/magicsword-io/LOLDrivers/tree/main/yaml/srvnetbus.sys.yml)

*last_updated:* 2023-03-07


{{< /column >}}
{{< /block >}}
