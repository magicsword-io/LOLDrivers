+++

description = "https://raw.githubusercontent.com/SigmaHQ/sigma/master/rules/windows/driver_load/driver_load_vuln_drivers_names.yml"
title = "PCADRVX64.sys"
weight = 10

+++


{{< block "grid-1" >}}
{{< column "mt-2 pt-1">}}




# PCADRVX64.sys 


{{< tip "warning" >}}
We were not able to verify the hash of this driver successfully, it has not been confirmed.
{{< /tip >}}




### Description


PCADRVX64.sys is a vulnerable driver and more information will be added as found.


- **Created**: 2023-01-09
- **Author**: Michael Haag
- **Acknowledgement**:  | [](https://twitter.com/)

### Commands

| Use Case | Privilages | Operating System | 
|:---- | ---- | ---- |
| Elevate privileges | kernel | Windows 10 |

```
sc.exe create PCADRVX64.sys binPath=C:\windows\temp\PCADRVX64.sys type=kernel
sc.exe start PCADRVX64.sys
```

### Resources
<br>


<li><a href=" https://raw.githubusercontent.com/SigmaHQ/sigma/master/rules/windows/driver_load/driver_load_vuln_drivers_names.yml"> https://raw.githubusercontent.com/SigmaHQ/sigma/master/rules/windows/driver_load/driver_load_vuln_drivers_names.yml</a></li>


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

[*source*](https://github.com/magicsword-io/LOLDrivers/tree/main/yaml/pcadrvx64.sys.yml)

*last_updated:* 2023-03-06


{{< /column >}}
{{< /block >}}
