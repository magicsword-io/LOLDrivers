+++

description = "https://raw.githubusercontent.com/SigmaHQ/sigma/master/rules/windows/driver_load/driver_load_vuln_drivers_names.yml"
title = "clfs.sys"
weight = 10

+++


{{< block "grid-1" >}}
{{< column "mt-2 pt-1">}}




# clfs.sys 


{{< tip "warning" >}}
We were not able to verify the hash of this driver successfully, it has not been confirmed.
{{< /tip >}}




### Description


clfs.sys is a vulnerable driver and more information will be added as found.


- **Created**: 2023-01-09
- **Author**: Michael Haag
- **Acknowledgement**:  | [](https://twitter.com/)

### Commands

| Use Case | Privilages | Operating System | 
|:---- | ---- | ---- |
| Elevate privileges | kernel | Windows 10 |

```
sc.exe create clfs.sys binPath=C:\windows\temp\clfs.sys type=kernel
sc.exe start clfs.sys
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

[*source*](https://github.com/magicsword-io/LOLDrivers/tree/main/yaml/clfs.sys.yml)

*last_updated:* 2023-03-06


{{< /column >}}
{{< /block >}}
