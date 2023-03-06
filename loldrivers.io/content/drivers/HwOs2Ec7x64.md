+++

description = "https://github.com/eclypsium/Screwed-Drivers/blob/master/DRIVERS.md"
title = "HwOs2Ec7x64.sys"
weight = 10

+++


{{< block "grid-1" >}}
{{< column "mt-2 pt-1">}}




# HwOs2Ec7x64.sys 


{{< tip "warning" >}}
We were not able to verify the hash of this driver successfully, it has not been confirmed.
{{< /tip >}}




### Description


HwOs2Ec7x64.sys is a vulnerable driver and more information will be added as found.


- **Created**: 2023-01-09
- **Author**: Michael Haag
- **Acknowledgement**:  | [](https://twitter.com/)

### Commands

| Use Case | Privilages | Operating System | 
|:---- | ---- | ---- |
| Elevate privileges | kernel | Windows 10 |

```
sc.exe create HwOs2Ec7x64.sys binPath=C:\windows\temp\HwOs2Ec7x64.sys type=kernel
sc.exe start HwOs2Ec7x64.sys
```

### Resources
<br>


<li><a href=" https://github.com/eclypsium/Screwed-Drivers/blob/master/DRIVERS.md"> https://github.com/eclypsium/Screwed-Drivers/blob/master/DRIVERS.md</a></li>


<br>


### Binary Metadata
<br>



<li><a href="https://www.virustotal.com/gui/file/b179e1ab6dc0b1aee783adbcad4ad6bb75a8a64cb798f30c0dd2ee8aaf43e6de">b179e1ab6dc0b1aee783adbcad4ad6bb75a8a64cb798f30c0dd2ee8aaf43e6de</a></li>



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

[*source*](https://github.com/magicsword-io/LOLDrivers/tree/main/yaml/hwos2ec7x64.sys.yml)

*last_updated:* 2023-03-06


{{< /column >}}
{{< /block >}}
