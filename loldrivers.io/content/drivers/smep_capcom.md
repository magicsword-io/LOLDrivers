+++

description = "https://github.com/namazso/physmem_drivers"
title = "smep_capcom.sys"
weight = 10

+++


{{< block "grid-1" >}}
{{< column "mt-2 pt-1">}}




# smep_capcom.sys ![:inline](/images/twitter_verified.png) 



### Description


smep_capcom.sys is a vulnerable driver and more information will be added as found.


- **Created**: 2023-01-09
- **Author**: Michael Haag
- **Acknowledgement**:  | [](https://twitter.com/)

### Commands

| Use Case | Privilages | Operating System | 
|:---- | ---- | ---- |
| Elevate privileges | kernel | Windows 10 |

```
sc.exe create smep_capcom.sys binPath=C:\windows\temp\smep_capcom.sys type=kernel
sc.exe start smep_capcom.sys
```

### Resources
<br>


<li><a href=" https://github.com/namazso/physmem_drivers"> https://github.com/namazso/physmem_drivers</a></li>


<br>


### Binary Metadata
<br>



<li><a href="https://www.virustotal.com/gui/file/DB2A9247177E8CDD50FE9433D066B86FFD2A84301AA6B2EB60F361CFFF077004">DB2A9247177E8CDD50FE9433D066B86FFD2A84301AA6B2EB60F361CFFF077004</a></li>



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

[*source*](https://github.com/magicsword-io/LOLDrivers/tree/main/yaml/smep_capcom.sys.yml)

*last_updated:* 2023-03-07


{{< /column >}}
{{< /block >}}
