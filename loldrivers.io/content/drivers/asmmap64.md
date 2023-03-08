+++

description = "https://github.com/namazso/physmem_drivers"
title = "asmmap64.sys"
weight = 10

+++


{{< block "grid-1" >}}
{{< column "mt-2 pt-1">}}




# asmmap64.sys 


{{< tip "warning" >}}
We were not able to verify the hash of this driver successfully, it has not been confirmed.
{{< /tip >}}




### Description


asmmap64.sys is a vulnerable driver and more information will be added as found.


- **Created**: 2023-01-09
- **Author**: Michael Haag
- **Acknowledgement**:  | [](https://twitter.com/)

### Commands

| Use Case | Privilages | Operating System | 
|:---- | ---- | ---- |
| Elevate privileges | kernel | Windows 10 |

```
sc.exe create asmmap64.sys binPath=C:\windows\temp\asmmap64.sys type=kernel
sc.exe start asmmap64.sys
```

### Resources
<br>


<li><a href=" https://github.com/namazso/physmem_drivers"> https://github.com/namazso/physmem_drivers</a></li>


<br>


### Binary Metadata
<br>



<li><a href="https://www.virustotal.com/gui/file/025E7BE9FCEFD6A83F4471BBA0C11F1C11BD5047047D26626DA24EE9A419CDC4">025E7BE9FCEFD6A83F4471BBA0C11F1C11BD5047047D26626DA24EE9A419CDC4</a></li>



- binary: 
- Verified: 
- Date: 
- Publisher: ASUSTeK Computer Inc.
- Company: 
- Description: Memory mapping Driver
- Product: 
- ProductVersion: 
- FileVersion: 
- MachineType: 
- OriginalFilename: 

[*source*](https://github.com/magicsword-io/LOLDrivers/tree/main/yaml/asmmap64.sys.yml)

*last_updated:* 2023-03-07


{{< /column >}}
{{< /block >}}
