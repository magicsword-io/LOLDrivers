+++

description = "https://github.com/Chigusa0w0/AsusDriversPrivEscala"
title = "driver7-x86.sys"
weight = 10

+++


{{< block "grid-1" >}}
{{< column "mt-2 pt-1">}}




# driver7-x86.sys 


{{< tip "warning" >}}
We were not able to verify the hash of this driver successfully, it has not been confirmed.
{{< /tip >}}




### Description


driver7-x86.sys is a vulnerable driver and more information will be added as found.


- **Created**: 2023-01-09
- **Author**: Michael Haag
- **Acknowledgement**:  | [](https://twitter.com/)

### Commands

| Use Case | Privilages | Operating System | 
|:---- | ---- | ---- |
| Elevate privileges | kernel | Windows 10 |

```
sc.exe create driver7-x86.sys binPath=C:\windows\temp\driver7-x86.sys type=kernel
sc.exe start driver7-x86.sys
```

### Resources
<br>


<li><a href=" https://github.com/Chigusa0w0/AsusDriversPrivEscala"> https://github.com/Chigusa0w0/AsusDriversPrivEscala</a></li>


<br>


### Binary Metadata
<br>



<li><a href="https://www.virustotal.com/gui/file/42851A01469BA97CDC38939B10CF9EA13237AA1F6C37B1AC84904C5A12A81FA0">42851A01469BA97CDC38939B10CF9EA13237AA1F6C37B1AC84904C5A12A81FA0</a></li>



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

[*source*](https://github.com/magicsword-io/LOLDrivers/tree/main/yaml/driver7-x86.sys.yml)

*last_updated:* 2023-03-07


{{< /column >}}
{{< /block >}}
