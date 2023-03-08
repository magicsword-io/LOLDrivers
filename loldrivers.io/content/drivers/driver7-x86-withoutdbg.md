+++

description = "https://github.com/Chigusa0w0/AsusDriversPrivEscala"
title = "driver7-x86-withoutdbg.sys"
weight = 10

+++


{{< block "grid-1" >}}
{{< column "mt-2 pt-1">}}




# driver7-x86-withoutdbg.sys 


{{< tip "warning" >}}
We were not able to verify the hash of this driver successfully, it has not been confirmed.
{{< /tip >}}




### Description


driver7-x86-withoutdbg.sys is a vulnerable driver and more information will be added as found.


- **Created**: 2023-01-09
- **Author**: Michael Haag
- **Acknowledgement**:  | [](https://twitter.com/)

### Commands

| Use Case | Privilages | Operating System | 
|:---- | ---- | ---- |
| Elevate privileges | kernel | Windows 10 |

```
sc.exe create driver7-x86-withoutdbg.sys binPath=C:\windows\temp\driver7-x86-withoutdbg.sys type=kernel
sc.exe start driver7-x86-withoutdbg.sys
```

### Resources
<br>


<li><a href=" https://github.com/Chigusa0w0/AsusDriversPrivEscala"> https://github.com/Chigusa0w0/AsusDriversPrivEscala</a></li>


<br>


### Binary Metadata
<br>



<li><a href="https://www.virustotal.com/gui/file/927C2A580D51A598177FA54C65E9D2610F5F212F1B6CB2FBF2740B64368F010A">927C2A580D51A598177FA54C65E9D2610F5F212F1B6CB2FBF2740B64368F010A</a></li>



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

[*source*](https://github.com/magicsword-io/LOLDrivers/tree/main/yaml/driver7-x86-withoutdbg.sys.yml)

*last_updated:* 2023-03-07


{{< /column >}}
{{< /block >}}
