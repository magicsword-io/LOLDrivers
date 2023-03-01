+++

description = "https://github.com/namazso/physmem_drivers"
title = "WINIODrv.sys"
weight = 10

+++


{{< block "grid-1" >}}
{{< column "mt-2 pt-1">}}


# WINIODrv.sys

#### Description

WINIODrv.sys is a vulnerable driver.

- **Created**: 2023-01-09
- **Author**: Michael Haag
- **Acknowledgement**:  | [](https://twitter.com/)

#### Command

```
sc.exe create WINIODrv binPath= C:\windows\temp\WINIODrv.sys type= kernel
sc.exe start WINIODrv.sys
```

#### Resources
<br>


<li><a href=" https://github.com/namazso/physmem_drivers"> https://github.com/namazso/physmem_drivers</a></li>


<br>


#### Binary Metadata
<br>



<li><a href="https://www.virustotal.com/gui/file/3243AAB18E273A9B9C4280A57AECEF278E10BFFF19ABB260D7A7820E41739099">3243AAB18E273A9B9C4280A57AECEF278E10BFFF19ABB260D7A7820E41739099</a></li>

<li><a href="https://www.virustotal.com/gui/file/7CFA5E10DFF8A99A5D544B011F676BC383991274C693E21E3AF40CF6982ADB8C">7CFA5E10DFF8A99A5D544B011F676BC383991274C693E21E3AF40CF6982ADB8C</a></li>

<li><a href="https://www.virustotal.com/gui/file/C9B49B52B493B53CD49C12C3FA9553E57C5394555B64E32D1208F5B96A5B8C6E">C9B49B52B493B53CD49C12C3FA9553E57C5394555B64E32D1208F5B96A5B8C6E</a></li>



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

[*source*](https://github.com/magicsword-io/LOLDrivers/tree/main/yaml/winiodrv.sys.yml)

*last_updated:* 2023-02-28


{{< /column >}}
{{< /block >}}
