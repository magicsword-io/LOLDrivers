+++

description = "https://github.com/jbaines-r7/dellicious and https://www.rapid7.com/blog/post/2021/12/13/driver-based-attacks-past-and-present/"
title = "rwdrv.sys"
weight = 10

+++


{{< block "grid-1" >}}
{{< column "mt-2 pt-1">}}


# rwdrv.sys

#### Description

This utility access almost all the computer hardware, including PCI (PCI Express), PCI Index/Data, Memory, Memory Index/Data, I/O Space, I/O Index/Data, Super I/O, Clock Generator, DIMM SPD, SMBus Device, CPU MSR Registers, ATA/ATAPI Identify Data, Disk Read Write, ACPI Tables Dump (include AML decode), Embedded Controller, USB Information, SMBIOS Structures, PCI Option ROMs, MP Configuration Table, E820, EDID and Remote Access. And also a Command Window is provided to access hardware manually.



- **Created**: 2023-01-09
- **Author**: Michael Haag
- **Acknowledgement**:  | [](https://twitter.com/)

#### Command

```
sc.exe create rwdrv binPath= C:\windows\temp\rwdrv.sys type= kernel
sc.exe start rwdrv.sys
```

#### Resources
<br>


<li><a href=" https://github.com/jbaines-r7/dellicious"> https://github.com/jbaines-r7/dellicious</a></li>

<li><a href=" https://www.rapid7.com/blog/post/2021/12/13/driver-based-attacks-past-and-present/"> https://www.rapid7.com/blog/post/2021/12/13/driver-based-attacks-past-and-present/</a></li>

<li><a href="http://rweverything.com/">http://rweverything.com/</a></li>


<br>


#### Binary Metadata
<br>



<li><a href="https://www.virustotal.com/gui/file/ea0b9eecf4ad5ec8c14aec13de7d661e7615018b1a3c65464bf5eca9bbf6ded3">ea0b9eecf4ad5ec8c14aec13de7d661e7615018b1a3c65464bf5eca9bbf6ded3</a></li>



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

[*source*](https://github.com/magicsword-io/LOLDrivers/tree/main/yaml/rwdrv.sys.yml)

*last_updated:* 2023-02-28


{{< /column >}}
{{< /block >}}
