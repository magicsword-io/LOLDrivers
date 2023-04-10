+++

description = ""
title = "rwdrv.sys"
weight = 10

+++


{{< block "grid-1" >}}
{{< column "mt-2 pt-1">}}


# rwdrv.sys ![:inline](/images/twitter_verified.png) 


### Description

This utility access almost all the computer hardware, including PCI (PCI Express), PCI Index/Data, Memory, Memory Index/Data, I/O Space, I/O Index/Data, Super I/O, Clock Generator, DIMM SPD, SMBus Device, CPU MSR Registers, ATA/ATAPI Identify Data, Disk Read Write, ACPI Tables Dump (include AML decode), Embedded Controller, USB Information, SMBIOS Structures, PCI Option ROMs, MP Configuration Table, E820, EDID and Remote Access. And also a Command Window is provided to access hardware manually.


- **Created**: 2023-01-09
- **Author**: Michael Haag
- **Acknowledgement**:  | [](https://twitter.com/)

### Commands

```
sc.exe create rwdrv.sys binPath=C:\windows\temp\rwdrv.sys type=kernel &amp;&amp; sc.exe start rwdrv.sys
```

| Use Case | Privileges | Operating System | 
|:---- | ---- | ---- |
| Elevate privileges | kernel | Windows 10 |

### Resources
<br>
<li><a href=" https://github.com/jbaines-r7/dellicious"> https://github.com/jbaines-r7/dellicious</a></li>
<li><a href=" https://www.rapid7.com/blog/post/2021/12/13/driver-based-attacks-past-and-present/"> https://www.rapid7.com/blog/post/2021/12/13/driver-based-attacks-past-and-present/</a></li>
<li><a href="http://rweverything.com/">http://rweverything.com/</a></li>
<li><a href="https://github.com/jbaines-r7/dellicious and https://www.rapid7.com/blog/post/2021/12/13/driver-based-attacks-past-and-present/">https://github.com/jbaines-r7/dellicious and https://www.rapid7.com/blog/post/2021/12/13/driver-based-attacks-past-and-present/</a></li>
<br>

### Known Vulnerable Samples

| Filename | rwdrv.sys |
|:---- | ---- | 
| MD5 | <a href="https://www.virustotal.com/gui/file/257483d5d8b268d0d679956c7acdf02d">257483d5d8b268d0d679956c7acdf02d</a> |
| SHA1 | <a href="https://www.virustotal.com/gui/file/fbf8b0613a2f7039aeb9fa09bd3b40c8ff49ded2">fbf8b0613a2f7039aeb9fa09bd3b40c8ff49ded2</a> |
| SHA256 | <a href="https://www.virustotal.com/gui/file/ea0b9eecf4ad5ec8c14aec13de7d661e7615018b1a3c65464bf5eca9bbf6ded3">ea0b9eecf4ad5ec8c14aec13de7d661e7615018b1a3c65464bf5eca9bbf6ded3</a> |
| Signature | ChongKim Chan, GlobalSign CodeSigning CA - G2, GlobalSign Root CA - R1   |


[*source*](https://github.com/magicsword-io/LOLDrivers/tree/main/yaml/rwdrv.yaml)

*last_updated:* 2023-04-10








{{< /column >}}
{{< /block >}}
