+++

description = ""
title = "HwRwDrv.sys"
weight = 10

+++


{{< block "grid-1" >}}
{{< column "mt-2 pt-1">}}


# HwRwDrv.sys ![:inline](/images/twitter_verified.png) 


### Description

HwRwDrv.sys is a vulnerable driver and more information will be added as found.

- **Created**: 2023-01-09
- **Author**: Michael Haag
- **Acknowledgement**:  | [](https://twitter.com/)

{{< button "https://github.com/magicsword-io/LOLDrivers/raw/main/drivers/dbc415304403be25ac83047c170b0ec2.bin" "Download" >}}
{{< tip "warning" >}}
This download link contains the vulnerable driver!

{{< /tip >}}

### Commands

```
sc.exe create HwRwDrv.sys binPath=C:\windows\temp\HwRwDrv.sys type=kernel &amp;&amp; sc.exe start HwRwDrv.sys
```

| Use Case | Privileges | Operating System | 
|:---- | ---- | ---- |
| Elevate privileges | kernel | Windows 10 |

### Resources
<br>
<li><a href=" https://github.com/namazso/physmem_drivers"> https://github.com/namazso/physmem_drivers</a></li>
<li><a href="https://github.com/namazso/physmem_drivers">https://github.com/namazso/physmem_drivers</a></li>
<br>

### Known Vulnerable Samples

| Property           | Value |
|:-------------------|:------|
| Filename           | HwRwDrv.sys |
| MD5                | [dbc415304403be25ac83047c170b0ec2](https://www.virustotal.com/gui/file/dbc415304403be25ac83047c170b0ec2) |
| SHA1               | [2b0bb408ff0e66bcdf6574f1ca52cbf4015b257b](https://www.virustotal.com/gui/file/2b0bb408ff0e66bcdf6574f1ca52cbf4015b257b) |
| SHA256             | [21ccdd306b5183c00ecfd0475b3152e7d94b921e858e59b68a03e925d1715f21](https://www.virustotal.com/gui/file/21ccdd306b5183c00ecfd0475b3152e7d94b921e858e59b68a03e925d1715f21) |
| Authentihash MD5   | [62d9c8a109afc08e2858d98df9776850](https://www.virustotal.com/gui/search/authentihash%253A62d9c8a109afc08e2858d98df9776850) |
| Authentihash SHA1  | [7beb26c59b8d1b9540c6fae7c05c2b1cc2537e54](https://www.virustotal.com/gui/search/authentihash%253A7beb26c59b8d1b9540c6fae7c05c2b1cc2537e54) |
| Authentihash SHA256| [d852810a7319e3249077a1b9f1317f6f4157a19bb99b90063d118c30c2c84ac2](https://www.virustotal.com/gui/search/authentihash%253Ad852810a7319e3249077a1b9f1317f6f4157a19bb99b90063d118c30c2c84ac2) |
| Publisher         | Shuttle Inc. |
| Signature         | Shuttle Inc., VeriSign Class 3 Code Signing 2010 CA, VeriSign   |
| Company           | Windows® winows 7 driver kits provider |
| Description       | Hardware read &amp; write driver |
| Product           | Hardware read &amp; write driver |
| OriginalFilename  | HwRwDrv.sys |


#### Imports
{{< details "Expand" >}}
* ntoskrnl.exe
* HAL.dll

{{< /details >}}
#### ImportedFunctions
{{< details "Expand" >}}
* MmUnmapIoSpace
* MmMapIoSpace
* IofCompleteRequest
* IoDeleteDevice
* IoCreateDevice
* KeBugCheckEx
* RtlInitUnicodeString
* IoCreateSymbolicLink
* IoDeleteSymbolicLink
* __C_specific_handler
* HalSetBusDataByOffset
* HalGetBusDataByOffset

{{< /details >}}
#### ExportedFunctions
{{< details "Expand" >}}

{{< /details >}}
-----



[*source*](https://github.com/magicsword-io/LOLDrivers/tree/main/yaml/hwrwdrv.yaml)

*last_updated:* 2023-04-20








{{< /column >}}
{{< /block >}}
