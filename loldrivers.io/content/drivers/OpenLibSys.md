+++

description = ""
title = "OpenLibSys.sys"
weight = 10

+++


{{< block "grid-1" >}}
{{< column "mt-2 pt-1">}}


# OpenLibSys.sys ![:inline](/images/twitter_verified.png) 


### Description

OpenLibSys.sys is a vulnerable driver and more information will be added as found.

- **Created**: 2023-01-09
- **Author**: Michael Haag
- **Acknowledgement**:  | [](https://twitter.com/)

{{< button "https://github.com/magicsword-io/LOLDrivers/raw/main/drivers/ccf523b951afaa0147f22e2a7aae4976.bin" "Download" >}}
{{< tip "warning" >}}
This download link contains the vulnerable driver!

{{< /tip >}}

### Commands

```
sc.exe create OpenLibSys.sys binPath=C:\windows\temp\OpenLibSys.sys type=kernel &amp;&amp; sc.exe start OpenLibSys.sys
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
| Filename           | OpenLibSys.sys |
| MD5                | [ccf523b951afaa0147f22e2a7aae4976](https://www.virustotal.com/gui/file/ccf523b951afaa0147f22e2a7aae4976) |
| SHA1               | [ac600a2bc06b312d92e649b7b55e3e91e9d63451](https://www.virustotal.com/gui/file/ac600a2bc06b312d92e649b7b55e3e91e9d63451) |
| SHA256             | [91314768da140999e682d2a290d48b78bb25a35525ea12c1b1f9634d14602b2c](https://www.virustotal.com/gui/file/91314768da140999e682d2a290d48b78bb25a35525ea12c1b1f9634d14602b2c) |
| Authentihash MD5   | [1244664c7917f03f2b43b30e132f64b5](https://www.virustotal.com/gui/search/authentihash%253A1244664c7917f03f2b43b30e132f64b5) |
| Authentihash SHA1  | [d6f015693e56a3ebba725a6591cc07443d0e1661](https://www.virustotal.com/gui/search/authentihash%253Ad6f015693e56a3ebba725a6591cc07443d0e1661) |
| Authentihash SHA256| [db68a9cbe22b22cba782592eef76e63e080ee8d30943be6da694701f44b6c33e](https://www.virustotal.com/gui/search/authentihash%253Adb68a9cbe22b22cba782592eef76e63e080ee8d30943be6da694701f44b6c33e) |
| Signature         | Noriyuki MIYAZAKI, GlobalSign ObjectSign CA, GlobalSign Primary Object Publishing CA, GlobalSign Root CA - R1   |
| Company           | OpenLibSys.org |
| Description       | OpenLibSys |
| Product           | OpenLibSys |
| OriginalFilename  | OpenLibSys.sys |


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
| Property           | Value |
|:-------------------|:------|
| Filename           | OpenLibSys.sys |
| MD5                | [96421b56dbda73e9b965f027a3bda7ba](https://www.virustotal.com/gui/file/96421b56dbda73e9b965f027a3bda7ba) |
| SHA1               | [da9cea92f996f938f699902482ac5313d5e8b28e](https://www.virustotal.com/gui/file/da9cea92f996f938f699902482ac5313d5e8b28e) |
| SHA256             | [f0605dda1def240dc7e14efa73927d6c6d89988c01ea8647b671667b2b167008](https://www.virustotal.com/gui/file/f0605dda1def240dc7e14efa73927d6c6d89988c01ea8647b671667b2b167008) |
| Authentihash MD5   | [bd94d3a0abc78f87147bf8ea41aad734](https://www.virustotal.com/gui/search/authentihash%253Abd94d3a0abc78f87147bf8ea41aad734) |
| Authentihash SHA1  | [7ecbd5098c4161b95dd7e674003dd53069374f3e](https://www.virustotal.com/gui/search/authentihash%253A7ecbd5098c4161b95dd7e674003dd53069374f3e) |
| Authentihash SHA256| [6f3937451f0170a0aec3033cadceeb86ab30ee3c67add3926e116ccc20c0d9a7](https://www.virustotal.com/gui/search/authentihash%253A6f3937451f0170a0aec3033cadceeb86ab30ee3c67add3926e116ccc20c0d9a7) |
| Signature         | Noriyuki MIYAZAKI, GlobalSign ObjectSign CA, GlobalSign Primary Object Publishing CA, GlobalSign Root CA - R1   |
| Company           | OpenLibSys.org |
| Description       | OpenLibSys |
| Product           | OpenLibSys |
| OriginalFilename  | OpenLibSys.sys |


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



[*source*](https://github.com/magicsword-io/LOLDrivers/tree/main/yaml/openlibsys.yaml)

*last_updated:* 2023-04-22








{{< /column >}}
{{< /block >}}
