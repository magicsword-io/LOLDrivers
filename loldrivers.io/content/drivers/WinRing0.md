+++

description = ""
title = "WinRing0.sys"
weight = 10

+++


{{< block "grid-1" >}}
{{< column "mt-2 pt-1">}}


# WinRing0.sys ![:inline](/images/twitter_verified.png) 


### Description

WinRing0.sys is a vulnerable driver and more information will be added as found.

- **Created**: 2023-01-09
- **Author**: Michael Haag
- **Acknowledgement**:  | [](https://twitter.com/)

{{< button "https://github.com/magicsword-io/LOLDrivers/raw/main/drivers/828bb9cb1dd449cd65a29b18ec46055f.bin" "Download" >}}
{{< tip "warning" >}}
This download link contains the vulnerable driver!

{{< /tip >}}

### Commands

```
sc.exe create WinRing0.sys binPath=C:\windows\temp\WinRing0.sys type=kernel &amp;&amp; sc.exe start WinRing0.sys
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
| Filename           | WinRing0.sys |
| MD5                | [828bb9cb1dd449cd65a29b18ec46055f](https://www.virustotal.com/gui/file/828bb9cb1dd449cd65a29b18ec46055f) |
| SHA1               | [558aad879b6a47d94a968f39d0a4e3a3aaef1ef1](https://www.virustotal.com/gui/file/558aad879b6a47d94a968f39d0a4e3a3aaef1ef1) |
| SHA256             | [3ec5ad51e6879464dfbccb9f4ed76c6325056a42548d5994ba869da9c4c039a8](https://www.virustotal.com/gui/file/3ec5ad51e6879464dfbccb9f4ed76c6325056a42548d5994ba869da9c4c039a8) |
| Authentihash MD5   | [650fa4b522e8d06d0cdfa4bf278e85f1](https://www.virustotal.com/gui/search/authentihash%253A650fa4b522e8d06d0cdfa4bf278e85f1) |
| Authentihash SHA1  | [dfe2533a4398d67dfc722eb8d9f8ffa3a823a721](https://www.virustotal.com/gui/search/authentihash%253Adfe2533a4398d67dfc722eb8d9f8ffa3a823a721) |
| Authentihash SHA256| [7188af66fe23bd8cf27f003ad6c7550cdb6faa5c948fe7c3b1435c9246345eb3](https://www.virustotal.com/gui/search/authentihash%253A7188af66fe23bd8cf27f003ad6c7550cdb6faa5c948fe7c3b1435c9246345eb3) |
| Signature         | TOSHIBA AMERICA INFORMATION SYSTEMS, INC., VeriSign Class 3 Code Signing 2004 CA, VeriSign Class 3 Public Primary CA   |
| Company           | OpenLibSys.org |
| Description       | WinRing0 |
| Product           | WinRing0 |
| OriginalFilename  | WinRing0.sys |


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
| Filename           | WinRing0.sys |
| MD5                | [12cecc3c14160f32b21279c1a36b8338](https://www.virustotal.com/gui/file/12cecc3c14160f32b21279c1a36b8338) |
| SHA1               | [7fb52290883a6b69a96d480f2867643396727e83](https://www.virustotal.com/gui/file/7fb52290883a6b69a96d480f2867643396727e83) |
| SHA256             | [47eaebc920ccf99e09fc9924feb6b19b8a28589f52783327067c9b09754b5e84](https://www.virustotal.com/gui/file/47eaebc920ccf99e09fc9924feb6b19b8a28589f52783327067c9b09754b5e84) |
| Authentihash MD5   | [650fa4b522e8d06d0cdfa4bf278e85f1](https://www.virustotal.com/gui/search/authentihash%253A650fa4b522e8d06d0cdfa4bf278e85f1) |
| Authentihash SHA1  | [dfe2533a4398d67dfc722eb8d9f8ffa3a823a721](https://www.virustotal.com/gui/search/authentihash%253Adfe2533a4398d67dfc722eb8d9f8ffa3a823a721) |
| Authentihash SHA256| [7188af66fe23bd8cf27f003ad6c7550cdb6faa5c948fe7c3b1435c9246345eb3](https://www.virustotal.com/gui/search/authentihash%253A7188af66fe23bd8cf27f003ad6c7550cdb6faa5c948fe7c3b1435c9246345eb3) |
| Signature         | Noriyuki MIYAZAKI, GlobalSign ObjectSign CA, GlobalSign Primary Object Publishing CA, GlobalSign Root CA - R1   |
| Company           | OpenLibSys.org |
| Description       | WinRing0 |
| Product           | WinRing0 |
| OriginalFilename  | WinRing0.sys |


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
| Filename           | WinRing0.sys |
| MD5                | [27bcbeec8a466178a6057b64bef66512](https://www.virustotal.com/gui/file/27bcbeec8a466178a6057b64bef66512) |
| SHA1               | [012db3a80faf1f7f727b538cbe5d94064e7159de](https://www.virustotal.com/gui/file/012db3a80faf1f7f727b538cbe5d94064e7159de) |
| SHA256             | [a7b000abbcc344444a9b00cfade7aa22ab92ce0cadec196c30eb1851ae4fa062](https://www.virustotal.com/gui/file/a7b000abbcc344444a9b00cfade7aa22ab92ce0cadec196c30eb1851ae4fa062) |
| Authentihash MD5   | [c4355451eccb590e5e6d817760d2d2ef](https://www.virustotal.com/gui/search/authentihash%253Ac4355451eccb590e5e6d817760d2d2ef) |
| Authentihash SHA1  | [7aed8186977fcf7ee219da493baecdb95ec8040d](https://www.virustotal.com/gui/search/authentihash%253A7aed8186977fcf7ee219da493baecdb95ec8040d) |
| Authentihash SHA256| [9305f0834e67aa16fb252bd30927e5f835639ef4b868f20d232260edffefd6f0](https://www.virustotal.com/gui/search/authentihash%253A9305f0834e67aa16fb252bd30927e5f835639ef4b868f20d232260edffefd6f0) |
| Signature         | EVGA, VeriSign Class 3 Code Signing 2010 CA, VeriSign   |
| Company           | OpenLibSys.org |
| Description       | WinRing0 |
| Product           | WinRing0 |
| OriginalFilename  | WinRing0.sys |


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



[*source*](https://github.com/magicsword-io/LOLDrivers/tree/main/yaml/winring0.yaml)

*last_updated:* 2023-05-06








{{< /column >}}
{{< /block >}}
