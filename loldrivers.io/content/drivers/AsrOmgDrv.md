+++

description = ""
title = "AsrOmgDrv.sys"
weight = 10

+++


{{< block "grid-1" >}}
{{< column "mt-2 pt-1">}}


# AsrOmgDrv.sys ![:inline](/images/twitter_verified.png) 


### Description

AsrOmgDrv.sys is a vulnerable driver and more information will be added as found.

- **Created**: 2023-01-09
- **Author**: Michael Haag
- **Acknowledgement**:  | [](https://twitter.com/)

{{< button "https://github.com/magicsword-io/LOLDrivers/raw/main/drivers/4f27c09cc8680e06b04d6a9c34ca1e08.bin" "Download" >}}
{{< tip "warning" >}}
This download link contains the vulnerable driver!

{{< /tip >}}

### Commands

```
sc.exe create AsrOmgDrv.sys binPath=C:\windows\temp\AsrOmgDrv.sys type=kernel &amp;&amp; sc.exe start AsrOmgDrv.sys
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
| Filename           | AsrOmgDrv.sys |
| MD5                | [4f27c09cc8680e06b04d6a9c34ca1e08](https://www.virustotal.com/gui/file/4f27c09cc8680e06b04d6a9c34ca1e08) |
| SHA1               | [400f833dcc2ef0a122dd0e0b1ec4ec929340d90e](https://www.virustotal.com/gui/file/400f833dcc2ef0a122dd0e0b1ec4ec929340d90e) |
| SHA256             | [950a4c0c772021cee26011a92194f0e58d61588f77f2873aa0599dff52a160c9](https://www.virustotal.com/gui/file/950a4c0c772021cee26011a92194f0e58d61588f77f2873aa0599dff52a160c9) |
| Authentihash MD5   | [b39f71ca0eb035173a7f6c3dc7a43620](https://www.virustotal.com/gui/search/authentihash%253Ab39f71ca0eb035173a7f6c3dc7a43620) |
| Authentihash SHA1  | [045818bc05faf8fb2b7ccc60623f5a6f185d68c7](https://www.virustotal.com/gui/search/authentihash%253A045818bc05faf8fb2b7ccc60623f5a6f185d68c7) |
| Authentihash SHA256| [6c9dc878d9605070921338d09c6dbecbe11dec50c03fc69a0462884a07c2c442](https://www.virustotal.com/gui/search/authentihash%253A6c9dc878d9605070921338d09c6dbecbe11dec50c03fc69a0462884a07c2c442) |
| Publisher         | ASROCK Incorporation |
| Signature         | ASROCK Incorporation, VeriSign Class 3 Code Signing 2010 CA, VeriSign   |
| Company           | ASRock Incorporation |
| Description       | ASRock IO Driver |
| Product           | ASRock IO Driver |
| OriginalFilename  | AsrDrv.sys |


#### Imports
{{< details "Expand" >}}
* ntoskrnl.exe
* HAL.dll

{{< /details >}}
#### ImportedFunctions
{{< details "Expand" >}}
* IoDeleteSymbolicLink
* ExFreePoolWithTag
* MmFreeContiguousMemorySpecifyCache
* RtlInitUnicodeString
* IoDeleteDevice
* RtlQueryRegistryValues
* MmUnmapIoSpace
* IoFreeMdl
* MmGetPhysicalAddress
* IoBuildAsynchronousFsdRequest
* MmMapIoSpace
* IofCompleteRequest
* IoFreeIrp
* RtlCompareMemory
* MmUnlockPages
* IoCreateSymbolicLink
* IoCreateDevice
* MmAllocateContiguousMemorySpecifyCache
* IofCallDriver
* KeBugCheckEx
* ExAllocatePoolWithTag
* KeStallExecutionProcessor

{{< /details >}}
#### ExportedFunctions
{{< details "Expand" >}}

{{< /details >}}


[*source*](https://github.com/magicsword-io/LOLDrivers/tree/main/yaml/asromgdrv.yaml)

*last_updated:* 2023-04-19








{{< /column >}}
{{< /block >}}
