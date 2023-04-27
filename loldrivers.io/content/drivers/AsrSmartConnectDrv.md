+++

description = ""
title = "AsrSmartConnectDrv.sys"
weight = 10

+++


{{< block "grid-1" >}}
{{< column "mt-2 pt-1">}}


# AsrSmartConnectDrv.sys ![:inline](/images/twitter_verified.png) 


### Description

AsrSmartConnectDrv.sys is a vulnerable driver and more information will be added as found.

- **Created**: 2023-01-09
- **Author**: Michael Haag
- **Acknowledgement**:  | [](https://twitter.com/)

{{< button "https://github.com/magicsword-io/LOLDrivers/raw/main/drivers/56a515173b211832e20fbc64e5a0447c.bin" "Download" >}}
{{< tip "warning" >}}
This download link contains the vulnerable driver!

{{< /tip >}}

### Commands

```
sc.exe create AsrSmartConnectDrv.sys binPath=C:\windows\temp\AsrSmartConnectDrv.sys     type=kernel &amp;&amp; sc.exe start AsrSmartConnectDrv.sys
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
| Filename           | AsrSmartConnectDrv.sys |
| MD5                | [56a515173b211832e20fbc64e5a0447c](https://www.virustotal.com/gui/file/56a515173b211832e20fbc64e5a0447c) |
| SHA1               | [1d0df45ee3fa758f0470e055915004e6eae54c95](https://www.virustotal.com/gui/file/1d0df45ee3fa758f0470e055915004e6eae54c95) |
| SHA256             | [47f08f7d30d824a8f4bb8a98916401a37c0fd8502db308aba91fe3112b892dcc](https://www.virustotal.com/gui/file/47f08f7d30d824a8f4bb8a98916401a37c0fd8502db308aba91fe3112b892dcc) |
| Authentihash MD5   | [fc88782a34ab832abb9c04c63c76830b](https://www.virustotal.com/gui/search/authentihash%253Afc88782a34ab832abb9c04c63c76830b) |
| Authentihash SHA1  | [a7bcabd8e465e5e1a0bad564d887a47f378dfdaa](https://www.virustotal.com/gui/search/authentihash%253Aa7bcabd8e465e5e1a0bad564d887a47f378dfdaa) |
| Authentihash SHA256| [f43d977a5fb1bdc10837e7c4ff03526d2b8fa9757da9dd8bd6514cd31748a858](https://www.virustotal.com/gui/search/authentihash%253Af43d977a5fb1bdc10837e7c4ff03526d2b8fa9757da9dd8bd6514cd31748a858) |
| Publisher         | ASROCK Incorporation |
| Signature         | ASROCK Incorporation, VeriSign Class 3 Code Signing 2010 CA, VeriSign   |
| Company           | RW-Everything |
| Description       | RW-Everything Read &amp; Write Driver |
| Product           | RW-Everything Read &amp; Write Driver |
| OriginalFilename  | RwDrv.sys |


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
-----



[*source*](https://github.com/magicsword-io/LOLDrivers/tree/main/yaml/asrsmartconnectdrv.yaml)

*last_updated:* 2023-04-27








{{< /column >}}
{{< /block >}}
