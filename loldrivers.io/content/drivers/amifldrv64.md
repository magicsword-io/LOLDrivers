+++

description = ""
title = "amifldrv64.sys"
weight = 10

+++


{{< block "grid-1" >}}
{{< column "mt-2 pt-1">}}


# amifldrv64.sys ![:inline](/images/twitter_verified.png) 


### Description

amifldrv64.sys is a vulnerable driver and more information will be added as found.

- **Created**: 2023-01-09
- **Author**: Michael Haag
- **Acknowledgement**:  | [](https://twitter.com/)

{{< button "https://github.com/magicsword-io/LOLDrivers/raw/main/drivers/6ab7b8ef0c44e7d2d5909fdb58d37fa5.bin" "Download" >}}
{{< tip "warning" >}}
This download link contains the vulnerable driver!

{{< /tip >}}

### Commands

```
sc.exe create amifldrv64.sys binPath=C:\windows\temp\amifldrv64.sys type=kernel &amp;&amp; sc.exe start amifldrv64.sys
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
| Filename           | amifldrv64.sys |
| MD5                | [6ab7b8ef0c44e7d2d5909fdb58d37fa5](https://www.virustotal.com/gui/file/6ab7b8ef0c44e7d2d5909fdb58d37fa5) |
| SHA1               | [bb962c9a8dda93e94fef504c4159de881e4706fe](https://www.virustotal.com/gui/file/bb962c9a8dda93e94fef504c4159de881e4706fe) |
| SHA256             | [42579a759f3f95f20a2c51d5ac2047a2662a2675b3fb9f46c1ed7f23393a0f00](https://www.virustotal.com/gui/file/42579a759f3f95f20a2c51d5ac2047a2662a2675b3fb9f46c1ed7f23393a0f00) |
| Authentihash MD5   | [fc9e48051c2b957ed1cc7b69a29a66c8](https://www.virustotal.com/gui/search/authentihash%253Afc9e48051c2b957ed1cc7b69a29a66c8) |
| Authentihash SHA1  | [716bce2ce697883eba0c051ed487de6304d73cd3](https://www.virustotal.com/gui/search/authentihash%253A716bce2ce697883eba0c051ed487de6304d73cd3) |
| Authentihash SHA256| [d7841ee6dac956cc0923368d6722063a19c9fa131e55c6f3b7484cce78d826f0](https://www.virustotal.com/gui/search/authentihash%253Ad7841ee6dac956cc0923368d6722063a19c9fa131e55c6f3b7484cce78d826f0) |
| Publisher         | &#34;American Megatrends, Inc.&#34; |
| Signature         | American Megatrends, Inc., VeriSign Class 3 Code Signing 2010 CA, VeriSign   |


#### Imports
{{< details "Expand" >}}
* ntoskrnl.exe
* HAL.dll

{{< /details >}}
#### ImportedFunctions
{{< details "Expand" >}}
* ZwClose
* ZwMapViewOfSection
* ObReferenceObjectByHandle
* ZwOpenSection
* RtlInitUnicodeString
* ZwUnmapViewOfSection
* MmFreeContiguousMemory
* IoFreeMdl
* MmMapLockedPages
* MmMapLockedPagesSpecifyCache
* PsGetVersion
* MmUnmapIoSpace
* IoAllocateMdl
* MmGetPhysicalAddress
* MmIsAddressValid
* MmAllocateContiguousMemory
* MmUnmapLockedPages
* IoDeleteDevice
* IoDeleteSymbolicLink
* IofCompleteRequest
* IoCreateSymbolicLink
* IoCreateDevice
* MmBuildMdlForNonPagedPool
* MmMapIoSpace
* HalTranslateBusAddress

{{< /details >}}
#### ExportedFunctions
{{< details "Expand" >}}

{{< /details >}}
-----



[*source*](https://github.com/magicsword-io/LOLDrivers/tree/main/yaml/amifldrv64.yaml)

*last_updated:* 2023-04-26








{{< /column >}}
{{< /block >}}
