+++

description = ""
title = "AsrIbDrv.sys"
weight = 10

+++


{{< block "grid-1" >}}
{{< column "mt-2 pt-1">}}


# AsrIbDrv.sys ![:inline](/images/twitter_verified.png) 


### Description

AsrIbDrv.sys is a vulnerable driver and more information will be added as found.

- **Created**: 2023-01-09
- **Author**: Michael Haag
- **Acknowledgement**:  | [](https://twitter.com/)

{{< button "https://github.com/magicsword-io/LOLDrivers/raw/main/drivers/5bab40019419a2713298a5c9173e5d30.bin" "Download" >}}
{{< tip "warning" >}}
This download link contains the vulnerable driver!

{{< /tip >}}

### Commands

```
sc.exe create AsrIbDrv.sys binPath=C:\windows\temp\AsrIbDrv.sys type=kernel &amp;&amp; sc.exe start AsrIbDrv.sys
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
| Filename           | AsrIbDrv.sys |
| MD5                | [5bab40019419a2713298a5c9173e5d30](https://www.virustotal.com/gui/file/5bab40019419a2713298a5c9173e5d30) |
| SHA1               | [2d503a2457a787014a1fdd48a2ece2e6cbe98ea7](https://www.virustotal.com/gui/file/2d503a2457a787014a1fdd48a2ece2e6cbe98ea7) |
| SHA256             | [2a652de6b680d5ad92376ad323021850dab2c653abf06edf26120f7714b8e08a](https://www.virustotal.com/gui/file/2a652de6b680d5ad92376ad323021850dab2c653abf06edf26120f7714b8e08a) |
| Authentihash MD5   | [a2bb232491925c750971c731b5fe0769](https://www.virustotal.com/gui/search/authentihash%253Aa2bb232491925c750971c731b5fe0769) |
| Authentihash SHA1  | [dd71b95f82ae2c31008da781c4de64d6059c5fca](https://www.virustotal.com/gui/search/authentihash%253Add71b95f82ae2c31008da781c4de64d6059c5fca) |
| Authentihash SHA256| [b8d748834fb982fa033cd2671843de727999b21fad30979ac4acc4828910ef8b](https://www.virustotal.com/gui/search/authentihash%253Ab8d748834fb982fa033cd2671843de727999b21fad30979ac4acc4828910ef8b) |
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


[*source*](https://github.com/magicsword-io/LOLDrivers/tree/main/yaml/asribdrv.yaml)

*last_updated:* 2023-04-20








{{< /column >}}
{{< /block >}}
