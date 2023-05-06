+++

description = ""
title = "AsrAutoChkUpdDrv.sys"
weight = 10

+++


{{< block "grid-1" >}}
{{< column "mt-2 pt-1">}}


# AsrAutoChkUpdDrv.sys ![:inline](/images/twitter_verified.png) 


### Description

AsrAutoChkUpdDrv.sys is a vulnerable driver and more information will be added as found.

- **Created**: 2023-01-09
- **Author**: Michael Haag
- **Acknowledgement**:  | [](https://twitter.com/)

{{< button "https://github.com/magicsword-io/LOLDrivers/raw/main/drivers/75d6c3469347de1cdfa3b1b9f1544208.bin" "Download" >}}
{{< tip "warning" >}}
This download link contains the vulnerable driver!

{{< /tip >}}

### Commands

```
sc.exe create AsrAutoChkUpdDrv.sys binPath=C:\windows\temp\AsrAutoChkUpdDrv.sys     type=kernel &amp;&amp; sc.exe start AsrAutoChkUpdDrv.sys
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
| Filename           | AsrAutoChkUpdDrv.sys |
| MD5                | [75d6c3469347de1cdfa3b1b9f1544208](https://www.virustotal.com/gui/file/75d6c3469347de1cdfa3b1b9f1544208) |
| SHA1               | [6523b3fd87de39eb5db1332e4523ce99556077dc](https://www.virustotal.com/gui/file/6523b3fd87de39eb5db1332e4523ce99556077dc) |
| SHA256             | [2aa1b08f47fbb1e2bd2e4a492f5d616968e703e1359a921f62b38b8e4662f0c4](https://www.virustotal.com/gui/file/2aa1b08f47fbb1e2bd2e4a492f5d616968e703e1359a921f62b38b8e4662f0c4) |
| Authentihash MD5   | [18d039cb3a6ac52395a74fb8189c4110](https://www.virustotal.com/gui/search/authentihash%253A18d039cb3a6ac52395a74fb8189c4110) |
| Authentihash SHA1  | [2eaa89604fa6e129825219b0debb59e775949672](https://www.virustotal.com/gui/search/authentihash%253A2eaa89604fa6e129825219b0debb59e775949672) |
| Authentihash SHA256| [d3d601c77d4bb367ab3105920ca8435aa775448a49c1eda6ac6f46ee5d8709cb](https://www.virustotal.com/gui/search/authentihash%253Ad3d601c77d4bb367ab3105920ca8435aa775448a49c1eda6ac6f46ee5d8709cb) |
| Publisher         | ASROCK Incorporation |
| Signature         | ASROCK Incorporation, VeriSign Class 3 Code Signing 2010 CA, VeriSign   |
| Company           | ASRock Incorporation |
| Description       | AsrAutoChkUpdDrv Driver |
| Product           | AsrAutoChkUpdDrv Driver |
| OriginalFilename  | AsrAutoChkUpdDrv.sys |


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



[*source*](https://github.com/magicsword-io/LOLDrivers/tree/main/yaml/asrautochkupddrv.yaml)

*last_updated:* 2023-05-06








{{< /column >}}
{{< /block >}}
