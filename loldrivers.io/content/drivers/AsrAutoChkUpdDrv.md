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
{% if driver.Category == "vulnerable driver" %}
This download link contains the vulnerable driver!
{% elif driver.Category == "malicious" %}
This download link contains the malicious driver!
{% endif %}
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

| Filename | AsrAutoChkUpdDrv.sys |
|:---- | ---- | 
| MD5 | <a href="https://www.virustotal.com/gui/file/75d6c3469347de1cdfa3b1b9f1544208">75d6c3469347de1cdfa3b1b9f1544208</a> |
| SHA1 | <a href="https://www.virustotal.com/gui/file/6523b3fd87de39eb5db1332e4523ce99556077dc">6523b3fd87de39eb5db1332e4523ce99556077dc</a> |
| SHA256 | <a href="https://www.virustotal.com/gui/file/2aa1b08f47fbb1e2bd2e4a492f5d616968e703e1359a921f62b38b8e4662f0c4">2aa1b08f47fbb1e2bd2e4a492f5d616968e703e1359a921f62b38b8e4662f0c4</a> |
| Authentihash MD5 | <a href="https://www.virustotal.com/gui/search/authentihash%253A18d039cb3a6ac52395a74fb8189c4110">18d039cb3a6ac52395a74fb8189c4110</a> || Authentihash SHA1 | <a href="https://www.virustotal.com/gui/search/authentihash%253A2eaa89604fa6e129825219b0debb59e775949672">2eaa89604fa6e129825219b0debb59e775949672</a> || Authentihash SHA256 | <a href="https://www.virustotal.com/gui/search/authentihash%253Ad3d601c77d4bb367ab3105920ca8435aa775448a49c1eda6ac6f46ee5d8709cb">d3d601c77d4bb367ab3105920ca8435aa775448a49c1eda6ac6f46ee5d8709cb</a> || Publisher | ASROCK Incorporation || Signature | ASROCK Incorporation, VeriSign Class 3 Code Signing 2010 CA, VeriSign   || Company | ASRock Incorporation || Description | AsrAutoChkUpdDrv Driver || Product | AsrAutoChkUpdDrv Driver || OriginalFilename | AsrAutoChkUpdDrv.sys |
#### Imports
{{< details "Expand" >}}* ntoskrnl.exe
* HAL.dll
{{< /details >}}
#### ImportedFunctions
{{< details "Expand" >}}* IoDeleteSymbolicLink
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
{{< details "Expand" >}}{{< /details >}}



[*source*](https://github.com/magicsword-io/LOLDrivers/tree/main/yaml/asrautochkupddrv.yaml)

*last_updated:* 2023-04-19








{{< /column >}}
{{< /block >}}
