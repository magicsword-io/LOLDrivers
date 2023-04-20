+++

description = ""
title = "ATSZIO64.sys"
weight = 10

+++


{{< block "grid-1" >}}
{{< column "mt-2 pt-1">}}


# ATSZIO64.sys ![:inline](/images/twitter_verified.png) 


### Description

ATSZIO64.sys is a vulnerable driver and more information will be added as found.

- **Created**: 2023-01-09
- **Author**: Michael Haag
- **Acknowledgement**:  | [](https://twitter.com/)

{{< button "https://github.com/magicsword-io/LOLDrivers/raw/main/drivers/b12d1630fd50b2a21fd91e45d522ba3a.bin" "Download" >}}
{{< tip "warning" >}}
This download link contains the vulnerable driver!

{{< /tip >}}

### Commands

```
sc.exe create ATSZIO64.sys binPath=C:\windows\temp\ATSZIO64.sys type=kernel &amp;&amp; sc.exe start ATSZIO64.sys
```

| Use Case | Privileges | Operating System | 
|:---- | ---- | ---- |
| Elevate privileges | kernel | Windows 10 |

### Resources
<br>
<li><a href=" https://github.com/elastic/protections-artifacts/search?q=VulnDriver"> https://github.com/elastic/protections-artifacts/search?q=VulnDriver</a></li>
<li><a href="https://github.com/elastic/protections-artifacts/search?q=VulnDriver">https://github.com/elastic/protections-artifacts/search?q=VulnDriver</a></li>
<br>

### Known Vulnerable Samples

| Property           | Value |
|:-------------------|:------|
| Filename           | ATSZIO64.sys |
| MD5                | [b12d1630fd50b2a21fd91e45d522ba3a](https://www.virustotal.com/gui/file/b12d1630fd50b2a21fd91e45d522ba3a) |
| SHA1               | [490109fa6739f114651f4199196c5121d1c6bdf2](https://www.virustotal.com/gui/file/490109fa6739f114651f4199196c5121d1c6bdf2) |
| SHA256             | [01e024cb14b34b6d525c642a710bfa14497ea20fd287c39ba404b10a8b143ece](https://www.virustotal.com/gui/file/01e024cb14b34b6d525c642a710bfa14497ea20fd287c39ba404b10a8b143ece) |
| Authentihash MD5   | [69a92cb6ac87c99f10b24eefa13f0b10](https://www.virustotal.com/gui/search/authentihash%253A69a92cb6ac87c99f10b24eefa13f0b10) |
| Authentihash SHA1  | [b66bf2b1b07f8f2bab1418131ae66b0a55265f73](https://www.virustotal.com/gui/search/authentihash%253Ab66bf2b1b07f8f2bab1418131ae66b0a55265f73) |
| Authentihash SHA256| [0ff8bcc7f938ec71ee33fbe089d38e40a8190603558d4765c47b1b09e1dd764a](https://www.virustotal.com/gui/search/authentihash%253A0ff8bcc7f938ec71ee33fbe089d38e40a8190603558d4765c47b1b09e1dd764a) |
| Signature         | ASUSTeK Computer Inc., VeriSign Class 3 Code Signing 2010 CA, VeriSign   |
| Company           | ASUSTek Computer Inc. |
| Description       | ATSZIO Driver |
| Product           | ATSZIO Driver |
| OriginalFilename  | ATSZIO.sys |


#### Imports
{{< details "Expand" >}}
* ntoskrnl.exe
* HAL.dll

{{< /details >}}
#### ImportedFunctions
{{< details "Expand" >}}
* KeWaitForSingleObject
* ExAllocatePool
* ExFreePoolWithTag
* MmAllocateContiguousMemory
* MmFreeContiguousMemory
* IofCompleteRequest
* IoCreateDevice
* IoCreateSymbolicLink
* IoCreateSynchronizationEvent
* KeSetEvent
* IoDeleteSymbolicLink
* ObReferenceObjectByHandle
* ZwClose
* ZwOpenSection
* ZwMapViewOfSection
* ZwUnmapViewOfSection
* MmGetPhysicalAddress
* __C_specific_handler
* DbgPrint
* IoDeleteDevice
* RtlInitUnicodeString
* HalSetBusDataByOffset
* HalGetBusDataByOffset

{{< /details >}}
#### ExportedFunctions
{{< details "Expand" >}}

{{< /details >}}
-----



[*source*](https://github.com/magicsword-io/LOLDrivers/tree/main/yaml/atszio64.yaml)

*last_updated:* 2023-04-20








{{< /column >}}
{{< /block >}}
