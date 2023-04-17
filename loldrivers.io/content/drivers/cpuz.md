+++

description = ""
title = "cpuz.sys"
weight = 10

+++


{{< block "grid-1" >}}
{{< column "mt-2 pt-1">}}


# cpuz.sys ![:inline](/images/twitter_verified.png) 


### Description

cpuz.sys is a vulnerable driver and more information will be added as found.

- **Created**: 2023-01-09
- **Author**: Michael Haag
- **Acknowledgement**:  | [](https://twitter.com/)

{{< button "https://github.com/magicsword-io/LOLDrivers/raw/main/drivers/c2eb4539a4f6ab6edd01bdc191619975.bin" "Download" >}}
{{< tip "warning" >}}
This download link contains the malcious driver!
{{< /tip >}}

### Commands

```
sc.exe create cpuz.sys binPath=C:\windows\temp\cpuz.sys type=kernel &amp;&amp; sc.exe start cpuz.sys
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

| Filename | cpuz.sys |
|:---- | ---- | 
| MD5 | <a href="https://www.virustotal.com/gui/file/c2eb4539a4f6ab6edd01bdc191619975">c2eb4539a4f6ab6edd01bdc191619975</a> |
| SHA1 | <a href="https://www.virustotal.com/gui/file/4d41248078181c7f61e6e4906aa96bbdea320dc2">4d41248078181c7f61e6e4906aa96bbdea320dc2</a> |
| SHA256 | <a href="https://www.virustotal.com/gui/file/8c95d28270a4a314299cf50f05dcbe63033b2a555195d2ad2f678e09e00393e6">8c95d28270a4a314299cf50f05dcbe63033b2a555195d2ad2f678e09e00393e6</a> |
| Authentihash MD5 | <a href="https://www.virustotal.com/gui/search/authentihash%253Ad8a92124984eb0c21f84461d5babd6de">d8a92124984eb0c21f84461d5babd6de</a> || Authentihash SHA1 | <a href="https://www.virustotal.com/gui/search/authentihash%253A6e928611c1afb608bf0df53a0d9f9e59a51199a2">6e928611c1afb608bf0df53a0d9f9e59a51199a2</a> || Authentihash SHA256 | <a href="https://www.virustotal.com/gui/search/authentihash%253A4bf6f1b49ed332b31c695ee1e3e8db69d7514a3179f707034eec96de4865e1d2">4bf6f1b49ed332b31c695ee1e3e8db69d7514a3179f707034eec96de4865e1d2</a> || Signature | CPUID, VeriSign Class 3 Code Signing 2004 CA, VeriSign Class 3 Public Primary CA   || Company | CPUID || Description | CPUID Driver || Product | CPUID service || OriginalFilename | cpuz.sys |
#### Imports
{{< details "Expand" >}}* ntoskrnl.exe
* HAL.dll
{{< /details >}}
#### ImportedFunctions
{{< details "Expand" >}}* IofCompleteRequest
* ExFreePool
* ExAllocatePoolWithTag
* RtlFreeUnicodeString
* ObfDereferenceObject
* MmIsAddressValid
* IoGetDeviceObjectPointer
* MmUnmapIoSpace
* RtlInitAnsiString
* MmMapIoSpace
* IoCreateSymbolicLink
* IoCreateDevice
* RtlUnwind
* KeTickCount
* KeBugCheckEx
* RtlInitUnicodeString
* IoDeleteSymbolicLink
* IoDeleteDevice
* PsGetVersion
* KeInitializeEvent
* IoBuildDeviceIoControlRequest
* IofCallDriver
* KeWaitForSingleObject
* RtlAnsiStringToUnicodeString
* IoCancelIrp
* READ_PORT_USHORT
* READ_PORT_ULONG
* WRITE_PORT_UCHAR
* WRITE_PORT_USHORT
* WRITE_PORT_ULONG
* HalGetBusDataByOffset
* HalSetBusDataByOffset
* KeStallExecutionProcessor
* READ_PORT_UCHAR
{{< /details >}}
#### ExportedFunctions
{{< details "Expand" >}}{{< /details >}}



[*source*](https://github.com/magicsword-io/LOLDrivers/tree/main/yaml/cpuz.yaml)

*last_updated:* 2023-04-17








{{< /column >}}
{{< /block >}}
