+++

description = ""
title = "cpuz141.sys"
weight = 10

+++


{{< block "grid-1" >}}
{{< column "mt-2 pt-1">}}


# cpuz141.sys ![:inline](/images/twitter_verified.png) 


### Description

cpuz141.sys is a vulnerable driver and more information will be added as found.

- **Created**: 2023-01-09
- **Author**: Michael Haag
- **Acknowledgement**:  | [](https://twitter.com/)

{{< button "https://github.com/magicsword-io/LOLDrivers/raw/main/drivers/db72def618cbc3c5f9aa82f091b54250.bin" "Download" >}}
{{< tip "warning" >}}
This download link contains the vulnerable driver!

{{< /tip >}}

### Commands

```
sc.exe create cpuz141.sys binPath=C:\windows\temp\cpuz141.sys type=kernel &amp;&amp; sc.exe start cpuz141.sys
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
| Filename           | cpuz141.sys |
| MD5                | [db72def618cbc3c5f9aa82f091b54250](https://www.virustotal.com/gui/file/db72def618cbc3c5f9aa82f091b54250) |
| SHA1               | [f5696fb352a3fbd14fb1a89ad21a71776027f9ab](https://www.virustotal.com/gui/file/f5696fb352a3fbd14fb1a89ad21a71776027f9ab) |
| SHA256             | [ded2927f9a4e64eefd09d0caba78e94f309e3a6292841ae81d5528cab109f95d](https://www.virustotal.com/gui/file/ded2927f9a4e64eefd09d0caba78e94f309e3a6292841ae81d5528cab109f95d) |
| Authentihash MD5   | [17b67e675e778c70d3c348d5088ab514](https://www.virustotal.com/gui/search/authentihash%253A17b67e675e778c70d3c348d5088ab514) |
| Authentihash SHA1  | [b38b98608e410c1555a7d73056e86e1db850bb2e](https://www.virustotal.com/gui/search/authentihash%253Ab38b98608e410c1555a7d73056e86e1db850bb2e) |
| Authentihash SHA256| [33b88ac3151f2192eaf4c2be3c7ad00e49090c8b94ec51b754e19ac784b087aa](https://www.virustotal.com/gui/search/authentihash%253A33b88ac3151f2192eaf4c2be3c7ad00e49090c8b94ec51b754e19ac784b087aa) |
| Publisher         | CPUID |
| Signature         | CPUID, VeriSign Class 3 Code Signing 2010 CA, VeriSign   |
| Company           | CPUID |
| Description       | CPUID Driver |
| Product           | CPUID service |
| OriginalFilename  | cpuz.sys |


#### Imports
{{< details "Expand" >}}
* ntoskrnl.exe
* HAL.dll

{{< /details >}}
#### ImportedFunctions
{{< details "Expand" >}}
* RtlInitUnicodeString
* IoDeleteDevice
* KeInitializeEvent
* RtlInitAnsiString
* MmUnmapIoSpace
* IoCancelIrp
* RtlFreeUnicodeString
* IoGetDeviceObjectPointer
* RtlAnsiStringToUnicodeString
* IofCompleteRequest
* KeWaitForSingleObject
* PsGetVersion
* IoCreateSymbolicLink
* ObfDereferenceObject
* IoCreateDevice
* IofCallDriver
* KeBugCheckEx
* ExFreePoolWithTag
* IoDeleteSymbolicLink
* IoBuildDeviceIoControlRequest
* MmMapIoSpace
* ExAllocatePoolWithTag
* RtlUnwindEx
* HalGetBusDataByOffset
* HalSetBusDataByOffset
* KeStallExecutionProcessor
* KeQueryPerformanceCounter

{{< /details >}}
#### ExportedFunctions
{{< details "Expand" >}}

{{< /details >}}


[*source*](https://github.com/magicsword-io/LOLDrivers/tree/main/yaml/cpuz141.yaml)

*last_updated:* 2023-04-19








{{< /column >}}
{{< /block >}}
