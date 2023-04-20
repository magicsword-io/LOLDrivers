+++

description = ""
title = "HpPortIox64.sys"
weight = 10

+++


{{< block "grid-1" >}}
{{< column "mt-2 pt-1">}}


# HpPortIox64.sys ![:inline](/images/twitter_verified.png) 


### Description

HpPortIox64.sys is a vulnerable driver and more information will be added as found.

- **Created**: 2023-01-09
- **Author**: Michael Haag
- **Acknowledgement**:  | [](https://twitter.com/)

{{< button "https://github.com/magicsword-io/LOLDrivers/raw/main/drivers/a641e3dccba765a10718c9cb0da7879e.bin" "Download" >}}
{{< tip "warning" >}}
This download link contains the vulnerable driver!

{{< /tip >}}

### Commands

```
sc.exe create HpPortIox64.sys binPath=C:\windows\temp\HpPortIox64.sys     type=kernel &amp;&amp; sc.exe start HpPortIox64.sys
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
| Filename           | HpPortIox64.sys |
| MD5                | [a641e3dccba765a10718c9cb0da7879e](https://www.virustotal.com/gui/file/a641e3dccba765a10718c9cb0da7879e) |
| SHA1               | [8c377ab4eebc5f4d8dd7bb3f90c0187dfdd3349f](https://www.virustotal.com/gui/file/8c377ab4eebc5f4d8dd7bb3f90c0187dfdd3349f) |
| SHA256             | [c5050a2017490fff7aa53c73755982b339ddb0fd7cef2cde32c81bc9834331c5](https://www.virustotal.com/gui/file/c5050a2017490fff7aa53c73755982b339ddb0fd7cef2cde32c81bc9834331c5) |
| Authentihash MD5   | [986877a0cf596be97155e9469f3c4b40](https://www.virustotal.com/gui/search/authentihash%253A986877a0cf596be97155e9469f3c4b40) |
| Authentihash SHA1  | [98807d9e11bad4feed54d0d2c1abadeb95ca997c](https://www.virustotal.com/gui/search/authentihash%253A98807d9e11bad4feed54d0d2c1abadeb95ca997c) |
| Authentihash SHA256| [35b31c96194d78cbb98b3223bf810f78f53fc0e4601f49169938ca883586e4e9](https://www.virustotal.com/gui/search/authentihash%253A35b31c96194d78cbb98b3223bf810f78f53fc0e4601f49169938ca883586e4e9) |
| Signature         | HP Inc., DigiCert SHA2 Assured ID Code Signing CA, DigiCert   |
| Company           | HP Inc. |
| Description       | HpPortIo |
| Product           | HpPortIo |
| OriginalFilename  | HpPortIox64.sys |


#### Imports
{{< details "Expand" >}}
* ntoskrnl.exe
* HAL.dll

{{< /details >}}
#### ImportedFunctions
{{< details "Expand" >}}
* MmGetSystemRoutineAddress
* RtlUnicodeStringToAnsiString
* ExAllocatePool
* ZwClose
* RtlAppendUnicodeStringToString
* ObReferenceObjectByHandle
* RtlCopyUnicodeString
* MmIsAddressValid
* ExFreePoolWithTag
* ZwOpenFile
* DbgPrint
* RtlEqualUnicodeString
* ZwCreateFile
* KeBugCheckEx
* RtlVolumeDeviceToDosName
* ExAllocatePoolWithTag
* DbgPrintEx
* IoCreateDevice
* IoCreateSymbolicLink
* RtlFreeAnsiString
* IofCompleteRequest
* RtlFreeUnicodeString
* RtlInitString
* IoDeleteDevice
* RtlInitUnicodeString
* strstr
* RtlAnsiStringToUnicodeString
* ObfDereferenceObject
* IoDeleteSymbolicLink
* ZwReadFile
* RtlUTF8ToUnicodeN
* RtlTimeFieldsToTime
* RtlCharToInteger
* RtlCompareMemory
* RtlAssert
* __C_specific_handler
* HalSetBusDataByOffset
* HalGetBusDataByOffset

{{< /details >}}
#### ExportedFunctions
{{< details "Expand" >}}

{{< /details >}}
-----



[*source*](https://github.com/magicsword-io/LOLDrivers/tree/main/yaml/hpportiox64.yaml)

*last_updated:* 2023-04-20








{{< /column >}}
{{< /block >}}
