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
This download link contains the malcious driver!
{{< /tip >}}

### Commands

```
sc.exe create HpPortIox64.sys binPath=C:\windows\temp\HpPortIox64.sys     type=kernel type=kernel &amp;&amp; sc.exe start HpPortIox64.sys
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

| Filename | HpPortIox64.sys |
|:---- | ---- | 
| MD5 | <a href="https://www.virustotal.com/gui/file/a641e3dccba765a10718c9cb0da7879e">a641e3dccba765a10718c9cb0da7879e</a> |
| SHA1 | <a href="https://www.virustotal.com/gui/file/8c377ab4eebc5f4d8dd7bb3f90c0187dfdd3349f">8c377ab4eebc5f4d8dd7bb3f90c0187dfdd3349f</a> |
| SHA256 | <a href="https://www.virustotal.com/gui/file/c5050a2017490fff7aa53c73755982b339ddb0fd7cef2cde32c81bc9834331c5">c5050a2017490fff7aa53c73755982b339ddb0fd7cef2cde32c81bc9834331c5</a> |
| Authentihash MD5 | <a href="https://www.virustotal.com/gui/search/authentihash%253A986877a0cf596be97155e9469f3c4b40">986877a0cf596be97155e9469f3c4b40</a> || Authentihash SHA1 | <a href="https://www.virustotal.com/gui/search/authentihash%253A98807d9e11bad4feed54d0d2c1abadeb95ca997c">98807d9e11bad4feed54d0d2c1abadeb95ca997c</a> || Authentihash SHA256 | <a href="https://www.virustotal.com/gui/search/authentihash%253A35b31c96194d78cbb98b3223bf810f78f53fc0e4601f49169938ca883586e4e9">35b31c96194d78cbb98b3223bf810f78f53fc0e4601f49169938ca883586e4e9</a> || Signature | HP Inc., DigiCert SHA2 Assured ID Code Signing CA, DigiCert   || Company | HP Inc. || Description | HpPortIo || Product | HpPortIo || OriginalFilename | HpPortIox64.sys |
#### Imports
{{< details "Expand" >}}* ntoskrnl.exe
* HAL.dll
{{< /details >}}
#### ImportedFunctions
{{< details "Expand" >}}* MmGetSystemRoutineAddress
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
{{< details "Expand" >}}{{< /details >}}



[*source*](https://github.com/magicsword-io/LOLDrivers/tree/main/yaml/hpportiox64.yaml)

*last_updated:* 2023-04-16








{{< /column >}}
{{< /block >}}
