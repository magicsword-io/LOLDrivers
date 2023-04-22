+++

description = ""
title = "RTCore64.sys"
weight = 10

+++


{{< block "grid-1" >}}
{{< column "mt-2 pt-1">}}


# RTCore64.sys ![:inline](/images/twitter_verified.png) 


### Description

The driver in Micro-Star MSI Afterburner 4.6.2.15658 (aka RTCore64.sys and RTCore32.sys) allows any authenticated user to read and write to arbitrary memory, I/O ports, and MSRs. This can be exploited for privilege escalation, code execution under high privileges, and information disclosure. These signed drivers can also be used to bypass the Microsoft driver-signing policy to deploy malicious code.

- **Created**: 2023-01-09
- **Author**: Michael Haag
- **Acknowledgement**:  | [](https://twitter.com/)

{{< button "https://github.com/magicsword-io/LOLDrivers/raw/main/drivers/2d8e4f38b36c334d0a32a7324832501d.bin" "Download" >}}
{{< tip "warning" >}}
This download link contains the vulnerable driver!

{{< /tip >}}

### Commands

```
sc.exe create RTCore64.sys binPath=C:\windows\temp\RTCore64.sys type=kernel &amp;&amp; sc.exe start RTCore64.sys
```

| Use Case | Privileges | Operating System | 
|:---- | ---- | ---- |
| Elevate privileges | kernel | Windows 10 |

### Resources
<br>
<li><a href="https://github.com/elastic/protections-artifacts/search?q=VulnDriver">https://github.com/elastic/protections-artifacts/search?q=VulnDriver</a></li>
<li><a href="https://news.sophos.com/en-us/2022/10/04/blackbyte-ransomware-returns/">https://news.sophos.com/en-us/2022/10/04/blackbyte-ransomware-returns/</a></li>
<li><a href="https://github.com/elastic/protections-artifacts/search?q=VulnDriver">https://github.com/elastic/protections-artifacts/search?q=VulnDriver</a></li>
<li><a href="https://github.com/VoidSec/Exploit-Development/tree/b82b6d3ac1cce66221101d3e0f4634aa64cb4ca7/windows/x64/kernel/RTCore64_MSI_Afterburner_v.4.6.4.16117">https://github.com/VoidSec/Exploit-Development/tree/b82b6d3ac1cce66221101d3e0f4634aa64cb4ca7/windows/x64/kernel/RTCore64_MSI_Afterburner_v.4.6.4.16117</a></li>
<br>

### Known Vulnerable Samples

| Property           | Value |
|:-------------------|:------|
| Filename           | RTCore64.sys |
| MD5                | [2d8e4f38b36c334d0a32a7324832501d](https://www.virustotal.com/gui/file/2d8e4f38b36c334d0a32a7324832501d) |
| SHA1               | [f6f11ad2cd2b0cf95ed42324876bee1d83e01775](https://www.virustotal.com/gui/file/f6f11ad2cd2b0cf95ed42324876bee1d83e01775) |
| SHA256             | [01aa278b07b58dc46c84bd0b1b5c8e9ee4e62ea0bf7a695862444af32e87f1fd](https://www.virustotal.com/gui/file/01aa278b07b58dc46c84bd0b1b5c8e9ee4e62ea0bf7a695862444af32e87f1fd) |
| Authentihash MD5   | [538e5e595c61d2ea8defb7b047784734](https://www.virustotal.com/gui/search/authentihash%253A538e5e595c61d2ea8defb7b047784734) |
| Authentihash SHA1  | [4a68c2d7a4c471e062a32c83a36eedb45a619683](https://www.virustotal.com/gui/search/authentihash%253A4a68c2d7a4c471e062a32c83a36eedb45a619683) |
| Authentihash SHA256| [478c36f8af7844a80e24c1822507beef6314519185717ec7ae224a0e04b2f330](https://www.virustotal.com/gui/search/authentihash%253A478c36f8af7844a80e24c1822507beef6314519185717ec7ae224a0e04b2f330) |
| Publisher         | N/A |
| Signature         | N, /, A   |
| Date                | N/A |


#### Imports
{{< details "Expand" >}}
* ntoskrnl.exe
* HAL.dll

{{< /details >}}
#### ImportedFunctions
{{< details "Expand" >}}
* ZwMapViewOfSection
* ObReferenceObjectByHandle
* ZwOpenSection
* MmMapIoSpace
* __C_specific_handler
* ZwClose
* ZwUnmapViewOfSection
* MmUnmapIoSpace
* IoCreateSymbolicLink
* IoCreateDevice
* RtlInitUnicodeString
* IoDeleteSymbolicLink
* IofCompleteRequest
* IoDeleteDevice
* HalTranslateBusAddress
* HalGetBusDataByOffset
* HalSetBusDataByOffset

{{< /details >}}
#### ExportedFunctions
{{< details "Expand" >}}

{{< /details >}}
-----
| Property           | Value |
|:-------------------|:------|
| Filename           | RTCore64.sys |
| MD5                | [0ec361f2fba49c73260af351c39ff9cb](https://www.virustotal.com/gui/file/0ec361f2fba49c73260af351c39ff9cb) |
| SHA1               | [af50109b112995f8c82be8ef3a88be404510cdde](https://www.virustotal.com/gui/file/af50109b112995f8c82be8ef3a88be404510cdde) |
| SHA256             | [cdd2a4575a46bada4837a6153a79c14d60ee3129830717ef09e0e3efd9d00812](https://www.virustotal.com/gui/file/cdd2a4575a46bada4837a6153a79c14d60ee3129830717ef09e0e3efd9d00812) |
| Authentihash MD5   | [63fd0d800cac53db02638349cea2f8e7](https://www.virustotal.com/gui/search/authentihash%253A63fd0d800cac53db02638349cea2f8e7) |
| Authentihash SHA1  | [3856e573765f090afbbb9e5be4c886653402f755](https://www.virustotal.com/gui/search/authentihash%253A3856e573765f090afbbb9e5be4c886653402f755) |
| Authentihash SHA256| [ff8d17761c1645bdd1f0eccc69024907bbbfbe5c60679402b7d02f95b16310fe](https://www.virustotal.com/gui/search/authentihash%253Aff8d17761c1645bdd1f0eccc69024907bbbfbe5c60679402b7d02f95b16310fe) |
| Publisher         | N/A |
| Signature         | N, /, A   |
| Date                | N/A |


#### Imports
{{< details "Expand" >}}
* ntoskrnl.exe
* HAL.dll

{{< /details >}}
#### ImportedFunctions
{{< details "Expand" >}}
* ZwMapViewOfSection
* ObReferenceObjectByHandle
* ZwOpenSection
* MmMapIoSpace
* IofCompleteRequest
* MmUnmapIoSpace
* ZwClose
* _except_handler3
* IoCreateSymbolicLink
* IoCreateDevice
* KeTickCount
* RtlInitUnicodeString
* IoDeleteSymbolicLink
* ZwUnmapViewOfSection
* IoDeleteDevice
* HalTranslateBusAddress
* HalGetBusDataByOffset
* HalSetBusDataByOffset

{{< /details >}}
#### ExportedFunctions
{{< details "Expand" >}}

{{< /details >}}
-----
| Property           | Value |
|:-------------------|:------|
| Filename           | RTCore64.sys |
| MD5                | [0a2ec9e3e236698185978a5fc76e74e6](https://www.virustotal.com/gui/file/0a2ec9e3e236698185978a5fc76e74e6) |
| SHA1               | [4fe873544c34243826489997a5ff14ed39dd090d](https://www.virustotal.com/gui/file/4fe873544c34243826489997a5ff14ed39dd090d) |
| SHA256             | [f1c8ca232789c2f11a511c8cd95a9f3830dd719cad5aa22cb7c3539ab8cb4dc3](https://www.virustotal.com/gui/file/f1c8ca232789c2f11a511c8cd95a9f3830dd719cad5aa22cb7c3539ab8cb4dc3) |
| Authentihash MD5   | [bcd9f192e2f9321ed549c722f30206e5](https://www.virustotal.com/gui/search/authentihash%253Abcd9f192e2f9321ed549c722f30206e5) |
| Authentihash SHA1  | [8498265d4ca81b83ec1454d9ec013d7a9c0c87bf](https://www.virustotal.com/gui/search/authentihash%253A8498265d4ca81b83ec1454d9ec013d7a9c0c87bf) |
| Authentihash SHA256| [606beced7746cdb684d3a44f41e48713c6bbe5bfb1486c52b5cca815e99d31b4](https://www.virustotal.com/gui/search/authentihash%253A606beced7746cdb684d3a44f41e48713c6bbe5bfb1486c52b5cca815e99d31b4) |
| Publisher         | N/A |
| Signature         | N, /, A   |
| Date                | N/A |


#### Imports
{{< details "Expand" >}}
* ntoskrnl.exe
* HAL.dll

{{< /details >}}
#### ImportedFunctions
{{< details "Expand" >}}
* MmUnmapIoSpace
* ZwUnmapViewOfSection
* MmMapIoSpace
* ZwClose
* IoDeleteDevice
* ObReferenceObjectByHandle
* IoCreateSymbolicLink
* ZwOpenSection
* KeBugCheckEx
* RtlInitUnicodeString
* ZwMapViewOfSection
* IofCompleteRequest
* IoDeleteSymbolicLink
* MmGetSystemRoutineAddress
* IoCreateDevice
* ObOpenObjectByPointer
* ZwSetSecurityObject
* IoDeviceObjectType
* _snwprintf
* RtlLengthSecurityDescriptor
* SeCaptureSecurityDescriptor
* ExFreePoolWithTag
* RtlCreateSecurityDescriptor
* RtlSetDaclSecurityDescriptor
* RtlAbsoluteToSelfRelativeSD
* IoIsWdmVersionAvailable
* SeExports
* wcschr
* _wcsnicmp
* ExAllocatePoolWithTag
* RtlLengthSid
* RtlAddAccessAllowedAce
* RtlGetSaclSecurityDescriptor
* RtlGetDaclSecurityDescriptor
* RtlGetGroupSecurityDescriptor
* RtlGetOwnerSecurityDescriptor
* ZwOpenKey
* ZwCreateKey
* ZwQueryValueKey
* ZwSetValueKey
* RtlFreeUnicodeString
* __C_specific_handler
* HalGetBusDataByOffset
* HalSetBusDataByOffset
* HalTranslateBusAddress

{{< /details >}}
#### ExportedFunctions
{{< details "Expand" >}}

{{< /details >}}
-----



[*source*](https://github.com/magicsword-io/LOLDrivers/tree/main/yaml/rtcore64.yaml)

*last_updated:* 2023-04-22








{{< /column >}}
{{< /block >}}
