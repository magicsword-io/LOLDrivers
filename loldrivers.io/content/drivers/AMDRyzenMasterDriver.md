+++

description = ""
title = "AMDRyzenMasterDriver.sys"
weight = 10

+++


{{< block "grid-1" >}}
{{< column "mt-2 pt-1">}}


# AMDRyzenMasterDriver.sys ![:inline](/images/twitter_verified.png) 


### Description

AMDRyzenMasterDriver.sys is a vulnerable driver and more information will be added as found.

- **Created**: 2023-01-09
- **Author**: Michael Haag
- **Acknowledgement**:  | [](https://twitter.com/)

{{< button "https://github.com/magicsword-io/LOLDrivers/raw/main/drivers/13ee349c15ee5d6cf640b3d0111ffc0e.bin" "Download" >}}
{{< tip "warning" >}}
This download link contains the vulnerable driver!

{{< /tip >}}

### Commands

```
sc.exe create AMDRyzenMasterDriver.sys binPath=C:\windows\temp\AMDRyzenMasterDriver.sys     type=kernel &amp;&amp; sc.exe start AMDRyzenMasterDriver.sys
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
| Filename           | AMDRyzenMasterDriver.sys |
| MD5                | [13ee349c15ee5d6cf640b3d0111ffc0e](https://www.virustotal.com/gui/file/13ee349c15ee5d6cf640b3d0111ffc0e) |
| SHA1               | [4f7a8e26a97980544be634b26899afbefb0a833c](https://www.virustotal.com/gui/file/4f7a8e26a97980544be634b26899afbefb0a833c) |
| SHA256             | [a13054f349b7baa8c8a3fcbd31789807a493cc52224bbff5e412eb2bd52a6433](https://www.virustotal.com/gui/file/a13054f349b7baa8c8a3fcbd31789807a493cc52224bbff5e412eb2bd52a6433) |
| Authentihash MD5   | [aa6e3970343cb83f7c924e98aeaf0c85](https://www.virustotal.com/gui/search/authentihash%253Aaa6e3970343cb83f7c924e98aeaf0c85) |
| Authentihash SHA1  | [c29a625c02bf49f3f055db90b280a1f201c59975](https://www.virustotal.com/gui/search/authentihash%253Ac29a625c02bf49f3f055db90b280a1f201c59975) |
| Authentihash SHA256| [001cd8b2ce1932d1a8c32bc2d643ee4fa6f67626d1b6895beea916285450566c](https://www.virustotal.com/gui/search/authentihash%253A001cd8b2ce1932d1a8c32bc2d643ee4fa6f67626d1b6895beea916285450566c) |
| Signature         | Advanced Micro Devices INC., Symantec Class 3 SHA256 Code Signing CA, VeriSign   |
| Company           | Advanced Micro Devices |
| Description       | AMD Ryzen Master Service Driver |
| Product           | AMD Ryzen Master Service Driver |
| OriginalFilename  | AMDRyzenMasterDriver.sys |


#### Imports
{{< details "Expand" >}}
* ntoskrnl.exe
* HAL.dll
* WDFLDR.SYS

{{< /details >}}
#### ImportedFunctions
{{< details "Expand" >}}
* KeLeaveCriticalRegion
* MmMapIoSpace
* MmUnmapIoSpace
* IofCompleteRequest
* IoCreateSymbolicLink
* IoDeleteDevice
* IoDeleteSymbolicLink
* MmBuildMdlForNonPagedPool
* MmMapLockedPagesSpecifyCache
* MmUnmapLockedPages
* IoAllocateMdl
* IoFreeMdl
* MmGetSystemRoutineAddress
* ZwClose
* ZwSetSecurityObject
* IoDeviceObjectType
* IoCreateDevice
* KeEnterCriticalRegion
* RtlGetDaclSecurityDescriptor
* RtlGetGroupSecurityDescriptor
* RtlGetOwnerSecurityDescriptor
* RtlGetSaclSecurityDescriptor
* SeCaptureSecurityDescriptor
* _snwprintf
* RtlLengthSecurityDescriptor
* SeExports
* RtlCreateSecurityDescriptor
* _wcsnicmp
* wcschr
* RtlAbsoluteToSelfRelativeSD
* RtlAddAccessAllowedAce
* RtlLengthSid
* IoIsWdmVersionAvailable
* RtlSetDaclSecurityDescriptor
* ZwOpenKey
* ZwSetValueKey
* ZwQueryValueKey
* ZwCreateKey
* RtlFreeUnicodeString
* KeDelayExecutionThread
* RtlGetVersion
* DbgPrint
* RtlCopyUnicodeString
* RtlInitUnicodeString
* ExFreePoolWithTag
* ExAllocatePoolWithTag
* ObOpenObjectByPointer
* strncmp
* HalSetBusDataByOffset
* HalGetBusDataByOffset
* WdfVersionBind
* WdfVersionUnbind
* WdfVersionBindClass
* WdfVersionUnbindClass

{{< /details >}}
#### ExportedFunctions
{{< details "Expand" >}}

{{< /details >}}
-----



[*source*](https://github.com/magicsword-io/LOLDrivers/tree/main/yaml/amdryzenmasterdriver.yaml)

*last_updated:* 2023-05-06








{{< /column >}}
{{< /block >}}
