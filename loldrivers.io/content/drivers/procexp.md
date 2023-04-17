+++

description = ""
title = "procexp.Sys"
weight = 10

+++


{{< block "grid-1" >}}
{{< column "mt-2 pt-1">}}


# procexp.Sys ![:inline](/images/twitter_verified.png) 


### Description

procexp.Sys is a vulnerable driver and more information will be added as found.

- **Created**: 2023-01-09
- **Author**: Michael Haag
- **Acknowledgement**:  | [](https://twitter.com/)

{{< button "https://github.com/magicsword-io/LOLDrivers/raw/main/drivers/97e3a44ec4ae58c8cc38eefc613e950e.bin" "Download" >}}
{{< tip "warning" >}}
This download link contains the malcious driver!
{{< /tip >}}

### Commands

```
sc.exe create procexp.Sys binPath=C:\windows\temp\procexp.Sys type=kernel &amp;&amp; sc.exe start procexp.Sys
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

| Filename | procexp.Sys |
|:---- | ---- | 
| MD5 | <a href="https://www.virustotal.com/gui/file/97e3a44ec4ae58c8cc38eefc613e950e">97e3a44ec4ae58c8cc38eefc613e950e</a> |
| SHA1 | <a href="https://www.virustotal.com/gui/file/bc47e15537fa7c32dfefd23168d7e1741f8477ed">bc47e15537fa7c32dfefd23168d7e1741f8477ed</a> |
| SHA256 | <a href="https://www.virustotal.com/gui/file/440883cd9d6a76db5e53517d0ec7fe13d5a50d2f6a7f91ecfc863bc3490e4f5c">440883cd9d6a76db5e53517d0ec7fe13d5a50d2f6a7f91ecfc863bc3490e4f5c</a> |
| Authentihash MD5 | <a href="https://www.virustotal.com/gui/search/authentihash%253A0a7106a04e6e3b13eb105b013f76e031">0a7106a04e6e3b13eb105b013f76e031</a> || Authentihash SHA1 | <a href="https://www.virustotal.com/gui/search/authentihash%253A0c74316dfb9c21b7ff2dc288c005f9474dc26589">0c74316dfb9c21b7ff2dc288c005f9474dc26589</a> || Authentihash SHA256 | <a href="https://www.virustotal.com/gui/search/authentihash%253Ac7fef94e329bd9b66b281539265f989313356cbd9c345df9e670e9c4b6e0edce">c7fef94e329bd9b66b281539265f989313356cbd9c345df9e670e9c4b6e0edce</a> || Signature | Microsoft Windows Hardware Compatibility Publisher, Microsoft Windows Third Party Component CA 2012, Microsoft Root Certificate Authority 2010   || Company | Sysinternals - www.sysinternals.com || Description | Process Explorer || Product | Process Explorer || OriginalFilename | procexp.Sys |
#### Imports
{{< details "Expand" >}}* ntoskrnl.exe
{{< /details >}}
#### ImportedFunctions
{{< details "Expand" >}}* strncpy
* RtlInitUnicodeString
* RtlUnicodeStringToAnsiString
* RtlFreeAnsiString
* KeWaitForSingleObject
* ExAllocatePoolWithTag
* ExFreePoolWithTag
* ExGetPreviousMode
* MmGetSystemRoutineAddress
* SeCaptureSubjectContext
* SeReleaseSubjectContext
* IofCompleteRequest
* IoCreateSymbolicLink
* IoDeleteDevice
* IoDeleteSymbolicLink
* ObReferenceObjectByHandle
* ObfDereferenceObject
* ZwClose
* MmIsAddressValid
* PsGetVersion
* ZwOpenProcess
* KeStackAttachProcess
* KeUnstackDetachProcess
* SePrivilegeCheck
* PsLookupProcessByProcessId
* ObOpenObjectByPointer
* ObQueryNameString
* ZwQueryObject
* ZwDuplicateObject
* ZwOpenProcessToken
* ZwQueryInformationProcess
* ZwQuerySystemInformation
* ObCloseHandle
* ObOpenObjectByName
* __C_specific_handler
* IoFileObjectType
* PsProcessType
* PsThreadType
* RtlFreeUnicodeString
* IoCreateDevice
* ZwSetSecurityObject
* IoDeviceObjectType
* _snwprintf
* RtlLengthSecurityDescriptor
* SeCaptureSecurityDescriptor
* RtlCreateSecurityDescriptor
* RtlSetDaclSecurityDescriptor
* RtlAbsoluteToSelfRelativeSD
* IoIsWdmVersionAvailable
* SeExports
* wcschr
* _wcsnicmp
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
* KeBugCheckEx
{{< /details >}}
#### ExportedFunctions
{{< details "Expand" >}}{{< /details >}}



[*source*](https://github.com/magicsword-io/LOLDrivers/tree/main/yaml/procexp.yaml)

*last_updated:* 2023-04-17








{{< /column >}}
{{< /block >}}
