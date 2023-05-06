+++

description = ""
title = "Air_SYSTEM10.sys"
weight = 10

+++


{{< block "grid-1" >}}
{{< column "mt-2 pt-1">}}


# Air_SYSTEM10.sys ![:inline](/images/twitter_verified.png) 


### Description

Driver categorized as POORTRY by Mandiant.

- **Created**: 2023-03-03
- **Author**: Michael Haag
- **Acknowledgement**:  | [](https://twitter.com/)

{{< button "https://github.com/magicsword-io/LOLDrivers/raw/main/drivers/1f2888e57fdd6aee466962c25ba7d62d.bin" "Download" >}}
{{< tip "warning" >}}
This download link contains the malicious driver!

{{< /tip >}}

### Commands

```
sc.exe create Air_SYSTEM10.sys binPath=C:\windows\temp\Air_SYSTEM10.sys     type=kernel &amp;&amp; sc.exe start Air_SYSTEM10.sys
```

| Use Case | Privileges | Operating System | 
|:---- | ---- | ---- |
| Elevate privileges | kernel | Windows 10 |

### Resources
<br>
<li><a href="https://www.mandiant.com/resources/blog/hunting-attestation-signed-malware">https://www.mandiant.com/resources/blog/hunting-attestation-signed-malware</a></li>
<li><a href=""></a></li>
<br>

### Known Vulnerable Samples

| Property           | Value |
|:-------------------|:------|
| Filename           | Air_SYSTEM10.sys |
| MD5                | [1f2888e57fdd6aee466962c25ba7d62d](https://www.virustotal.com/gui/file/1f2888e57fdd6aee466962c25ba7d62d) |
| SHA1               | [c23eeb6f18f626ce1fd840227f351fa7543bb167](https://www.virustotal.com/gui/file/c23eeb6f18f626ce1fd840227f351fa7543bb167) |
| SHA256             | [f461414a2596555cece5cfee65a3c22648db0082ca211f6238af8230e41b3212](https://www.virustotal.com/gui/file/f461414a2596555cece5cfee65a3c22648db0082ca211f6238af8230e41b3212) |
| Authentihash MD5   | [6f562fc03c72abd6ff33c6df23df0219](https://www.virustotal.com/gui/search/authentihash%253A6f562fc03c72abd6ff33c6df23df0219) |
| Authentihash SHA1  | [7435b3f4c67217bfcdcfa9d940b12e5d5d6a22da](https://www.virustotal.com/gui/search/authentihash%253A7435b3f4c67217bfcdcfa9d940b12e5d5d6a22da) |
| Authentihash SHA256| [9c31a9fbf833b732b5f3f06c31e200994a65ce187260e66eff62278660dba4ef](https://www.virustotal.com/gui/search/authentihash%253A9c31a9fbf833b732b5f3f06c31e200994a65ce187260e66eff62278660dba4ef) |
| Signature         | Microsoft Windows Hardware Compatibility Publisher, Microsoft Windows Third Party Component CA 2014, Microsoft Root Certificate Authority 2010   |


#### Imports
{{< details "Expand" >}}
* FLTMGR.SYS
* ntoskrnl.exe

{{< /details >}}
#### ImportedFunctions
{{< details "Expand" >}}
* FltRegisterFilter
* FltUnregisterFilter
* FltStartFiltering
* FltGetFileNameInformation
* FltReleaseFileNameInformation
* FltParseFileNameInformation
* FltCreateCommunicationPort
* FltCloseCommunicationPort
* FltCloseClientPort
* FltBuildDefaultSecurityDescriptor
* FltFreeSecurityDescriptor
* FltGetRequestorProcess
* ExAllocatePoolWithTag
* DbgPrintEx
* PsSetLoadImageNotifyRoutine
* PsRemoveLoadImageNotifyRoutine
* strstr
* wcsstr
* RtlInitUnicodeString
* MmGetSystemRoutineAddress
* ExFreePoolWithTag
* IoCreateDevice
* IoGetCurrentProcess
* ObReferenceObjectByHandle
* ObfDereferenceObject
* MmIsAddressValid
* PsLookupProcessByProcessId
* PsGetProcessImageFileName
* __C_specific_handler
* PsProcessType
* ExInitializeRundownProtection
* ExAcquireRundownProtection
* ExReleaseRundownProtection
* ExWaitForRundownProtectionRelease
* PsCreateSystemThread
* PsTerminateSystemThread
* ZwClose
* PsGetCurrentProcessId
* KeStackAttachProcess
* KeUnstackDetachProcess
* ObOpenObjectByPointer
* ZwAllocateVirtualMemory
* ZwQueryVirtualMemory
* ZwProtectVirtualMemory
* PsGetProcessWow64Process
* strcpy_s
* ObRegisterCallbacks
* ObUnRegisterCallbacks
* ObGetFilterVersion
* RtlSetDaclSecurityDescriptor
* KeBugCheckEx
* RtlCompareUnicodeString
* KeDelayExecutionThread
* MmBuildMdlForNonPagedPool
* MmMapLockedPagesSpecifyCache
* MmUnmapLockedPages
* IoAllocateMdl
* MmCopyVirtualMemory
* PsGetProcessPeb
* ZwQuerySystemInformation

{{< /details >}}
#### ExportedFunctions
{{< details "Expand" >}}

{{< /details >}}
-----



[*source*](https://github.com/magicsword-io/LOLDrivers/tree/main/yaml/air_system10.yaml)

*last_updated:* 2023-05-06








{{< /column >}}
{{< /block >}}
