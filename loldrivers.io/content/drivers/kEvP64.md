+++

description = ""
title = "kEvP64.sys"
weight = 10

+++


{{< block "grid-1" >}}
{{< column "mt-2 pt-1">}}


# kEvP64.sys ![:inline](/images/twitter_verified.png) 


### Description

kEvP64.sys is a vulnerable driver and more information will be added as found.

- **Created**: 2023-01-09
- **Author**: Michael Haag
- **Acknowledgement**:  | [](https://twitter.com/)

{{< button "https://github.com/magicsword-io/LOLDrivers/raw/main/drivers/20125794b807116617d43f02b616e092.bin" "Download" >}}
{{< tip "warning" >}}
This download link contains the vulnerable driver!

{{< /tip >}}

### Commands

```
sc.exe create kEvP64.sys binPath=C:\windows\temp\kEvP64.sys type=kernel &amp;&amp; sc.exe start kEvP64.sys
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
| Filename           | kEvP64.sys |
| MD5                | [20125794b807116617d43f02b616e092](https://www.virustotal.com/gui/file/20125794b807116617d43f02b616e092) |
| SHA1               | [f3db629cfe37a73144d5258e64d9dd8b38084cf4](https://www.virustotal.com/gui/file/f3db629cfe37a73144d5258e64d9dd8b38084cf4) |
| SHA256             | [1aaa9aef39cb3c0a854ecb4ca7d3b213458f302025e0ec5bfbdef973cca9111c](https://www.virustotal.com/gui/file/1aaa9aef39cb3c0a854ecb4ca7d3b213458f302025e0ec5bfbdef973cca9111c) |
| Authentihash MD5   | [89184d56336f62fecc67f644b1ec4219](https://www.virustotal.com/gui/search/authentihash%253A89184d56336f62fecc67f644b1ec4219) |
| Authentihash SHA1  | [cd773a4b5aef78bda651069b9304e4d5e2033cb9](https://www.virustotal.com/gui/search/authentihash%253Acd773a4b5aef78bda651069b9304e4d5e2033cb9) |
| Authentihash SHA256| [c7ba2720675aada538c47fa9e8950a81b6df23f63fa181680e6232651abffbef](https://www.virustotal.com/gui/search/authentihash%253Ac7ba2720675aada538c47fa9e8950a81b6df23f63fa181680e6232651abffbef) |
| Signature         | 北京华林保软件技术有限公司, VeriSign Class 3 Code Signing 2010 CA, VeriSign   |
| Company           | PowerTool |
| Description       | PowerTool |
| Product           | PowerTool |
| OriginalFilename  | kEvP64.sys |


#### Imports
{{< details "Expand" >}}
* ntoskrnl.exe
* HAL.dll
* FLTMGR.SYS

{{< /details >}}
#### ImportedFunctions
{{< details "Expand" >}}
* ProbeForRead
* KeClearEvent
* PsProcessType
* IoReuseIrp
* ObRegisterCallbacks
* IoBuildDeviceIoControlRequest
* IoDeleteSymbolicLink
* ExFreePoolWithTag
* RtlAnsiStringToUnicodeString
* ObUnRegisterCallbacks
* PsGetProcessImageFileName
* PsRemoveCreateThreadNotifyRoutine
* PsLookupProcessByProcessId
* ZwQuerySymbolicLinkObject
* _wcsnicmp
* SeCreateAccessState
* KeInitializeApc
* IoGetRelatedDeviceObject
* RtlInitUnicodeString
* IoDeleteDevice
* KeSetEvent
* ExGetPreviousMode
* ProbeForWrite
* IoGetFileObjectGenericMapping
* swprintf
* ObCreateObject
* ObGetFilterVersion
* MmGetSystemRoutineAddress
* IoCreateFile
* KeInitializeEvent
* RtlInitAnsiString
* RtlUnicodeStringToAnsiString
* RtlGetVersion
* ZwQuerySystemInformation
* ExReleaseRundownProtection
* PsSetCreateProcessNotifyRoutine
* MmUnmapIoSpace
* RtlEqualUnicodeString
* MmBuildMdlForNonPagedPool
* ZwOpenSymbolicLinkObject
* IoFreeMdl
* KeUnstackDetachProcess
* ExInitializeRundownProtection
* ZwOpenDirectoryObject
* IoVolumeDeviceToDosName
* KeDelayExecutionThread
* RtlFreeUnicodeString
* ExEnumHandleTable
* ObQueryNameString
* ExAllocatePoolWithTag
* IoDriverObjectType
* ZwCreateFile
* wcsstr
* MmMapLockedPagesSpecifyCache
* IoGetDeviceObjectPointer
* IoStopTimer
* ExAllocatePool
* IoUnregisterShutdownNotification
* IoGetCurrentProcess
* MmMapIoSpace
* NtClose
* ZwClose
* IofCompleteRequest
* ObReferenceObjectByHandle
* KeWaitForSingleObject
* ZwQueryDirectoryObject
* PsRemoveLoadImageNotifyRoutine
* IoFreeIrp
* MmProbeAndLockPages
* PsThreadType
* RtlCompareUnicodeString
* IoAllocateIrp
* ObSetHandleAttributes
* MmUnlockPages
* ZwQueryInformationProcess
* IoCreateSymbolicLink
* MmIsAddressValid
* ObfDereferenceObject
* ObReferenceObjectByName
* IoCreateDevice
* ZwTerminateProcess
* RtlAssert
* KeCancelTimer
* CmUnRegisterCallback
* ObOpenObjectByPointer
* DbgPrint
* KeStackAttachProcess
* PsGetProcessWow64Process
* IoAllocateMdl
* IofCallDriver
* KeBugCheckEx
* IoThreadToProcess
* ExAcquireRundownProtection
* sprintf
* PsGetProcessPeb
* ExWaitForRundownProtectionRelease
* _wcsicmp
* _stricmp
* IoFileObjectType
* __C_specific_handler
* HalSetBusDataByOffset
* KeStallExecutionProcessor
* HalGetBusDataByOffset
* FltUnregisterFilter
* FltEnumerateFilters
* FltObjectDereference
* FltRegisterFilter

{{< /details >}}
#### ExportedFunctions
{{< details "Expand" >}}

{{< /details >}}


[*source*](https://github.com/magicsword-io/LOLDrivers/tree/main/yaml/kevp64.yaml)

*last_updated:* 2023-04-19








{{< /column >}}
{{< /block >}}
