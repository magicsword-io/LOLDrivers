+++

description = ""
title = "amp.sys"
weight = 10

+++


{{< block "grid-1" >}}
{{< column "mt-2 pt-1">}}


# amp.sys ![:inline](/images/twitter_verified.png) 


### Description

amp.sys is a vulnerable driver and more information will be added as found.

- **Created**: 2023-01-09
- **Author**: Michael Haag
- **Acknowledgement**:  | [](https://twitter.com/)

{{< button "https://github.com/magicsword-io/LOLDrivers/raw/main/drivers/c533d6d64b474ffc3169a0e0fc0a701a.bin" "Download" >}}
{{< tip "warning" >}}
This download link contains the malcious driver!
{{< /tip >}}

### Commands

```
sc.exe create amp.sys binPath=C:\windows\temp\amp.sys type=kernel &amp;&amp; sc.exe start amp.sys
```

| Use Case | Privileges | Operating System | 
|:---- | ---- | ---- |
| Elevate privileges | kernel | Windows 10 |

### Resources
<br>
<li><a href=" https://gist.github.com/k4nfr3/af970e7facb09195e56f2112e1c9549c"> https://gist.github.com/k4nfr3/af970e7facb09195e56f2112e1c9549c</a></li>
<li><a href="https://gist.github.com/k4nfr3/af970e7facb09195e56f2112e1c9549c">https://gist.github.com/k4nfr3/af970e7facb09195e56f2112e1c9549c</a></li>
<br>

### Known Vulnerable Samples

| Filename | amp.sys |
|:---- | ---- | 
| MD5 | <a href="https://www.virustotal.com/gui/file/c533d6d64b474ffc3169a0e0fc0a701a">c533d6d64b474ffc3169a0e0fc0a701a</a> |
| SHA1 | <a href="https://www.virustotal.com/gui/file/3f223581409492172a1e875f130f3485b90fbe5f">3f223581409492172a1e875f130f3485b90fbe5f</a> |
| SHA256 | <a href="https://www.virustotal.com/gui/file/cbb8239a765bf5b2c1b6a5c8832d2cab8fef5deacadfb65d8ed43ef56d291ab6">cbb8239a765bf5b2c1b6a5c8832d2cab8fef5deacadfb65d8ed43ef56d291ab6</a> |
| Authentihash MD5 | <a href="https://www.virustotal.com/gui/search/authentihash%253A74ee74d20c3afc42d7722a88aacf3671">74ee74d20c3afc42d7722a88aacf3671</a> || Authentihash SHA1 | <a href="https://www.virustotal.com/gui/search/authentihash%253A87a84133f5e4c12d2d4a42fcc3be84b43a6202b5">87a84133f5e4c12d2d4a42fcc3be84b43a6202b5</a> || Authentihash SHA256 | <a href="https://www.virustotal.com/gui/search/authentihash%253Aa37371c4e62f106e7da03fd5bdd6f12ecdf7fcaf1195dbf9fb7ef6eb456a7506">a37371c4e62f106e7da03fd5bdd6f12ecdf7fcaf1195dbf9fb7ef6eb456a7506</a> || Signature | -   || Company | CYREN Inc. || Description | AMP Minifilter || Product | CYREN AMP 5 || OriginalFilename | amp.sys |
#### Imports
{{< details "Expand" >}}* ntoskrnl.exe
* FLTMGR.SYS
{{< /details >}}
#### ImportedFunctions
{{< details "Expand" >}}* ObfDereferenceObject
* ObQueryNameString
* RtlIntegerToUnicodeString
* IoGetCurrentProcess
* _strnicmp
* MmIsAddressValid
* _strupr
* MmGetSystemRoutineAddress
* PsGetVersion
* ExInitializeResourceLite
* ExDeleteResourceLite
* KeEnterCriticalRegion
* ExAcquireResourceSharedLite
* ExReleaseResourceForThreadLite
* KeLeaveCriticalRegion
* ExAcquireResourceExclusiveLite
* wcschr
* wcsrchr
* ZwQueryInformationFile
* ZwSetInformationFile
* ZwReadFile
* ZwWriteFile
* ExUuidCreate
* ObReferenceObjectByHandle
* _wcsupr
* wcsncmp
* IoGetTopLevelIrp
* IoSetTopLevelIrp
* IoGetStackLimits
* ObfReferenceObject
* ZwOpenDirectoryObject
* ZwOpenSymbolicLinkObject
* ZwQuerySymbolicLinkObject
* RtlFreeUnicodeString
* KeSetEvent
* RtlTimeToTimeFields
* swprintf
* _wcsicmp
* ExSystemTimeToLocalTime
* KeWaitForMultipleObjects
* KeResetEvent
* PsTerminateSystemThread
* PsGetCurrentProcessId
* wcsncpy
* PsCreateSystemThread
* PsGetCurrentThreadId
* ZwOpenProcess
* ZwQueryInformationProcess
* IoAllocateErrorLogEntry
* IoWriteErrorLogEntry
* IoAllocateWorkItem
* IoQueueWorkItem
* IoFreeWorkItem
* ExReleaseResourceLite
* ZwCreateKey
* ZwSetValueKey
* ZwQueryValueKey
* RtlInitAnsiString
* RtlAnsiStringToUnicodeString
* RtlUnicodeStringToAnsiString
* RtlCopyUnicodeString
* IoGetDeviceObjectPointer
* IoBuildDeviceIoControlRequest
* KeWaitForSingleObject
* IofCallDriver
* KeInitializeEvent
* RtlCompareString
* RtlInitString
* ExAllocatePoolWithTag
* KeDelayExecutionThread
* IofCompleteRequest
* IoIs32bitProcess
* ZwLoadDriver
* ZwUnloadDriver
* RtlInitUnicodeString
* IoCreateSymbolicLink
* IoCreateDevice
* IoDeleteDevice
* IoDeleteSymbolicLink
* ZwClose
* ExAllocatePool
* ZwCreateFile
* ExFreePool
* RtlUnicodeStringToInteger
* strncmp
* _wcsnicmp
* strchr
* KeReleaseSpinLock
* KeAcquireSpinLockRaiseToDpc
* ExInitializeNPagedLookasideList
* ExpInterlockedPushEntrySList
* ExpInterlockedPopEntrySList
* ExDeletePagedLookasideList
* ExQueryDepthSList
* ExInitializePagedLookasideList
* ExDeleteNPagedLookasideList
* __C_specific_handler
* _local_unwind
* FltGetVolumeFromInstance
* FltSetCallbackDataDirty
* FltGetFileNameInformation
* FltReleaseFileNameInformation
* FltGetVolumeProperties
* FltStartFiltering
* FltRegisterFilter
* FltGetRoutineAddress
* FltGetDiskDeviceObject
* FltUnregisterFilter
* FltGetTunneledName
* FltGetDestinationFileNameInformation
* FltGetStreamHandleContext
* FltSetStreamHandleContext
* FltCancelFileOpen
* FltCreateFile
* FltObjectReference
* FltReleaseContext
* FltSetInstanceContext
* FltAllocateContext
* FltGetInstanceContext
* FltEnumerateInstances
* FltGetVolumeFromName
* FltObjectDereference
* FltGetFileNameInformationUnsafe
* FltQueryInformationFile
* FltClose
* FltFlushBuffers
{{< /details >}}
#### ExportedFunctions
{{< details "Expand" >}}{{< /details >}}



[*source*](https://github.com/magicsword-io/LOLDrivers/tree/main/yaml/amp.yaml)

*last_updated:* 2023-04-17








{{< /column >}}
{{< /block >}}
