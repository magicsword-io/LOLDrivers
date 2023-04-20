+++

description = ""
title = "BlackBoneDrv10.sys"
weight = 10

+++


{{< block "grid-1" >}}
{{< column "mt-2 pt-1">}}


# BlackBoneDrv10.sys 


{{< tip "warning" >}}
We were not able to verify the hash of this driver successfully, it has not been confirmed.
{{< /tip >}}


### Description

BlackBoneDrv10.sys is a vulnerable driver and more information will be added as found.

- **Created**: 2023-01-09
- **Author**: Michael Haag
- **Acknowledgement**:  | [](https://twitter.com/)

{{< button "https://github.com/magicsword-io/LOLDrivers/raw/main/drivers/f7393fb917aed182e4cbef25ce8af950.bin" "Download" >}}
{{< tip "warning" >}}
This download link contains the vulnerable driver!

{{< /tip >}}

### Commands

```
sc.exe create BlackBoneDrv10.sys binPath=C:\windows\temp\BlackBoneDrv10.sys     type=kernel &amp;&amp; sc.exe start BlackBoneDrv10.sys
```

| Use Case | Privileges | Operating System | 
|:---- | ---- | ---- |
| Elevate privileges | kernel | Windows 10 |

### Resources
<br>
<li><a href=" https://learn.microsoft.com/en-us/windows/security/threat-protection/windows-defender-application-control/microsoft-recommended-driver-block-rules"> https://learn.microsoft.com/en-us/windows/security/threat-protection/windows-defender-application-control/microsoft-recommended-driver-block-rules</a></li>
<li><a href="https://learn.microsoft.com/en-us/windows/security/threat-protection/windows-defender-application-control/microsoft-recommended-driver-block-rules">https://learn.microsoft.com/en-us/windows/security/threat-protection/windows-defender-application-control/microsoft-recommended-driver-block-rules</a></li>
<br>

### Known Vulnerable Samples

| Property           | Value |
|:-------------------|:------|
| Filename           | BlackBoneDrv10.sys |
| MD5                | [f7393fb917aed182e4cbef25ce8af950](https://www.virustotal.com/gui/file/f7393fb917aed182e4cbef25ce8af950) |
| SHA1               | [3ee2fd08137e9262d2e911158090e4a7c7427ea0](https://www.virustotal.com/gui/file/3ee2fd08137e9262d2e911158090e4a7c7427ea0) |
| SHA256             | [f51bdb0ad924178131c21e39a8ccd191e46b5512b0f2e1cc8486f63e84e5d960](https://www.virustotal.com/gui/file/f51bdb0ad924178131c21e39a8ccd191e46b5512b0f2e1cc8486f63e84e5d960) |
| Authentihash MD5   | [068d02b18a4c87366e8d54200f319e50](https://www.virustotal.com/gui/search/authentihash%253A068d02b18a4c87366e8d54200f319e50) |
| Authentihash SHA1  | [79ef55ea5d6cab924abb722d501e9b950fdae904](https://www.virustotal.com/gui/search/authentihash%253A79ef55ea5d6cab924abb722d501e9b950fdae904) |
| Authentihash SHA256| [a4ac619fb531793945ad4c72bdd809ebd38512fc234aa452cb8364ee05465a7b](https://www.virustotal.com/gui/search/authentihash%253Aa4ac619fb531793945ad4c72bdd809ebd38512fc234aa452cb8364ee05465a7b) |
| Signature         | Nanjing Zhixiao Information Technology Co.,Ltd, VeriSign Class 3 Code Signing 2010 CA, VeriSign   |


#### Imports
{{< details "Expand" >}}
* ntoskrnl.exe

{{< /details >}}
#### ImportedFunctions
{{< details "Expand" >}}
* RtlUnicodeStringToInteger
* RtlInitAnsiString
* DbgPrintEx
* RtlGetVersion
* KeInitializeGuardedMutex
* ExAllocatePoolWithTag
* ExFreePoolWithTag
* IoCreateDevice
* IoCreateSymbolicLink
* IoDeleteDevice
* IoDeleteSymbolicLink
* ZwClose
* ZwOpenKey
* ZwQueryValueKey
* RtlInitializeGenericTableAvl
* RtlCompareString
* PsSetCreateProcessNotifyRoutine
* RtlImageNtHeader
* IofCompleteRequest
* RtlInitUnicodeString
* KeDelayExecutionThread
* ProbeForRead
* IoGetCurrentProcess
* ObfDereferenceObject
* KeStackAttachProcess
* KeUnstackDetachProcess
* PsIsThreadTerminating
* PsLookupProcessByProcessId
* ZwAllocateVirtualMemory
* ZwFreeVirtualMemory
* PsGetProcessWow64Process
* PsIsProtectedProcess
* ZwProtectVirtualMemory
* __C_specific_handler
* RtlImageDirectoryEntryToData
* RtlAnsiStringToUnicodeString
* RtlCompareUnicodeString
* RtlAppendUnicodeToString
* RtlFreeUnicodeString
* KeWaitForSingleObject
* MmMapLockedPagesSpecifyCache
* MmAllocatePagesForMdl
* MmFreePagesFromMdl
* PsCreateSystemThread
* PsTerminateSystemThread
* PsWrapApcWow64Thread
* ObReferenceObjectByHandle
* ZwCreateFile
* ZwQueryInformationFile
* ZwReadFile
* PsGetCurrentThreadId
* PsGetProcessId
* PsLookupThreadByThreadId
* ZwWaitForSingleObject
* ZwQuerySystemInformation
* ZwQueryInformationThread
* PsGetProcessPeb
* PsGetThreadTeb
* PsGetCurrentProcessWow64Process
* KeTestAlertThread
* KeInitializeApc
* KeInsertQueueApc
* PsThreadType
* RtlCopyUnicodeString
* KeResetEvent
* ZwWriteFile
* RtlRandomEx
* RtlCreateUnicodeString
* RtlDowncaseUnicodeString
* ZwCreateEvent
* ZwDeleteFile
* ZwQueryInformationProcess
* _vsnwprintf
* ExEventObjectType
* KeAcquireGuardedMutex
* KeReleaseGuardedMutex
* MmGetSystemRoutineAddress
* RtlCaptureContext
* KeCapturePersistentThreadState
* ProbeForWrite
* MmProbeAndLockPages
* MmUnlockPages
* MmBuildMdlForNonPagedPool
* MmUnmapLockedPages
* IoAllocateMdl
* IoFreeMdl
* ObCloseHandle
* ZwOpenFile
* RtlInsertElementGenericTableAvl
* RtlDeleteElementGenericTableAvl
* RtlLookupElementGenericTableAvl
* RtlEnumerateGenericTableAvl
* RtlIsGenericTableEmptyAvl
* PsGetCurrentProcessId
* ZwQueryVirtualMemory
* MmHighestUserAddress
* MmCopyVirtualMemory
* ExEnumHandleTable
* ExfUnblockPushLock
* RtlCompareUnicodeStrings

{{< /details >}}
#### ExportedFunctions
{{< details "Expand" >}}

{{< /details >}}
-----



[*source*](https://github.com/magicsword-io/LOLDrivers/tree/main/yaml/blackbonedrv10.yaml)

*last_updated:* 2023-04-20








{{< /column >}}
{{< /block >}}
