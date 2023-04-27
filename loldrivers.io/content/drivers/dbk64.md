+++

description = ""
title = "dbk64.sys"
weight = 10

+++


{{< block "grid-1" >}}
{{< column "mt-2 pt-1">}}


# dbk64.sys ![:inline](/images/twitter_verified.png) 


### Description

dbk64.sys is a vulnerable driver and more information will be added as found.

- **Created**: 2023-01-09
- **Author**: Michael Haag
- **Acknowledgement**:  | [](https://twitter.com/)

{{< button "https://github.com/magicsword-io/LOLDrivers/raw/main/drivers/1c294146fc77565030603878fd0106f9.bin" "Download" >}}
{{< tip "warning" >}}
This download link contains the vulnerable driver!

{{< /tip >}}

### Commands

```
sc.exe create dbk64.sys binPath=C:\windows\temp\dbk64.sys type=kernel &amp;&amp; sc.exe start dbk64.sys
```

| Use Case | Privileges | Operating System | 
|:---- | ---- | ---- |
| Elevate privileges | kernel | Windows 10 |

### Resources
<br>
<li><a href=" https://github.com/eclypsium/Screwed-Drivers/blob/master/DRIVERS.md"> https://github.com/eclypsium/Screwed-Drivers/blob/master/DRIVERS.md</a></li>
<li><a href="https://github.com/eclypsium/Screwed-Drivers/blob/master/DRIVERS.md">https://github.com/eclypsium/Screwed-Drivers/blob/master/DRIVERS.md</a></li>
<br>

### Known Vulnerable Samples

| Property           | Value |
|:-------------------|:------|
| Filename           | dbk64.sys |
| MD5                | [1c294146fc77565030603878fd0106f9](https://www.virustotal.com/gui/file/1c294146fc77565030603878fd0106f9) |
| SHA1               | [6053d258096bccb07cb0057d700fe05233ab1fbb](https://www.virustotal.com/gui/file/6053d258096bccb07cb0057d700fe05233ab1fbb) |
| SHA256             | [18e1707b319c279c7e0204074088cc39286007a1cf6cb6e269d5067d8d0628c6](https://www.virustotal.com/gui/file/18e1707b319c279c7e0204074088cc39286007a1cf6cb6e269d5067d8d0628c6) |
| Authentihash MD5   | [50dadd183094b8711a4f00a198972e6b](https://www.virustotal.com/gui/search/authentihash%253A50dadd183094b8711a4f00a198972e6b) |
| Authentihash SHA1  | [d7512b033d7332edd747631f9d1ccc9276dadbe4](https://www.virustotal.com/gui/search/authentihash%253Ad7512b033d7332edd747631f9d1ccc9276dadbe4) |
| Authentihash SHA256| [71dc8d678e0749599d3db144c93741f64def1b8b0efb98bef963d2215ebb4992](https://www.virustotal.com/gui/search/authentihash%253A71dc8d678e0749599d3db144c93741f64def1b8b0efb98bef963d2215ebb4992) |
| Signature         | Cheat Engine, GlobalSign Extended Validation CodeSigning CA - SHA256 - G3, GlobalSign, GlobalSign Root CA - R1   |


#### Imports
{{< details "Expand" >}}
* ksecdd.sys
* ntoskrnl.exe
* WDFLDR.SYS

{{< /details >}}
#### ImportedFunctions
{{< details "Expand" >}}
* BCryptVerifySignature
* BCryptCreateHash
* BCryptDestroyKey
* BCryptFinishHash
* BCryptDestroyHash
* BCryptImportKeyPair
* BCryptCloseAlgorithmProvider
* BCryptGetProperty
* BCryptHashData
* BCryptOpenAlgorithmProvider
* ExDeleteResourceLite
* MmGetSystemRoutineAddress
* MmAllocateContiguousMemory
* IofCompleteRequest
* IoCreateDevice
* IoCreateSymbolicLink
* IoDeleteDevice
* IoDeleteSymbolicLink
* ObUnRegisterCallbacks
* ZwClose
* ZwOpenKey
* ZwQueryValueKey
* SeSinglePrivilegeCheck
* PsSetCreateProcessNotifyRoutineEx
* KeInitializeDpc
* KeInsertQueueDpc
* KeSetTargetProcessorDpc
* KeFlushQueuedDpcs
* KeRevertToUserAffinityThreadEx
* KeSetSystemAffinityThreadEx
* KeQueryActiveProcessors
* KeInitializeEvent
* KeSetEvent
* KeWaitForSingleObject
* PsGetCurrentProcessId
* PsGetCurrentThreadId
* KeDelayExecutionThread
* ExAcquireResourceExclusiveLite
* ExReleaseResourceLite
* MmProbeAndLockPages
* MmUnlockPages
* MmMapLockedPagesSpecifyCache
* MmUnmapLockedPages
* PsWrapApcWow64Thread
* IoAllocateMdl
* IoFreeMdl
* IoGetCurrentProcess
* ObReferenceObjectByHandle
* ObfDereferenceObject
* ObRegisterCallbacks
* ZwOpenSection
* ZwMapViewOfSection
* ZwUnmapViewOfSection
* MmGetPhysicalMemoryRanges
* MmGetPhysicalAddress
* PsSetCreateThreadNotifyRoutine
* PsGetProcessId
* PsGetThreadProcessId
* ExFreePoolWithTag
* KeDetachProcess
* KeStackAttachProcess
* KeUnstackDetachProcess
* PsLookupProcessByProcessId
* ObOpenObjectByPointer
* ZwAllocateVirtualMemory
* KeInitializeApc
* KeInsertQueueApc
* ZwOpenThread
* ZwQueryInformationProcess
* PsProcessType
* PsThreadType
* DbgBreakPointWithStatus
* RtlGetVersion
* ExAllocatePoolWithTag
* MmGetVirtualForPhysical
* PsLookupThreadByThreadId
* __C_specific_handler
* KeQueryActiveProcessorCount
* KeClearEvent
* ExAcquireResourceSharedLite
* RtlInitializeGenericTable
* RtlInsertElementGenericTable
* RtlDeleteElementGenericTable
* RtlLookupElementGenericTable
* RtlGetElementGenericTable
* KeReleaseSemaphore
* KeInitializeSemaphore
* KeWaitForMultipleObjects
* ExAcquireFastMutex
* ExReleaseFastMutex
* MmBuildMdlForNonPagedPool
* ZwCreateFile
* ZwWriteFile
* HalDispatchTable
* KeInitializeMutex
* KeReleaseMutex
* KeSetSystemAffinityThread
* KeQueryMaximumProcessorCount
* MmAllocateContiguousMemorySpecifyCache
* MmFreeContiguousMemory
* PsCreateSystemThread
* ZwDeleteFile
* ZwWaitForSingleObject
* swprintf_s
* MmMapIoSpace
* MmUnmapIoSpace
* KeAcquireSpinLockAtDpcLevel
* KeReleaseSpinLockFromDpcLevel
* MmAllocatePagesForMdl
* ZwQueryInformationFile
* ZwReadFile
* RtlAppendUnicodeToString
* RtlUnwindEx
* RtlAnsiCharToUnicodeChar
* KeBugCheckEx
* ExInitializeResourceLite
* RtlCopyUnicodeString
* ExAllocatePool
* DbgPrint
* RtlInitUnicodeString
* KeAttachProcess
* WdfVersionBind
* WdfVersionBindClass
* WdfVersionUnbindClass
* WdfVersionUnbind

{{< /details >}}
#### ExportedFunctions
{{< details "Expand" >}}

{{< /details >}}
-----



[*source*](https://github.com/magicsword-io/LOLDrivers/tree/main/yaml/dbk64.yaml)

*last_updated:* 2023-04-27








{{< /column >}}
{{< /block >}}
