+++

description = ""
title = "aswVmm.sys"
weight = 10

+++


{{< block "grid-1" >}}
{{< column "mt-2 pt-1">}}


# aswVmm.sys ![:inline](/images/twitter_verified.png) 


### Description

aswVmm.sys is a vulnerable driver and more information will be added as found.

- **Created**: 2023-01-09
- **Author**: Michael Haag
- **Acknowledgement**:  | [](https://twitter.com/)

{{< button "https://github.com/magicsword-io/LOLDrivers/raw/main/drivers/a5f637d61719d37a5b4868c385e363c0.bin" "Download" >}}
{{< tip "warning" >}}
This download link contains the vulnerable driver!

{{< /tip >}}

### Commands

```
sc.exe create aswVmm.sys binPath=C:\windows\temp\aswVmm.sys type=kernel &amp;&amp; sc.exe start aswVmm.sys
```

| Use Case | Privileges | Operating System | 
|:---- | ---- | ---- |
| Elevate privileges | kernel | Windows 10 |

### Resources
<br>
<li><a href=" https://github.com/elastic/protections-artifacts/search?q=VulnDriver"> https://github.com/elastic/protections-artifacts/search?q=VulnDriver</a></li>
<li><a href="https://github.com/tanduRE/AvastHV">https://github.com/tanduRE/AvastHV</a></li>
<li><a href="https://github.com/elastic/protections-artifacts/search?q=VulnDriver">https://github.com/elastic/protections-artifacts/search?q=VulnDriver</a></li>
<br>

### Known Vulnerable Samples

| Filename | aswVmm.sys |
|:---- | ---- | 
| MD5 | <a href="https://www.virustotal.com/gui/file/a5f637d61719d37a5b4868c385e363c0">a5f637d61719d37a5b4868c385e363c0</a> |
| SHA1 | <a href="https://www.virustotal.com/gui/file/34c85afe6d84cd3deec02c0a72e5abfa7a2886c3">34c85afe6d84cd3deec02c0a72e5abfa7a2886c3</a> |
| SHA256 | <a href="https://www.virustotal.com/gui/file/36505921af5a09175395ebaea29c72b2a69a3a9204384a767a5be8a721f31b10">36505921af5a09175395ebaea29c72b2a69a3a9204384a767a5be8a721f31b10</a> |
| Authentihash MD5 | <a href="https://www.virustotal.com/gui/search/authentihash%253A14260121e1984480cf6e7ec1adead3a3">14260121e1984480cf6e7ec1adead3a3</a> || Authentihash SHA1 | <a href="https://www.virustotal.com/gui/search/authentihash%253Abce48d80831090b849b7f0d2f9dffd36ec44d894">bce48d80831090b849b7f0d2f9dffd36ec44d894</a> || Authentihash SHA256 | <a href="https://www.virustotal.com/gui/search/authentihash%253Aa2b0b2e9e458016b22ebbf47411008f0a87efd9103b125870ce37246ab5bdff0">a2b0b2e9e458016b22ebbf47411008f0a87efd9103b125870ce37246ab5bdff0</a> || Signature | AVAST Software, VeriSign Class 3 Code Signing 2010 CA, VeriSign   || Company | AVAST Software || Description | avast! VM Monitor || Product | avast! Antivirus || OriginalFilename | aswVmm.sys |
#### Imports
{{< details "Expand" >}}* ntoskrnl.exe
* HAL.dll
{{< /details >}}
#### ImportedFunctions
{{< details "Expand" >}}* memcpy
* IoDeleteDevice
* ZwClose
* IoDeleteSymbolicLink
* RtlInitUnicodeString
* ExDeleteResourceLite
* IoReleaseRemoveLockAndWaitEx
* KeCancelTimer
* ExFreePoolWithTag
* IoUnregisterShutdownNotification
* KeSetTimerEx
* KeInitializeDpc
* KeInitializeTimerEx
* IoCreateSymbolicLink
* KeInitializeEvent
* IoRegisterShutdownNotification
* RtlAppendUnicodeToString
* RtlCopyUnicodeString
* ExAllocatePoolWithTag
* ExInitializeResourceLite
* IoAcquireRemoveLockEx
* IoInitializeRemoveLockEx
* IoIsWdmVersionAvailable
* KeQueryActiveProcessors
* InitSafeBootMode
* MmFreeContiguousMemory
* MmGetPhysicalAddress
* _allrem
* _alldiv
* MmUnmapIoSpace
* MmMapIoSpace
* MmFreePagesFromMdl
* MmUnmapLockedPages
* MmMapLockedPagesSpecifyCache
* IoReleaseRemoveLockEx
* IofCompleteRequest
* KeLeaveCriticalRegion
* ExReleaseResourceLite
* ExAcquireResourceExclusiveLite
* KeEnterCriticalRegion
* ExAcquireResourceSharedLite
* IoFreeMdl
* MmUnlockPages
* MmProbeAndLockPages
* IoAllocateMdl
* RtlLookupElementGenericTableAvl
* RtlDeleteElementGenericTableAvl
* RtlInsertElementGenericTableAvl
* _aullshr
* KeUnstackDetachProcess
* KeStackAttachProcess
* PsLookupProcessByProcessId
* RtlInitializeGenericTableAvl
* RtlEnumerateGenericTableAvl
* RtlIsGenericTableEmptyAvl
* ZwOpenFile
* _allshr
* _allmul
* MmIsAddressValid
* MmGetSystemRoutineAddress
* IoFreeWorkItem
* PsGetProcessWin32Process
* IoGetCurrentProcess
* IoQueueWorkItem
* IoAllocateWorkItem
* MmAllocateContiguousMemorySpecifyCache
* ExRegisterCallback
* ExCreateCallback
* ExUnregisterCallback
* PsRemoveLoadImageNotifyRoutine
* PsSetLoadImageNotifyRoutine
* PsSetCreateProcessNotifyRoutine
* KeResetEvent
* KeSetEvent
* MmGetPhysicalMemoryRanges
* MmAllocatePagesForMdl
* RtlCheckRegistryKey
* RtlCompareUnicodeString
* ZwCreateKey
* ZwQueryValueKey
* PsTerminateSystemThread
* KeWaitForSingleObject
* KeSetSystemAffinityThread
* KeSetPriorityThread
* ObReferenceObjectByHandle
* PsThreadType
* PsCreateSystemThread
* KeWaitForMultipleObjects
* DbgPrint
* MmFreeMappingAddress
* MmAllocateMappingAddress
* ProbeForRead
* ExGetPreviousMode
* KeTickCount
* KeBugCheckEx
* _allshl
* memset
* ObfDereferenceObject
* ZwSetSecurityObject
* ObOpenObjectByPointer
* IoDeviceObjectType
* IoCreateDevice
* RtlUnwind
* RtlGetDaclSecurityDescriptor
* RtlGetSaclSecurityDescriptor
* RtlGetGroupSecurityDescriptor
* RtlGetOwnerSecurityDescriptor
* _snwprintf
* RtlLengthSecurityDescriptor
* SeCaptureSecurityDescriptor
* SeExports
* _wcsnicmp
* RtlAddAccessAllowedAce
* RtlLengthSid
* wcschr
* RtlAbsoluteToSelfRelativeSD
* RtlSetDaclSecurityDescriptor
* RtlCreateSecurityDescriptor
* ZwOpenKey
* ZwSetValueKey
* RtlFreeUnicodeString
* ZwUnmapViewOfSection
* ZwMapViewOfSection
* ZwCreateSection
* KfLowerIrql
* KeGetCurrentIrql
* KeRaiseIrqlToDpcLevel
{{< /details >}}
#### ExportedFunctions
{{< details "Expand" >}}{{< /details >}}



[*source*](https://github.com/magicsword-io/LOLDrivers/tree/main/yaml/aswvmm.yaml)

*last_updated:* 2023-04-19








{{< /column >}}
{{< /block >}}
