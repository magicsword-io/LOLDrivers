+++

description = ""
title = "HwOs2Ec10x64.sys"
weight = 10

+++


{{< block "grid-1" >}}
{{< column "mt-2 pt-1">}}


# HwOs2Ec10x64.sys ![:inline](/images/twitter_verified.png) 


### Description

HwOs2Ec10x64.sys is a vulnerable driver and more information will be added as found.

- **Created**: 2023-01-09
- **Author**: Michael Haag
- **Acknowledgement**:  | [](https://twitter.com/)

{{< button "https://github.com/magicsword-io/LOLDrivers/raw/main/drivers/37086ae5244442ba552803984a11d6cb.bin" "Download" >}}
{{< tip "warning" >}}
This download link contains the vulnerable driver!

{{< /tip >}}

### Commands

```
sc.exe create HwOs2Ec10x64.sys binPath=C:\windows\temp\HwOs2Ec10x64.sys     type=kernel &amp;&amp; sc.exe start HwOs2Ec10x64.sys
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
| Filename           | HwOs2Ec10x64.sys |
| MD5                | [37086ae5244442ba552803984a11d6cb](https://www.virustotal.com/gui/file/37086ae5244442ba552803984a11d6cb) |
| SHA1               | [dc0e97adb756c0f30b41840a59b85218cbdd198f](https://www.virustotal.com/gui/file/dc0e97adb756c0f30b41840a59b85218cbdd198f) |
| SHA256             | [bb1135b51acca8348d285dc5461d10e8f57260e7d0c8cc4a092734d53fc40cbc](https://www.virustotal.com/gui/file/bb1135b51acca8348d285dc5461d10e8f57260e7d0c8cc4a092734d53fc40cbc) |
| Authentihash MD5   | [20be6af18d3b97968b2a8d5a9513caaa](https://www.virustotal.com/gui/search/authentihash%253A20be6af18d3b97968b2a8d5a9513caaa) |
| Authentihash SHA1  | [b6a4ef3babbd79479723b8586ea0e8c7a33d1661](https://www.virustotal.com/gui/search/authentihash%253Ab6a4ef3babbd79479723b8586ea0e8c7a33d1661) |
| Authentihash SHA256| [ab494aba56e9ea7b6055ac437f6b678e7239b0fda54bf28019480565a098a6e3](https://www.virustotal.com/gui/search/authentihash%253Aab494aba56e9ea7b6055ac437f6b678e7239b0fda54bf28019480565a098a6e3) |
| Signature         | Huawei Technologies Co., Ltd., Symantec Class 3 Extended Validation Code Signing CA - G2, VeriSign   |
| Company           | Huawei |
| Description       | HwOs2Ec |
| Product           | Huawei MateBook |
| OriginalFilename  | HwOs2Ec.sys |


#### Imports
{{< details "Expand" >}}
* ntoskrnl.exe
* HAL.dll

{{< /details >}}
#### ImportedFunctions
{{< details "Expand" >}}
* IoCreateDevice
* IoCreateSymbolicLink
* IoDeleteDevice
* IoDeleteSymbolicLink
* IoGetCurrentProcess
* InitSafeBootMode
* memcpy_s
* _wcsnicmp
* RtlInitUnicodeString
* RtlEqualUnicodeString
* RtlCopyUnicodeString
* RtlAppendUnicodeToString
* KeEnterCriticalRegion
* KeLeaveCriticalRegion
* ExAllocatePool
* ExAllocatePoolWithTag
* ExFreePoolWithTag
* ExInitializeResourceLite
* ExAcquireResourceSharedLite
* ExAcquireResourceExclusiveLite
* ExReleaseResourceLite
* ExDeleteResourceLite
* MmProbeAndLockPages
* MmMapLockedPagesSpecifyCache
* MmUnmapLockedPages
* IoAllocateMdl
* IoFreeMdl
* ObReferenceObjectByHandle
* ObfDereferenceObject
* ObRegisterCallbacks
* ObUnRegisterCallbacks
* ZwClose
* PsSetCreateProcessNotifyRoutine
* ZwOpenProcess
* ZwQuerySystemInformation
* ZwQueryInformationProcess
* ZwAllocateVirtualMemory
* ZwFreeVirtualMemory
* KeInitializeApc
* ZwOpenThread
* IofCompleteRequest
* PsGetProcessPeb
* RtlImageDirectoryEntryToData
* KeStackAttachProcess
* KeUnstackDetachProcess
* __C_specific_handler
* PsProcessType
* PsThreadType
* KeLowerIrql
* KfRaiseIrql
* MmBuildMdlForNonPagedPool
* MmMapIoSpace
* MmUnmapIoSpace
* MmMapIoSpaceEx
* MmAllocateContiguousMemory
* MmFreeContiguousMemory
* MmGetPhysicalAddress
* PsGetThreadId
* PsGetThreadProcessId
* MmGetSystemRoutineAddress
* RtlGetVersion
* ZwTerminateProcess
* KeInitializeEvent
* ExAcquireFastMutex
* ExReleaseFastMutex
* KeSetEvent
* KeWaitForMultipleObjects
* KeWaitForSingleObject
* PsCreateSystemThread
* PsTerminateSystemThread
* RtlCompareUnicodeStrings
* wcscpy_s
* RtlCompareUnicodeString
* RtlAppendUnicodeStringToString
* ZwCreateFile
* ZwOpenKey
* ZwQueryValueKey
* ObOpenObjectByPointer
* ObQueryNameString
* IoFileObjectType
* KeInsertQueueApc
* DbgPrint
* HalGetBusDataByOffset

{{< /details >}}
#### ExportedFunctions
{{< details "Expand" >}}

{{< /details >}}
-----



[*source*](https://github.com/magicsword-io/LOLDrivers/tree/main/yaml/hwos2ec10x64.yaml)

*last_updated:* 2023-05-06








{{< /column >}}
{{< /block >}}
