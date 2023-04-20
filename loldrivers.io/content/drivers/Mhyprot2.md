+++

description = ""
title = "Mhyprot2.sys"
weight = 10

+++


{{< block "grid-1" >}}
{{< column "mt-2 pt-1">}}


# Mhyprot2.sys ![:inline](/images/twitter_verified.png) 


### Description

Mhyprot2.sys is a vulnerable driver and more information will be added as found.

- **Created**: 2023-01-09
- **Author**: Michael Haag
- **Acknowledgement**:  | [](https://twitter.com/)

{{< button "https://github.com/magicsword-io/LOLDrivers/raw/main/drivers/4b817d0e7714b9d43db43ae4a22a161e.bin" "Download" >}}
{{< tip "warning" >}}
This download link contains the vulnerable driver!

{{< /tip >}}

### Commands

```
sc.exe create Mhyprot2.sys binPath=C:\windows\temp\Mhyprot2.sys type=kernel &amp;&amp; sc.exe start Mhyprot2.sys
```

| Use Case | Privileges | Operating System | 
|:---- | ---- | ---- |
| Elevate privileges | kernel | Windows 10 |

### Resources
<br>
<li><a href=" https://github.com/namazso/physmem_drivers"> https://github.com/namazso/physmem_drivers</a></li>
<li><a href="https://github.com/namazso/physmem_drivers">https://github.com/namazso/physmem_drivers</a></li>
<br>

### Known Vulnerable Samples

| Property           | Value |
|:-------------------|:------|
| Filename           | Mhyprot2.sys |
| MD5                | [4b817d0e7714b9d43db43ae4a22a161e](https://www.virustotal.com/gui/file/4b817d0e7714b9d43db43ae4a22a161e) |
| SHA1               | [0466e90bf0e83b776ca8716e01d35a8a2e5f96d3](https://www.virustotal.com/gui/file/0466e90bf0e83b776ca8716e01d35a8a2e5f96d3) |
| SHA256             | [509628b6d16d2428031311d7bd2add8d5f5160e9ecc0cd909f1e82bbbb3234d6](https://www.virustotal.com/gui/file/509628b6d16d2428031311d7bd2add8d5f5160e9ecc0cd909f1e82bbbb3234d6) |
| Authentihash MD5   | [ff295de93e6b6dcc3938d50901a7240d](https://www.virustotal.com/gui/search/authentihash%253Aff295de93e6b6dcc3938d50901a7240d) |
| Authentihash SHA1  | [484c72dd4fd91083b249f3ccc733a3c8335e583f](https://www.virustotal.com/gui/search/authentihash%253A484c72dd4fd91083b249f3ccc733a3c8335e583f) |
| Authentihash SHA256| [0c7809ac1fa074408518ddc0ac118912c9cd43ed9c89213bc4d59043016b040c](https://www.virustotal.com/gui/search/authentihash%253A0c7809ac1fa074408518ddc0ac118912c9cd43ed9c89213bc4d59043016b040c) |
| Signature         | miHoYo Co.,Ltd., DigiCert Assured ID Code Signing CA-1, DigiCert   |


#### Imports
{{< details "Expand" >}}
* ntoskrnl.exe
* WDFLDR.SYS

{{< /details >}}
#### ImportedFunctions
{{< details "Expand" >}}
* NtQuerySystemInformation
* RtlInitUnicodeString
* ExAllocatePool
* ExAllocatePoolWithTag
* ExFreePoolWithTag
* IofCompleteRequest
* IoCreateDevice
* IoCreateSymbolicLink
* IoDeleteDevice
* IoDeleteSymbolicLink
* _wcsicmp
* RtlInitString
* RtlAnsiStringToUnicodeString
* RtlFreeUnicodeString
* IoGetDeviceObjectPointer
* ZwClose
* MmIsAddressValid
* ZwOpenDirectoryObject
* ZwQueryDirectoryObject
* ObReferenceObjectByName
* ZwQuerySystemInformation
* __C_specific_handler
* MmHighestUserAddress
* IoDriverObjectType
* KeQueryTimeIncrement
* KeStackAttachProcess
* KeUnstackDetachProcess
* PsGetProcessWow64Process
* PsGetProcessPeb
* MmUnlockPages
* MmGetSystemRoutineAddress
* MmUnmapLockedPages
* IoFreeMdl
* ZwTerminateProcess
* PsGetProcessImageFileName
* ObOpenObjectByPointer
* PsReferenceProcessFilePointer
* IoQueryFileDosDeviceName
* ZwQueryVirtualMemory
* MmProbeAndLockPages
* PsLookupProcessByProcessId
* MmMapLockedPagesSpecifyCache
* IoAllocateMdl
* IoGetCurrentProcess
* MmCopyVirtualMemory
* KeClearEvent
* KeSetEvent
* KeWaitForSingleObject
* MmMapLockedPages
* ObReferenceObjectByHandle
* PsSetCreateProcessNotifyRoutineEx
* PsSetCreateThreadNotifyRoutine
* PsRemoveCreateThreadNotifyRoutine
* PsSetLoadImageNotifyRoutine
* PsRemoveLoadImageNotifyRoutine
* ExEventObjectType
* ObRegisterCallbacks
* ObUnRegisterCallbacks
* ObGetFilterVersion
* IoThreadToProcess
* strcmp
* PsProcessType
* PsThreadType
* RtlGetVersion
* ObfReferenceObject
* ObGetObjectType
* ExEnumHandleTable
* ExfUnblockPushLock
* _snprintf
* vsprintf_s
* ZwCreateFile
* ZwWriteFile
* PsLookupThreadByThreadId
* NtQueryInformationThread
* PsGetThreadProcess
* DbgPrint
* KeDelayExecutionThread
* KdDisableDebugger
* KdChangeOption
* PsCreateSystemThread
* PsTerminateSystemThread
* KdDebuggerEnabled
* PsGetVersion
* KeInitializeEvent
* RtlCopyUnicodeString
* ObfDereferenceObject
* ExReleaseFastMutex
* ExAcquireFastMutex
* MmBuildMdlForNonPagedPool
* WdfVersionBindClass
* WdfVersionBind
* WdfVersionUnbind
* WdfVersionUnbindClass

{{< /details >}}
#### ExportedFunctions
{{< details "Expand" >}}

{{< /details >}}
-----



[*source*](https://github.com/magicsword-io/LOLDrivers/tree/main/yaml/mhyprot2.yaml)

*last_updated:* 2023-04-20








{{< /column >}}
{{< /block >}}
