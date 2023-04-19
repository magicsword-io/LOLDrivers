+++

description = ""
title = "mhyprot3.sys"
weight = 10

+++


{{< block "grid-1" >}}
{{< column "mt-2 pt-1">}}


# mhyprot3.sys 


{{< tip "warning" >}}
We were not able to verify the hash of this driver successfully, it has not been confirmed.
{{< /tip >}}


### Description

mhyprot3.sys is a vulnerable driver and more information will be added as found.

- **Created**: 2023-01-09
- **Author**: Michael Haag
- **Acknowledgement**:  | [](https://twitter.com/)

{{< button "https://github.com/magicsword-io/LOLDrivers/raw/main/drivers/5cc5c26fc99175997d84fe95c61ab2c2.bin" "Download" >}}
{{< tip "warning" >}}
{% if driver.Category == "vulnerable driver" %}
This download link contains the vulnerable driver!
{% elif driver.Category == "malicious" %}
This download link contains the malicious driver!
{% endif %}
{{< /tip >}}

### Commands

```
sc.exe create mhyprot3.sys binPath=C:\windows\temp\mhyprot3.sys type=kernel &amp;&amp; sc.exe start mhyprot3.sys
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

| Filename | mhyprot3.sys |
|:---- | ---- | 
| MD5 | <a href="https://www.virustotal.com/gui/file/5cc5c26fc99175997d84fe95c61ab2c2">5cc5c26fc99175997d84fe95c61ab2c2</a> |
| SHA1 | <a href="https://www.virustotal.com/gui/file/a197a02025946aca96d6e74746f84774df31249e">a197a02025946aca96d6e74746f84774df31249e</a> |
| SHA256 | <a href="https://www.virustotal.com/gui/file/475e5016c9c0f5a127896f9179a1b1577a67b357f399ab5a1e68aab07134729a">475e5016c9c0f5a127896f9179a1b1577a67b357f399ab5a1e68aab07134729a</a> |
| Authentihash MD5 | <a href="https://www.virustotal.com/gui/search/authentihash%253A7ce959fb5b40f1ba40bcac22c8d95c75">7ce959fb5b40f1ba40bcac22c8d95c75</a> || Authentihash SHA1 | <a href="https://www.virustotal.com/gui/search/authentihash%253A82fe9b69f358ef5851eeaa26a9a03f2e1b231358">82fe9b69f358ef5851eeaa26a9a03f2e1b231358</a> || Authentihash SHA256 | <a href="https://www.virustotal.com/gui/search/authentihash%253Aaac86a3143de3e18dea6eab813b285da0718e9fb6bc0bbb46c6e7638476061d8">aac86a3143de3e18dea6eab813b285da0718e9fb6bc0bbb46c6e7638476061d8</a> || Signature | miHoYo Co.,Ltd., DigiCert SHA2 Assured ID Code Signing CA, DigiCert   |
#### Imports
{{< details "Expand" >}}* ntoskrnl.exe
* WDFLDR.SYS
{{< /details >}}
#### ImportedFunctions
{{< details "Expand" >}}* ExReleaseFastMutex
* ObfDereferenceObject
* PsLookupProcessByProcessId
* NtQuerySystemInformation
* RtlInitUnicodeString
* KeSetEvent
* KeEnterCriticalRegion
* KeLeaveCriticalRegion
* KeWaitForSingleObject
* ExAllocatePoolWithTag
* ExInitializeResourceLite
* ExAcquireResourceExclusiveLite
* ExReleaseResourceLite
* IofCompleteRequest
* IoCreateDevice
* IoCreateSymbolicLink
* IoDeleteDevice
* IoDeleteSymbolicLink
* IoGetCurrentProcess
* ObReferenceObjectByHandle
* ZwClose
* ZwOpenSection
* ZwMapViewOfSection
* MmIsAddressValid
* PsGetCurrentProcessId
* MmCopyVirtualMemory
* vsprintf_s
* swprintf_s
* ExEventObjectType
* _wcsicmp
* RtlInitString
* RtlAnsiStringToUnicodeString
* RtlFreeUnicodeString
* IoGetDeviceObjectPointer
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
* ExAcquireFastMutex
* MmUnmapLockedPages
* IoFreeMdl
* ZwTerminateProcess
* PsGetProcessImageFileName
* ZwQueryObject
* ObOpenObjectByPointer
* PsReferenceProcessFilePointer
* IoQueryFileDosDeviceName
* MmProbeAndLockPages
* MmBuildMdlForNonPagedPool
* MmMapLockedPagesSpecifyCache
* IoAllocateMdl
* KeClearEvent
* MmMapLockedPages
* PsSetCreateProcessNotifyRoutineEx
* PsSetCreateThreadNotifyRoutine
* PsRemoveCreateThreadNotifyRoutine
* PsSetLoadImageNotifyRoutine
* PsRemoveLoadImageNotifyRoutine
* RtlUpcaseUnicodeChar
* DbgPrint
* ObRegisterCallbacks
* ObUnRegisterCallbacks
* ObGetFilterVersion
* PsGetProcessId
* IoThreadToProcess
* strcmp
* PsProcessType
* PsThreadType
* RtlEqualUnicodeString
* RtlGetVersion
* ObfReferenceObject
* ObGetObjectType
* ExEnumHandleTable
* ExfUnblockPushLock
* PsAcquireProcessExitSynchronization
* PsReleaseProcessExitSynchronization
* _snprintf
* ZwCreateFile
* ZwWriteFile
* PsLookupThreadByThreadId
* NtQueryInformationThread
* PsGetThreadProcess
* KeDelayExecutionThread
* KdDisableDebugger
* KdChangeOption
* PsCreateSystemThread
* PsTerminateSystemThread
* KdDebuggerEnabled
* PsGetVersion
* RtlCopyUnicodeString
* ExFreePoolWithTag
* ExAllocatePool
* KeInitializeEvent
* MmGetSystemRoutineAddress
* WdfVersionBindClass
* WdfVersionBind
* WdfVersionUnbind
* WdfVersionUnbindClass
{{< /details >}}
#### ExportedFunctions
{{< details "Expand" >}}{{< /details >}}



[*source*](https://github.com/magicsword-io/LOLDrivers/tree/main/yaml/mhyprot3.yaml)

*last_updated:* 2023-04-19








{{< /column >}}
{{< /block >}}
