+++

description = ""
title = "aswArPot.sys"
weight = 10

+++


{{< block "grid-1" >}}
{{< column "mt-2 pt-1">}}


# aswArPot.sys ![:inline](/images/twitter_verified.png) 


### Description

Avast’s “Anti Rootkit” driver (also used by AVG) has been found to be vulnerable to two high severity attacks that could potentially lead to privilege escalation by running code in the kernel from a non-administrator user.

- **Created**: 2023-01-09
- **Author**: Michael Haag
- **Acknowledgement**:  | [@mattnotmax](https://twitter.com/@mattnotmax)

{{< button "https://github.com/magicsword-io/LOLDrivers/raw/main/drivers/a179c4093d05a3e1ee73f6ff07f994aa.bin" "Download" >}}
{{< tip "warning" >}}
This download link contains the vulnerable driver!

{{< /tip >}}

### Commands

```
sc.exe create aswArPot.sys binPath=C:\windows\temp\aswArPot.sys type=kernel &amp;&amp; sc.exe start aswArPot.sys
```

| Use Case | Privileges | Operating System | 
|:---- | ---- | ---- |
| Elevate privileges | kernel | Windows 10 |

### Resources
<br>
<li><a href=" https://learn.microsoft.com/en-us/windows/security/threat-protection/windows-defender-application-control/microsoft-recommended-driver-block-rules"> https://learn.microsoft.com/en-us/windows/security/threat-protection/windows-defender-application-control/microsoft-recommended-driver-block-rules</a></li>
<li><a href="CVE-2022-26522, CVE-2022-26523: Both of these vulnerabilities were fixed in version 22.1.">CVE-2022-26522, CVE-2022-26523: Both of these vulnerabilities were fixed in version 22.1.</a></li>
<br>

### Known Vulnerable Samples

| Property           | Value |
|:-------------------|:------|
| Filename           | aswArPot.sys |
| MD5                | [a179c4093d05a3e1ee73f6ff07f994aa](https://www.virustotal.com/gui/file/a179c4093d05a3e1ee73f6ff07f994aa) |
| SHA1               | [5d6b9e80e12bfc595d4d26f6afb099b3cb471dd4](https://www.virustotal.com/gui/file/5d6b9e80e12bfc595d4d26f6afb099b3cb471dd4) |
| SHA256             | [4b5229b3250c8c08b98cb710d6c056144271de099a57ae09f5d2097fc41bd4f1](https://www.virustotal.com/gui/file/4b5229b3250c8c08b98cb710d6c056144271de099a57ae09f5d2097fc41bd4f1) |
| Authentihash MD5   | [66d55dcf5fe5e1b60f32880d48207105](https://www.virustotal.com/gui/search/authentihash%253A66d55dcf5fe5e1b60f32880d48207105) |
| Authentihash SHA1  | [b8b5e5951f1c4148537e9850f2b577a453e4c045](https://www.virustotal.com/gui/search/authentihash%253Ab8b5e5951f1c4148537e9850f2b577a453e4c045) |
| Authentihash SHA256| [c0c131bc8d6c8b5a2be32474474b1221bce1289c174c87e743ed4a512f5571d4](https://www.virustotal.com/gui/search/authentihash%253Ac0c131bc8d6c8b5a2be32474474b1221bce1289c174c87e743ed4a512f5571d4) |
| Signature         | Avast Software s.r.o., DigiCert High Assurance Code Signing CA-1, DigiCert   |
| Date                | 2021-02-01 14:09:00 |
| Company           | AVAST Software |
| Description       | Avast Anti Rootkit |
| Product           | Avast Antivirus  |
| OriginalFilename  | aswArPot.sys |


#### Imports
{{< details "Expand" >}}
* ntoskrnl.exe

{{< /details >}}
#### ImportedFunctions
{{< details "Expand" >}}
* __C_specific_handler
* KeDelayExecutionThread
* IoAllocateWorkItem
* MmIsAddressValid
* MmUnlockPages
* ExAllocatePool
* RtlAnsiStringToUnicodeString
* KeAcquireSpinLockRaiseToDpc
* ZwQuerySystemInformation
* PsRemoveLoadImageNotifyRoutine
* ZwUnmapViewOfSection
* ZwQuerySymbolicLinkObject
* MmProbeAndLockPages
* RtlVolumeDeviceToDosName
* PsSetLoadImageNotifyRoutine
* IoGetRequestorProcessId
* ZwReadFile
* ObQueryNameString
* IoDetachDevice
* ZwOpenThreadTokenEx
* ZwOpenProcessTokenEx
* towlower
* NtBuildNumber
* ExReleaseFastMutex
* _wcsicmp
* _snwprintf
* RtlConvertSidToUnicodeString
* ObfDereferenceObject
* IoAllocateMdl
* ZwCreateSection
* ZwQueryInformationProcess
* IoAttachDeviceToDeviceStackSafe
* PsGetProcessId
* PsCreateSystemThread
* ZwQueryInformationThread
* RtlInitUnicodeString
* ZwOpenSymbolicLinkObject
* tolower
* PsRemoveCreateThreadNotifyRoutine
* IoDeleteDevice
* IoBuildDeviceIoControlRequest
* wcsncpy
* IoGetDeviceObjectPointer
* IoGetCurrentProcess
* ObOpenObjectByPointer
* strncpy
* KeReleaseSpinLock
* _strnicmp
* IoFileObjectType
* KeStackAttachProcess
* PsLookupProcessByProcessId
* PsGetCurrentProcessId
* KeSetEvent
* PsThreadType
* RtlUnicodeStringToAnsiString
* ZwQueryInformationToken
* ZwMapViewOfSection
* strncmp
* ObReferenceObjectByHandle
* RtlGetVersion
* PsGetThreadId
* PsGetVersion
* KeClearEvent
* IoGetBaseFileSystemDeviceObject
* wcschr
* ZwSetInformationFile
* ZwEnumerateKey
* IoFreeMdl
* wcsstr
* ExAcquireFastMutex
* MmGetSystemRoutineAddress
* IoFreeWorkItem
* _stricmp
* ExAllocatePoolWithTag
* RtlInitString
* IoCreateDevice
* IofCallDriver
* IoDeviceObjectType
* _snprintf
* ExFreePoolWithTag
* ZwOpenFile
* KeSetSystemAffinityThread
* strstr
* KeInitializeEvent
* ObReferenceObjectByName
* strchr
* _wcsnicmp
* KeQueryActiveProcessors
* RtlEqualSid
* IoQueueWorkItem
* MmUnmapLockedPages
* MmMapLockedPagesSpecifyCache
* PsSetCreateThreadNotifyRoutine
* PsGetCurrentThreadId
* IofCompleteRequest
* PsGetProcessWin32Process
* ExEventObjectType
* ZwQueryInformationFile
* KeWaitForSingleObject
* IoCreateSymbolicLink
* PsSetCreateProcessNotifyRoutine
* IoDriverObjectType
* PsLookupThreadByThreadId
* IoGetDeviceInterfaces
* ZwClose
* PsTerminateSystemThread
* wcsrchr
* strrchr
* SeExports
* KeUnstackDetachProcess
* KeResetEvent
* KeRevertToUserAffinityThread
* ZwOpenProcess
* wcsncmp
* ZwOpenKey
* PsGetThreadProcess
* IoThreadToProcess
* PsInitialSystemProcess
* KeInsertQueueDpc
* KeNumberProcessors
* KeInitializeDpc
* KeSetTargetProcessorDpc
* PsProcessType
* MmMapIoSpace
* MmUnmapIoSpace
* ZwDeleteFile
* KeAttachProcess
* KeDetachProcess
* RtlCompareUnicodeString
* ZwWriteFile
* NtClose
* ObfReferenceObject
* IoBuildSynchronousFsdRequest
* ZwOpenThread
* ZwTerminateProcess
* RtlEqualUnicodeString
* IoFreeIrp
* ZwQueryDirectoryObject
* KeBugCheck
* ZwOpenDirectoryObject
* IoAllocateIrp
* KdDebuggerNotPresent
* ZwSetSecurityObject
* RtlGetDaclSecurityDescriptor
* RtlGetGroupSecurityDescriptor
* RtlGetOwnerSecurityDescriptor
* RtlGetSaclSecurityDescriptor
* SeCaptureSecurityDescriptor
* RtlLengthSecurityDescriptor
* RtlCreateSecurityDescriptor
* RtlAbsoluteToSelfRelativeSD
* RtlAddAccessAllowedAce
* RtlLengthSid
* IoIsWdmVersionAvailable
* RtlSetDaclSecurityDescriptor
* ZwSetValueKey
* ZwQueryValueKey
* ZwCreateKey
* RtlFreeUnicodeString
* KeBugCheckEx
* RtlQueryRegistryValues
* RtlPrefixUnicodeString
* ExRegisterCallback
* ExCreateCallback
* ExUnregisterCallback
* strcmp

{{< /details >}}
#### ExportedFunctions
{{< details "Expand" >}}

{{< /details >}}
-----



[*source*](https://github.com/magicsword-io/LOLDrivers/tree/main/yaml/aswarpot.yaml)

*last_updated:* 2023-04-20








{{< /column >}}
{{< /block >}}
