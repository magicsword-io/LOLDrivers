+++

description = ""
title = "zamguard64.sys"
weight = 10

+++


{{< block "grid-1" >}}
{{< column "mt-2 pt-1">}}


# zamguard64.sys ![:inline](/images/twitter_verified.png) 


### Description

zamguard64.sys is a vulnerable driver and more information will be added as found.

- **Created**: 2023-01-09
- **Author**: Michael Haag
- **Acknowledgement**:  | [](https://twitter.com/)

{{< button "https://github.com/magicsword-io/LOLDrivers/raw/main/drivers/21e13f2cb269defeae5e1d09887d47bb.bin" "Download" >}}
{{< tip "warning" >}}
This download link contains the vulnerable driver!

{{< /tip >}}

### Commands

```
sc.exe create zamguard64.sys binPath=C:\windows\temp\zamguard64.sys type=kernel &amp;&amp; sc.exe start zamguard64.sys
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
| Filename           | zamguard64.sys |
| MD5                | [21e13f2cb269defeae5e1d09887d47bb](https://www.virustotal.com/gui/file/21e13f2cb269defeae5e1d09887d47bb) |
| SHA1               | [16d7ecf09fc98798a6170e4cef2745e0bee3f5c7](https://www.virustotal.com/gui/file/16d7ecf09fc98798a6170e4cef2745e0bee3f5c7) |
| SHA256             | [543991ca8d1c65113dff039b85ae3f9a87f503daec30f46929fd454bc57e5a91](https://www.virustotal.com/gui/file/543991ca8d1c65113dff039b85ae3f9a87f503daec30f46929fd454bc57e5a91) |
| Authentihash MD5   | [3f2771b22553380efcee72a27dc4d96c](https://www.virustotal.com/gui/search/authentihash%253A3f2771b22553380efcee72a27dc4d96c) |
| Authentihash SHA1  | [0d15b7de0f1129b540f48d7a3cba2c6bf5d44112](https://www.virustotal.com/gui/search/authentihash%253A0d15b7de0f1129b540f48d7a3cba2c6bf5d44112) |
| Authentihash SHA256| [ceb1bf90d8652dac481fba362e5c3a6548a116897e729733f2be27f4edc5fc1f](https://www.virustotal.com/gui/search/authentihash%253Aceb1bf90d8652dac481fba362e5c3a6548a116897e729733f2be27f4edc5fc1f) |
| Signature         | Zemana Ltd., DigiCert High Assurance Code Signing CA-1, DigiCert   |
| Company           | Zemana Ltd. |
| Description       | ZAM |
| Product           | ZAM |


#### Imports
{{< details "Expand" >}}
* ntoskrnl.exe
* FLTMGR.SYS

{{< /details >}}
#### ImportedFunctions
{{< details "Expand" >}}
* FsRtlIsNameInExpression
* PsGetProcessImageFileName
* ZwQueryInformationProcess
* __C_specific_handler
* strchr
* RtlAppendUnicodeToString
* KeInitializeSemaphore
* KeReleaseSemaphore
* KeWaitForSingleObject
* KeAcquireSpinLockRaiseToDpc
* KeReleaseSpinLock
* PsCreateSystemThread
* PsTerminateSystemThread
* ZwQueryInformationFile
* ZwWriteFile
* PsGetCurrentThreadId
* ZwDeleteFile
* _vsnprintf
* PsThreadType
* PsSetCreateProcessNotifyRoutine
* PsGetProcessSessionId
* RtlAppendUnicodeStringToString
* ZwDeleteValueKey
* ZwSetValueKey
* towupper
* RtlIntegerToUnicodeString
* KeInitializeEvent
* KeSetEvent
* KeAcquireSpinLockAtDpcLevel
* KeReleaseSpinLockFromDpcLevel
* MmProbeAndLockPages
* IoAllocateIrp
* IoAllocateMdl
* IofCallDriver
* IoFreeIrp
* IoFreeMdl
* IoGetDeviceObjectPointer
* IoGetRelatedDeviceObject
* ObCloseHandle
* ObfReferenceObject
* ZwSetInformationFile
* ZwReadFile
* ZwOpenSymbolicLinkObject
* ZwQuerySymbolicLinkObject
* IoCreateFileSpecifyDeviceObjectHint
* IoGetDeviceAttachmentBaseRef
* FsRtlGetFileSize
* ObQueryNameString
* IoFileObjectType
* KeReadStateEvent
* ExQueueWorkItem
* ExGetPreviousMode
* MmGetSystemRoutineAddress
* NtOpenProcess
* ZwCreateEvent
* ZwWaitForSingleObject
* ZwSetEvent
* NtQuerySystemInformation
* ExEventObjectType
* NtBuildNumber
* ZwDeleteKey
* ObReferenceObjectByName
* IoDriverObjectType
* MmIsDriverVerifying
* IofCompleteRequest
* IoCreateDevice
* IoCreateSymbolicLink
* IoDeleteDevice
* IoDeleteSymbolicLink
* RtlSetDaclSecurityDescriptor
* MmMapLockedPagesSpecifyCache
* PsGetProcessId
* IoThreadToProcess
* PsGetCurrentProcessSessionId
* ZwTerminateProcess
* KeStackAttachProcess
* KeUnstackDetachProcess
* ZwOpenThread
* PsProcessType
* ExInterlockedInsertHeadList
* ExInterlockedRemoveHeadList
* CmRegisterCallback
* CmUnRegisterCallback
* RtlCreateRegistryKey
* ZwOpenKey
* ZwEnumerateKey
* ZwQueryKey
* ZwQueryValueKey
* RtlUnicodeStringToAnsiString
* RtlFreeAnsiString
* ProbeForWrite
* PsSetLoadImageNotifyRoutine
* PsRemoveLoadImageNotifyRoutine
* PsGetProcessSectionBaseAddress
* MmSystemRangeStart
* KeBugCheckEx
* PsLookupProcessByProcessId
* ZwOpenProcess
* PsGetCurrentProcessId
* RtlUpcaseUnicodeString
* RtlUpperString
* ZwClose
* ZwCreateFile
* ObfDereferenceObject
* ObReferenceObjectByHandle
* ProbeForRead
* ExFreePoolWithTag
* ExAllocatePoolWithTag
* KeDelayExecutionThread
* RtlGetVersion
* DbgPrint
* RtlCopyUnicodeString
* RtlInitUnicodeString
* wcsstr
* ZwQuerySystemInformation
* strstr
* FltSendMessage
* FltCloseCommunicationPort
* FltCreateCommunicationPort
* FltReleaseContext
* FltGetStreamHandleContext
* FltSetStreamHandleContext
* FltAllocateContext
* FltCancelFileOpen
* FltQueryInformationFile
* FltReadFile
* FltParseFileNameInformation
* FltReleaseFileNameInformation
* FltGetFileNameInformation
* FltFreePoolAlignedWithTag
* FltAllocatePoolAlignedWithTag
* FltStartFiltering
* FltUnregisterFilter
* FltRegisterFilter
* FltBuildDefaultSecurityDescriptor

{{< /details >}}
#### ExportedFunctions
{{< details "Expand" >}}

{{< /details >}}
-----



[*source*](https://github.com/magicsword-io/LOLDrivers/tree/main/yaml/zamguard64.yaml)

*last_updated:* 2023-04-22








{{< /column >}}
{{< /block >}}
