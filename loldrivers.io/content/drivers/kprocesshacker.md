+++

description = ""
title = "kprocesshacker.sys"
weight = 10

+++


{{< block "grid-1" >}}
{{< column "mt-2 pt-1">}}


# kprocesshacker.sys ![:inline](/images/twitter_verified.png) 


### Description

kprocesshacker.sys is a vulnerable driver and more information will be added as found.

- **Created**: 2023-01-09
- **Author**: Michael Haag
- **Acknowledgement**:  | [](https://twitter.com/)

{{< button "https://github.com/magicsword-io/LOLDrivers/raw/main/drivers/1b5c3c458e31bede55145d0644e88d75.bin" "Download" >}}
{{< tip "warning" >}}
This download link contains the vulnerable driver!

{{< /tip >}}

### Commands

```
sc.exe create kprocesshacker.sys binPath=C:\windows\temp\kprocesshacker.sys     type=kernel &amp;&amp; sc.exe start kprocesshacker.sys
```

| Use Case | Privileges | Operating System | 
|:---- | ---- | ---- |
| Elevate privileges | kernel | Windows 10 |

### Resources
<br>
<li><a href=" https://github.com/jbaines-r7/dellicious"> https://github.com/jbaines-r7/dellicious</a></li>
<li><a href=" https://www.rapid7.com/blog/post/2021/12/13/driver-based-attacks-past-and-present/"> https://www.rapid7.com/blog/post/2021/12/13/driver-based-attacks-past-and-present/</a></li>
<li><a href="https://github.com/jbaines-r7/dellicious and https://www.rapid7.com/blog/post/2021/12/13/driver-based-attacks-past-and-present/">https://github.com/jbaines-r7/dellicious and https://www.rapid7.com/blog/post/2021/12/13/driver-based-attacks-past-and-present/</a></li>
<br>

### Known Vulnerable Samples

| Property           | Value |
|:-------------------|:------|
| Filename           | kprocesshacker.sys |
| MD5                | [1b5c3c458e31bede55145d0644e88d75](https://www.virustotal.com/gui/file/1b5c3c458e31bede55145d0644e88d75) |
| SHA1               | [a21c84c6bf2e21d69fa06daaf19b4cc34b589347](https://www.virustotal.com/gui/file/a21c84c6bf2e21d69fa06daaf19b4cc34b589347) |
| SHA256             | [70211a3f90376bbc61f49c22a63075d1d4ddd53f0aefa976216c46e6ba39a9f4](https://www.virustotal.com/gui/file/70211a3f90376bbc61f49c22a63075d1d4ddd53f0aefa976216c46e6ba39a9f4) |
| Authentihash MD5   | [dd81d5b2343e1976d1708e7eb0649f8f](https://www.virustotal.com/gui/search/authentihash%253Add81d5b2343e1976d1708e7eb0649f8f) |
| Authentihash SHA1  | [c2b8c1b34f09a91efe196f646ef7f9a11190fb8e](https://www.virustotal.com/gui/search/authentihash%253Ac2b8c1b34f09a91efe196f646ef7f9a11190fb8e) |
| Authentihash SHA256| [4ee2a56c1592ff0e951b452c0de064eba05b7c98e3add04c8aa3b4a84eb797a5](https://www.virustotal.com/gui/search/authentihash%253A4ee2a56c1592ff0e951b452c0de064eba05b7c98e3add04c8aa3b4a84eb797a5) |
| Signature         | Wen Jia Liu, DigiCert High Assurance Code Signing CA-1, DigiCert   |
| Company           | wj32 |
| Description       | KProcessHacker |
| Product           | KProcessHacker |
| OriginalFilename  | kprocesshacker.sys |


#### Imports
{{< details "Expand" >}}
* ntoskrnl.exe
* ksecdd.sys

{{< /details >}}
#### ImportedFunctions
{{< details "Expand" >}}
* SePrivilegeCheck
* ZwOpenKey
* ProbeForRead
* RtlGetVersion
* PsProcessType
* ObOpenObjectByName
* ObGetObjectType
* PsReleaseProcessExitSynchronization
* ZwQueryObject
* RtlEqualUnicodeString
* KeUnstackDetachProcess
* ExEnumHandleTable
* ObQueryNameString
* IoFileObjectType
* IoDriverObjectType
* ExfUnblockPushLock
* ObReferenceObjectByHandle
* PsAcquireProcessExitSynchronization
* PsInitialSystemProcess
* ObSetHandleAttributes
* ZwQueryInformationProcess
* ObfDereferenceObject
* ExAllocatePoolWithQuotaTag
* ZwQueryInformationThread
* ObOpenObjectByPointer
* KeStackAttachProcess
* PsLookupProcessByProcessId
* PsJobType
* PsReferencePrimaryToken
* SeTokenObjectType
* IoCreateDevice
* PsGetProcessJob
* PsLookupProcessThreadByCid
* ZwTerminateProcess
* PsDereferencePrimaryToken
* IoThreadToProcess
* RtlWalkFrameChain
* KeInitializeApc
* KeSetEvent
* KeInsertQueueApc
* KeWaitForSingleObject
* PsThreadType
* PsLookupThreadByThreadId
* ZwQuerySystemInformation
* ZwQueryVirtualMemory
* ExReleaseFastMutex
* ExAcquireFastMutex
* ZwReadFile
* MmHighestUserAddress
* SeLocateProcessImageName
* KeDelayExecutionThread
* ZwCreateFile
* RtlRandomEx
* ZwQueryInformationFile
* MmUnmapLockedPages
* ExRaiseStatus
* MmMapLockedPagesSpecifyCache
* MmProbeAndLockPages
* MmUnlockPages
* MmIsAddressValid
* KeBugCheckEx
* PsGetCurrentProcessId
* IofCompleteRequest
* ZwClose
* ZwQueryValueKey
* KeInitializeEvent
* ProbeForWrite
* IoDeleteDevice
* RtlInitUnicodeString
* ExFreePoolWithTag
* IoGetCurrentProcess
* ExAllocatePoolWithTag
* __C_specific_handler
* BCryptCreateHash
* BCryptDestroyKey
* BCryptImportKeyPair
* BCryptCloseAlgorithmProvider
* BCryptVerifySignature
* BCryptFinishHash
* BCryptHashData
* BCryptDestroyHash
* BCryptOpenAlgorithmProvider
* BCryptGetProperty

{{< /details >}}
#### ExportedFunctions
{{< details "Expand" >}}

{{< /details >}}
-----



[*source*](https://github.com/magicsword-io/LOLDrivers/tree/main/yaml/kprocesshacker.yaml)

*last_updated:* 2023-04-26








{{< /column >}}
{{< /block >}}
