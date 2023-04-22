+++

description = ""
title = "wantd_6.sys"
weight = 10

+++


{{< block "grid-1" >}}
{{< column "mt-2 pt-1">}}


# wantd_6.sys ![:inline](/images/twitter_verified.png) 


### Description

Driver used in the Daxin malware campaign.

- **Created**: 2023-02-28
- **Author**: Michael Haag
- **Acknowledgement**:  | [](https://twitter.com/)

{{< button "https://github.com/magicsword-io/LOLDrivers/raw/main/drivers/4b058945c9f2b8d8ebc485add1101ba5.bin" "Download" >}}
{{< tip "warning" >}}
This download link contains the malicious driver!

{{< /tip >}}

### Commands

```
sc.exe create wantd_6.sys binPath=C:\windows\temp\wantd_6.sys type=kernel &amp;&amp; sc.exe start wantd_6.sys
```

| Use Case | Privileges | Operating System | 
|:---- | ---- | ---- |
| Elevate privileges | kernel | Windows 10 |

### Resources
<br>
<li><a href="https://gist.github.com/MHaggis/9ab3bb795a6018d70fb11fa7c31f8f48">https://gist.github.com/MHaggis/9ab3bb795a6018d70fb11fa7c31f8f48</a></li>
<li><a href="https://symantec-enterprise-blogs.security.com/blogs/threat-intelligence/daxin-backdoor-espionage">https://symantec-enterprise-blogs.security.com/blogs/threat-intelligence/daxin-backdoor-espionage</a></li>
<li><a href=""></a></li>
<br>

### Known Vulnerable Samples

| Property           | Value |
|:-------------------|:------|
| Filename           | wantd_6.sys |
| MD5                | [4b058945c9f2b8d8ebc485add1101ba5](https://www.virustotal.com/gui/file/4b058945c9f2b8d8ebc485add1101ba5) |
| SHA1               | [37e6450c7cd6999d080da94b867ba23faa8c32fe](https://www.virustotal.com/gui/file/37e6450c7cd6999d080da94b867ba23faa8c32fe) |
| SHA256             | [e7af7bcb86bd6bab1835f610671c3921441965a839673ac34444cf0ce7b2164e](https://www.virustotal.com/gui/file/e7af7bcb86bd6bab1835f610671c3921441965a839673ac34444cf0ce7b2164e) |
| Authentihash MD5   | [3bfdb46b5ad5fa267b992a2350a6518a](https://www.virustotal.com/gui/search/authentihash%253A3bfdb46b5ad5fa267b992a2350a6518a) |
| Authentihash SHA1  | [cb65c6f9f411892d13ffe8ba1cb5e9c4be2c0a25](https://www.virustotal.com/gui/search/authentihash%253Acb65c6f9f411892d13ffe8ba1cb5e9c4be2c0a25) |
| Authentihash SHA256| [bd243e33fa80f4bd6010c23ecdf94b6008fee30df248255dcfe014c91f2ce2af](https://www.virustotal.com/gui/search/authentihash%253Abd243e33fa80f4bd6010c23ecdf94b6008fee30df248255dcfe014c91f2ce2af) |
| Publisher         | Anhua Xinda (Beijing) Technology Co., Ltd. |
| Signature         | T, h, e,  , d, i, g, i, t, a, l,  , s, i, g, n, a, t, u, r, e,  , o, f,  , t, h, e,  , o, b, j, e, c, t,  , d, i, d,  , n, o, t,  , v, e, r, i, f, y, .   |
| Date                | 8:23 PM 2/28/2022 |
| Company           | Microsoft Corporation |
| Description       | WAN Transport Driver |
| Product           | Microsoft Windows Operating System |
| OriginalFilename  | wantd.sys |


#### Imports
{{< details "Expand" >}}
* ntoskrnl.exe
* NDIS.SYS

{{< /details >}}
#### ImportedFunctions
{{< details "Expand" >}}
* wcsncmp
* IoAllocateMdl
* _stricmp
* sprintf
* RtlLengthRequiredSid
* _strnicmp
* ExAllocatePoolWithTag
* vsprintf
* IoDeleteSymbolicLink
* ExFreePoolWithTag
* RtlAnsiStringToUnicodeString
* NtWriteFile
* RtlCreateAcl
* PsLookupProcessByProcessId
* NtQuerySystemInformation
* _wcsnicmp
* ZwReadFile
* RtlSetDaclSecurityDescriptor
* KeInitializeApc
* IoDeleteDevice
* NtFsControlFile
* KeInsertQueueApc
* MmGetSystemRoutineAddress
* IoCreateFile
* atoi
* _snprintf
* ZwQuerySystemInformation
* KeReleaseSpinLock
* RtlAddAccessAllowedAce
* RtlImageDirectoryEntryToData
* KeDetachProcess
* ZwOpenFile
* ZwCreateFile
* PsCreateSystemThread
* ZwQueryValueKey
* PsTerminateSystemThread
* ZwFreeVirtualMemory
* KeQueryTimeIncrement
* ObReferenceObjectByHandle
* KeWaitForSingleObject
* KeAttachProcess
* PsGetVersion
* PsThreadType
* RtlCompareUnicodeString
* ZwOpenProcess
* ZwQueryInformationProcess
* IoCreateSymbolicLink
* ObfDereferenceObject
* IoCreateDevice
* ZwTerminateProcess
* ZwQueryInformationFile
* KeWaitForMultipleObjects
* ZwWriteFile
* NtReadFile
* PsLookupThreadByThreadId
* RtlLengthSid
* RtlCreateSecurityDescriptor
* ZwAllocateVirtualMemory
* ZwOpenKey
* KeAcquireSpinLockRaiseToDpc
* RtlUnicodeStringToInteger
* MmIsAddressValid
* ZwDeviceIoControlFile
* IofCompleteRequest
* ZwClose
* MmMapLockedPagesSpecifyCache
* KeDelayExecutionThread
* MmUserProbeAddress
* MmBuildMdlForNonPagedPool
* memchr
* ZwWaitForSingleObject
* RtlInitUnicodeString
* NdisAllocateMemoryWithTag
* NdisAllocateNetBufferAndNetBufferList
* NdisMSendNetBufferListsComplete
* NdisReturnNetBufferLists
* NdisAllocateNetBufferListPool
* NdisFreeMemory
* NdisMIndicateStatus
* NdisFreeMdl
* NdisFreeNetBufferListPool
* NdisFreeNetBufferList
* NdisSendNetBufferLists

{{< /details >}}
#### ExportedFunctions
{{< details "Expand" >}}

{{< /details >}}
-----



[*source*](https://github.com/magicsword-io/LOLDrivers/tree/main/yaml/wantd_6.yaml)

*last_updated:* 2023-04-22








{{< /column >}}
{{< /block >}}
