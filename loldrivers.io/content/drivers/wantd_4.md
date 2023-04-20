+++

description = ""
title = "wantd_4.sys"
weight = 10

+++


{{< block "grid-1" >}}
{{< column "mt-2 pt-1">}}


# wantd_4.sys ![:inline](/images/twitter_verified.png) 


### Description

Driver used in the Daxin malware campaign.

- **Created**: 2023-02-28
- **Author**: Michael Haag
- **Acknowledgement**:  | [](https://twitter.com/)

{{< button "https://github.com/magicsword-io/LOLDrivers/raw/main/drivers/79df0eabbf2895e4e2dae15a4772868c.bin" "Download" >}}
{{< tip "warning" >}}
This download link contains the malicious driver!

{{< /tip >}}

### Commands

```
sc.exe create wantd_4.sys binPath=C:\windows\temp\wantd_4.sys type=kernel &amp;&amp; sc.exe start wantd_4.sys
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
| Filename           | wantd_4.sys |
| MD5                | [79df0eabbf2895e4e2dae15a4772868c](https://www.virustotal.com/gui/file/79df0eabbf2895e4e2dae15a4772868c) |
| SHA1               | [d02403f85be6f243054395a873b41ef8a17ea279](https://www.virustotal.com/gui/file/d02403f85be6f243054395a873b41ef8a17ea279) |
| SHA256             | [8d9a2363b757d3f127b9c6ed8f7b8b018e652369bc070aa3500b3a978feaa6ce](https://www.virustotal.com/gui/file/8d9a2363b757d3f127b9c6ed8f7b8b018e652369bc070aa3500b3a978feaa6ce) |
| Authentihash MD5   | [00a677b8d21de4be1c7c16f2f105dbc6](https://www.virustotal.com/gui/search/authentihash%253A00a677b8d21de4be1c7c16f2f105dbc6) |
| Authentihash SHA1  | [a10f5c6c4d5ae78f0ca771328c74eb9fc51e593d](https://www.virustotal.com/gui/search/authentihash%253Aa10f5c6c4d5ae78f0ca771328c74eb9fc51e593d) |
| Authentihash SHA256| [3f55375fb70cb355fe7de7f59904b12ef996447cbc7113fefa379995e040d678](https://www.virustotal.com/gui/search/authentihash%253A3f55375fb70cb355fe7de7f59904b12ef996447cbc7113fefa379995e040d678) |
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


[*source*](https://github.com/magicsword-io/LOLDrivers/tree/main/yaml/wantd_4.yaml)

*last_updated:* 2023-04-20








{{< /column >}}
{{< /block >}}
