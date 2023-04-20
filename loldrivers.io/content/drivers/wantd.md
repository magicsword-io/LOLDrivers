+++

description = ""
title = "wantd.sys"
weight = 10

+++


{{< block "grid-1" >}}
{{< column "mt-2 pt-1">}}


# wantd.sys ![:inline](/images/twitter_verified.png) 


### Description

Driver used in the Daxin malware campaign.

- **Created**: 2023-02-28
- **Author**: Michael Haag
- **Acknowledgement**:  | [](https://twitter.com/)

{{< button "https://github.com/magicsword-io/LOLDrivers/raw/main/drivers/b0770094c3c64250167b55e4db850c04.bin" "Download" >}}
{{< tip "warning" >}}
This download link contains the malicious driver!

{{< /tip >}}

### Commands

```
sc.exe create wantd.sys binPath=C:\windows\temp\wantd.sys type=kernel &amp;&amp; sc.exe start wantd.sys
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
| Filename           | wantd.sys |
| MD5                | [b0770094c3c64250167b55e4db850c04](https://www.virustotal.com/gui/file/b0770094c3c64250167b55e4db850c04) |
| SHA1               | [6abbc3003c7aa69ce79cbbcd2e3210b07f21d202](https://www.virustotal.com/gui/file/6abbc3003c7aa69ce79cbbcd2e3210b07f21d202) |
| SHA256             | [06a0ec9a316eb89cb041b1907918e3ad3b03842ec65f004f6fa74d57955573a4](https://www.virustotal.com/gui/file/06a0ec9a316eb89cb041b1907918e3ad3b03842ec65f004f6fa74d57955573a4) |
| Authentihash MD5   | [1ed42c05e43c14ab16d16fbe8eaed870](https://www.virustotal.com/gui/search/authentihash%253A1ed42c05e43c14ab16d16fbe8eaed870) |
| Authentihash SHA1  | [68cb54489a0556594a28f5f1410cc64d74a1c182](https://www.virustotal.com/gui/search/authentihash%253A68cb54489a0556594a28f5f1410cc64d74a1c182) |
| Authentihash SHA256| [a47b9af109988e8e033886638edc84964968eecd0d24483eafaad6a6d68005ea](https://www.virustotal.com/gui/search/authentihash%253Aa47b9af109988e8e033886638edc84964968eecd0d24483eafaad6a6d68005ea) |
| Publisher         | Anhua Xinda (Beijing) Technology Co., Ltd. |
| Signature         | A,  , r, e, q, u, i, r, e, d,  , c, e, r, t, i, f, i, c, a, t, e,  , i, s,  , n, o, t,  , w, i, t, h, i, n,  , i, t, s,  , v, a, l, i, d, i, t, y,  , p, e, r, i, o, d,  , w, h, e, n,  , v, e, r, i, f, y, i, n, g,  , a, g, a, i, n, s, t,  , t, h, e,  , c, u, r, r, e, n, t,  , s, y, s, t, e, m,  , c, l, o, c, k,  , o, r,  , t, h, e,  , t, i, m, e, s, t, a, m, p,  , i, n,  , t, h, e,  , s, i, g, n, e, d,  , f, i, l, e, .   |
| Date                | 11:59 PM 11/27/2013 |
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



[*source*](https://github.com/magicsword-io/LOLDrivers/tree/main/yaml/wantd.yaml)

*last_updated:* 2023-04-20








{{< /column >}}
{{< /block >}}
