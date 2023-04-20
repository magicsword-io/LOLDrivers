+++

description = ""
title = "wantd_5.sys"
weight = 10

+++


{{< block "grid-1" >}}
{{< column "mt-2 pt-1">}}


# wantd_5.sys ![:inline](/images/twitter_verified.png) 


### Description

Driver used in the Daxin malware campaign.

- **Created**: 2023-02-28
- **Author**: Michael Haag
- **Acknowledgement**:  | [](https://twitter.com/)

{{< button "https://github.com/magicsword-io/LOLDrivers/raw/main/drivers/6d131a7462e568213b44ef69156f10a5.bin" "Download" >}}
{{< tip "warning" >}}
This download link contains the malicious driver!

{{< /tip >}}

### Commands

```
sc.exe create wantd_5.sys binPath=C:\windows\temp\wantd_5.sys type=kernel &amp;&amp; sc.exe start wantd_5.sys
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
| Filename           | wantd_5.sys |
| MD5                | [6d131a7462e568213b44ef69156f10a5](https://www.virustotal.com/gui/file/6d131a7462e568213b44ef69156f10a5) |
| SHA1               | [25bf4e30a94df9b8f8ab900d1a43fd056d285c9d](https://www.virustotal.com/gui/file/25bf4e30a94df9b8f8ab900d1a43fd056d285c9d) |
| SHA256             | [b9dad0131c51e2645e761b74a71ebad2bf175645fa9f42a4ab0e6921b83306e3](https://www.virustotal.com/gui/file/b9dad0131c51e2645e761b74a71ebad2bf175645fa9f42a4ab0e6921b83306e3) |
| Authentihash MD5   | [7c35b7a9bf59a63b84f252906732edde](https://www.virustotal.com/gui/search/authentihash%253A7c35b7a9bf59a63b84f252906732edde) |
| Authentihash SHA1  | [ea0d2851b890d39d85bfb0dd1404c87f73aed47f](https://www.virustotal.com/gui/search/authentihash%253Aea0d2851b890d39d85bfb0dd1404c87f73aed47f) |
| Authentihash SHA256| [448a507774886c1745beaa86cd0867d93f142f5d2b58d452c5a8250d93359779](https://www.virustotal.com/gui/search/authentihash%253A448a507774886c1745beaa86cd0867d93f142f5d2b58d452c5a8250d93359779) |
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


[*source*](https://github.com/magicsword-io/LOLDrivers/tree/main/yaml/wantd_5.yaml)

*last_updated:* 2023-04-20








{{< /column >}}
{{< /block >}}
