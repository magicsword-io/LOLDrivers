+++

description = ""
title = "wantd_2.sys"
weight = 10

+++


{{< block "grid-1" >}}
{{< column "mt-2 pt-1">}}


# wantd_2.sys ![:inline](/images/twitter_verified.png) 


### Description

Driver used in the Daxin malware campaign.

- **Created**: 2023-02-28
- **Author**: Michael Haag
- **Acknowledgement**:  | [](https://twitter.com/)

{{< button "https://github.com/magicsword-io/LOLDrivers/raw/main/drivers/8636fe3724f2bcba9399daffd6ef3c7e.bin" "Download" >}}
{{< tip "warning" >}}
This download link contains the malicious driver!

{{< /tip >}}

### Commands

```
sc.exe create wantd_2.sys binPath=C:\windows\temp\wantd_2.sys type=kernel &amp;&amp; sc.exe start wantd_2.sys
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

| Filename | wantd_2.sys |
|:---- | ---- | 
| MD5 | <a href="https://www.virustotal.com/gui/file/8636fe3724f2bcba9399daffd6ef3c7e">8636fe3724f2bcba9399daffd6ef3c7e</a> |
| SHA1 | <a href="https://www.virustotal.com/gui/file/3b6b35bca1b05fafbfc883a844df6d52af44ccdc">3b6b35bca1b05fafbfc883a844df6d52af44ccdc</a> |
| SHA256 | <a href="https://www.virustotal.com/gui/file/6908ebf52eb19c6719a0b508d1e2128f198d10441551cbfb9f4031d382f5229f">6908ebf52eb19c6719a0b508d1e2128f198d10441551cbfb9f4031d382f5229f</a> |
| Authentihash MD5 | <a href="https://www.virustotal.com/gui/search/authentihash%253A4b7d15fe072cc44bb427206b295f861d">4b7d15fe072cc44bb427206b295f861d</a> || Authentihash SHA1 | <a href="https://www.virustotal.com/gui/search/authentihash%253A2edc9b891f72f204bee80618058f921a3f6fb5a1">2edc9b891f72f204bee80618058f921a3f6fb5a1</a> || Authentihash SHA256 | <a href="https://www.virustotal.com/gui/search/authentihash%253A25d16b2b53fc7b52a65616ab7fc04a503946c20fe96556681bfaddd589401f4a">25d16b2b53fc7b52a65616ab7fc04a503946c20fe96556681bfaddd589401f4a</a> || Publisher | Anhua Xinda (Beijing) Technology Co., Ltd. || Signature | S, i, g, n, e, d   || Date | 7:52 AM 4/30/2014 || Company | Microsoft Corporation || Description | WAN Transport Driver || Product | Microsoft Windows Operating System || OriginalFilename | wantd.sys |
#### Imports
{{< details "Expand" >}}* ntoskrnl.exe
* NDIS.SYS
{{< /details >}}
#### ImportedFunctions
{{< details "Expand" >}}* IoAllocateMdl
* _stricmp
* sprintf
* RtlLengthRequiredSid
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
* ZwQuerySystemInformation
* KeReleaseSpinLock
* RtlAddAccessAllowedAce
* RtlImageDirectoryEntryToData
* KeDetachProcess
* KeDelayExecutionThread
* wcsncmp
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
* DbgPrint
* PsLookupThreadByThreadId
* RtlLengthSid
* RtlCreateSecurityDescriptor
* ZwAllocateVirtualMemory
* ZwOpenKey
* KeAcquireSpinLockRaiseToDpc
* ZwOpenFile
* RtlUnicodeStringToInteger
* MmIsAddressValid
* ZwDeviceIoControlFile
* IofCompleteRequest
* ZwClose
* MmMapLockedPagesSpecifyCache
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
* NdisCopyFromNetBufferToNetBuffer
* NdisFreeMdl
* NdisFreeNetBufferListPool
* NdisFreeNetBufferList
* NdisSendNetBufferLists
{{< /details >}}
#### ExportedFunctions
{{< details "Expand" >}}{{< /details >}}



[*source*](https://github.com/magicsword-io/LOLDrivers/tree/main/yaml/wantd_2.yaml)

*last_updated:* 2023-04-19








{{< /column >}}
{{< /block >}}
