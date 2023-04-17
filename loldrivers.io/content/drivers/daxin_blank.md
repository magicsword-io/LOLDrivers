+++

description = ""
title = "daxin_blank.sys"
weight = 10

+++


{{< block "grid-1" >}}
{{< column "mt-2 pt-1">}}


# daxin_blank.sys ![:inline](/images/twitter_verified.png) 


### Description

Driver used in the Daxin malware campaign.

- **Created**: 2023-02-28
- **Author**: Michael Haag
- **Acknowledgement**:  | [](https://twitter.com/)

{{< button "https://github.com/magicsword-io/LOLDrivers/raw/main/drivers/62c18d61ed324088f963510bae43b831.bin" "Download" >}}
{{< tip "warning" >}}
This download link contains the malcious driver!
{{< /tip >}}

### Commands

```
sc.exe create daxin_blank.sys binPath=C:\windows\temp\daxin_blank.sys     type=kernel type=kernel &amp;&amp; sc.exe start daxin_blank.sys
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

| Filename | daxin_blank.sys |
|:---- | ---- | 
| MD5 | <a href="https://www.virustotal.com/gui/file/62c18d61ed324088f963510bae43b831">62c18d61ed324088f963510bae43b831</a> |
| SHA1 | <a href="https://www.virustotal.com/gui/file/8302802b709ad242a81b939b6c90b3230e1a1f1e">8302802b709ad242a81b939b6c90b3230e1a1f1e</a> |
| SHA256 | <a href="https://www.virustotal.com/gui/file/49c827cf48efb122a9d6fd87b426482b7496ccd4a2dbca31ebbf6b2b80c98530">49c827cf48efb122a9d6fd87b426482b7496ccd4a2dbca31ebbf6b2b80c98530</a> |
| Authentihash MD5 | <a href="https://www.virustotal.com/gui/search/authentihash%253A253bde63495fa4f995a6debae44e598e">253bde63495fa4f995a6debae44e598e</a> || Authentihash SHA1 | <a href="https://www.virustotal.com/gui/search/authentihash%253A57391d4c4e30f91e3e780d5242fd98a178ec67ac">57391d4c4e30f91e3e780d5242fd98a178ec67ac</a> || Authentihash SHA256 | <a href="https://www.virustotal.com/gui/search/authentihash%253Aa000d211840cb8fbcbf95c334b1d04eadb45ba03b0413c96472e47e9e22413ff">a000d211840cb8fbcbf95c334b1d04eadb45ba03b0413c96472e47e9e22413ff</a> || Publisher | Anhua Xinda (Beijing) Technology Co., Ltd. || Signature | S, i, g, n, e, d   || Date | 7:07 AM 1/23/2013 |
#### Imports
{{< details "Expand" >}}* ntoskrnl.exe
* NDIS.SYS
{{< /details >}}
#### ImportedFunctions
{{< details "Expand" >}}* wcsncmp
* DbgPrint
* IoAllocateMdl
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
* ZwOpenFile
* ZwWaitForSingleObject
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
* PsGetCurrentProcessId
* ZwDeviceIoControlFile
* IofCompleteRequest
* ZwClose
* MmMapLockedPagesSpecifyCache
* MmUserProbeAddress
* MmBuildMdlForNonPagedPool
* memchr
* KeDelayExecutionThread
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



[*source*](https://github.com/magicsword-io/LOLDrivers/tree/main/yaml/daxin_blank.yaml)

*last_updated:* 2023-04-16








{{< /column >}}
{{< /block >}}
