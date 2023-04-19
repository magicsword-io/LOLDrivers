+++

description = ""
title = "daxin_blank4.sys"
weight = 10

+++


{{< block "grid-1" >}}
{{< column "mt-2 pt-1">}}


# daxin_blank4.sys ![:inline](/images/twitter_verified.png) 


### Description

Driver used in the Daxin malware campaign.

- **Created**: 2023-02-28
- **Author**: Michael Haag
- **Acknowledgement**:  | [](https://twitter.com/)

{{< button "https://github.com/magicsword-io/LOLDrivers/raw/main/drivers/491aec2249ad8e2020f9f9b559ab68a8.bin" "Download" >}}
{{< tip "warning" >}}
This download link contains the malicious driver!

{{< /tip >}}

### Commands

```
sc.exe create daxin_blank4.sys binPath=C:\windows\temp\daxin_blank4.sys     type=kernel &amp;&amp; sc.exe start daxin_blank4.sys
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

| Filename | daxin_blank4.sys |
|:---- | ---- | 
| MD5 | <a href="https://www.virustotal.com/gui/file/491aec2249ad8e2020f9f9b559ab68a8">491aec2249ad8e2020f9f9b559ab68a8</a> |
| SHA1 | <a href="https://www.virustotal.com/gui/file/8692274681e8d10c26ddf2b993f31974b04f5bf0">8692274681e8d10c26ddf2b993f31974b04f5bf0</a> |
| SHA256 | <a href="https://www.virustotal.com/gui/file/8dafe5f3d0527b66f6857559e3c81872699003e0f2ffda9202a1b5e29db2002e">8dafe5f3d0527b66f6857559e3c81872699003e0f2ffda9202a1b5e29db2002e</a> |
| Authentihash MD5 | <a href="https://www.virustotal.com/gui/search/authentihash%253Af66f4d6b97b9e7b0e467daed2ed69bed">f66f4d6b97b9e7b0e467daed2ed69bed</a> || Authentihash SHA1 | <a href="https://www.virustotal.com/gui/search/authentihash%253Ac8f227b45d27c43db4b661ef610efbfacfda8a75">c8f227b45d27c43db4b661ef610efbfacfda8a75</a> || Authentihash SHA256 | <a href="https://www.virustotal.com/gui/search/authentihash%253A15b081ec83a89182b5bb0a642d56513f40810b5b0a42e904ab6d3fa8f34c0446">15b081ec83a89182b5bb0a642d56513f40810b5b0a42e904ab6d3fa8f34c0446</a> || Publisher | n/a || Signature | U, n, s, i, g, n, e, d   || Date | 8:42 AM 4/20/2010 |
#### Imports
{{< details "Expand" >}}* NTOSKRNL.EXE
* HAL.DLL
* ntoskrnl.exe
* NDIS.SYS
{{< /details >}}
#### ImportedFunctions
{{< details "Expand" >}}* strlen
* IoFreeMdl
* MmMapLockedPagesSpecifyCache
* ZwClose
* IofCompleteRequest
* KeResetEvent
* InterlockedIncrement
* KeSetEvent
* InterlockedDecrement
* RtlUnicodeStringToInteger
* RtlInitUnicodeString
* KeInitializeEvent
* wcsncmp
* wcscat
* wcslen
* wcscpy
* MmBuildMdlForNonPagedPool
* IoAllocateMdl
* strncmp
* MmMapLockedPages
* MmProbeAndLockPages
* MmUnlockPages
* MmUnmapLockedPages
* RtlFreeUnicodeString
* ZwWriteFile
* ZwCreateFile
* RtlAnsiStringToUnicodeString
* strcat
* ZwReadFile
* ZwQueryInformationFile
* _wcsnicmp
* strcmp
* _stricmp
* MmGetSystemRoutineAddress
* ZwQueryValueKey
* ZwOpenKey
* IoCreateFile
* KeWaitForMultipleObjects
* strcpy
* RtlUnwind
* vsprintf
* KeWaitForSingleObject
* KeDelayExecutionThread
* PsTerminateSystemThread
* PsCreateSystemThread
* ObReferenceObjectByHandle
* ExFreePool
* KeInitializeSpinLock
* KeTickCount
* memset
* memcpy
* RtlCompareUnicodeString
* ExAllocatePoolWithTag
* KfAcquireSpinLock
* KfReleaseSpinLock
* PsGetVersion
* ZwTerminateProcess
* ZwOpenProcess
* RtlSetDaclSecurityDescriptor
* RtlAddAccessAllowedAce
* RtlCreateAcl
* RtlLengthSid
* RtlCreateSecurityDescriptor
* ZwWaitForSingleObject
* NtFsControlFile
* NtWriteFile
* NtReadFile
* RtlLengthRequiredSid
* RtlImageDirectoryEntryToData
* ZwQueryInformationProcess
* ZwQuerySystemInformation
* PsLookupProcessByProcessId
* KeAttachProcess
* KeDetachProcess
* PsLookupThreadByThreadId
* KeInitializeApc
* KeInsertQueueApc
* ZwOpenFile
* ZwDeviceIoControlFile
* PsThreadType
* NtQuerySystemInformation
* NdisAllocateMemory
* NdisAllocatePacket
* NdisCopyFromPacketToPacket
* NdisFreePacket
* NdisAllocateBuffer
* NdisDeregisterProtocol
* NdisRegisterProtocol
* NdisAllocateBufferPool
* NdisAllocatePacketPool
* NdisFreeBufferPool
* NdisFreePacketPool
* NdisFreeMemory
{{< /details >}}
#### ExportedFunctions
{{< details "Expand" >}}{{< /details >}}



[*source*](https://github.com/magicsword-io/LOLDrivers/tree/main/yaml/daxin_blank4.yaml)

*last_updated:* 2023-04-19








{{< /column >}}
{{< /block >}}
