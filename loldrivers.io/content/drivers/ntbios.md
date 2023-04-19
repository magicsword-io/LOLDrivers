+++

description = ""
title = "ntbios.sys"
weight = 10

+++


{{< block "grid-1" >}}
{{< column "mt-2 pt-1">}}


# ntbios.sys ![:inline](/images/twitter_verified.png) 


### Description

Driver used in the Daxin malware campaign.

- **Created**: 2023-02-28
- **Author**: Michael Haag
- **Acknowledgement**:  | [](https://twitter.com/)

{{< button "https://github.com/magicsword-io/LOLDrivers/raw/main/drivers/14580bd59c55185115fd3abe73b016a2.bin" "Download" >}}
{{< tip "warning" >}}
This download link contains the malicious driver!

{{< /tip >}}

### Commands

```
sc.exe create ntbios.sys binPath=C:\windows\temp \n \n \n  tbios.sys type=kernel &amp;&amp; sc.exe start ntbios.sys
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

| Filename | ntbios.sys |
|:---- | ---- | 
| MD5 | <a href="https://www.virustotal.com/gui/file/14580bd59c55185115fd3abe73b016a2">14580bd59c55185115fd3abe73b016a2</a> |
| SHA1 | <a href="https://www.virustotal.com/gui/file/71469dce9c2f38d0e0243a289f915131bf6dd2a8">71469dce9c2f38d0e0243a289f915131bf6dd2a8</a> |
| SHA256 | <a href="https://www.virustotal.com/gui/file/96bf3ee7c6673b69c6aa173bb44e21fa636b1c2c73f4356a7599c121284a51cc">96bf3ee7c6673b69c6aa173bb44e21fa636b1c2c73f4356a7599c121284a51cc</a> |
| Authentihash MD5 | <a href="https://www.virustotal.com/gui/search/authentihash%253Add3f6fe14dadb95f5d8c963006dec9d7">dd3f6fe14dadb95f5d8c963006dec9d7</a> || Authentihash SHA1 | <a href="https://www.virustotal.com/gui/search/authentihash%253A2374491565e5798dccd4db2dc2af7e9bbefafd5b">2374491565e5798dccd4db2dc2af7e9bbefafd5b</a> || Authentihash SHA256 | <a href="https://www.virustotal.com/gui/search/authentihash%253A50f9323eaf7c49cfca5890c6c46d729574d0caca89f7acc9f608c8226f54a975">50f9323eaf7c49cfca5890c6c46d729574d0caca89f7acc9f608c8226f54a975</a> || Publisher | n/a || Signature | U, n, s, i, g, n, e, d   || Date | 10:26 AM 11/19/2009 || Company | Microsoft Corporation || Description | ntbios driver || Product |  Microsoft(R) Windows (R) NT Operating System || OriginalFilename | ntbios.sys |
#### Imports
{{< details "Expand" >}}* NTOSKRNL.EXE
* HAL.DLL
* ntoskrnl.exe
* NDIS.SYS
{{< /details >}}
#### ImportedFunctions
{{< details "Expand" >}}* MmUnlockPages
* MmProbeAndLockPages
* IoAllocateMdl
* IoQueueWorkItem
* IoAllocateWorkItem
* IoGetCurrentProcess
* _stricmp
* IoFreeWorkItem
* RtlFreeUnicodeString
* ZwClose
* ZwWriteFile
* ZwCreateFile
* RtlAnsiStringToUnicodeString
* _strnicmp
* RtlUnwind
* RtlCopyUnicodeString
* wcsncmp
* swprintf
* IoCreateDevice
* IoCreateSymbolicLink
* KeInitializeSpinLock
* ExfInterlockedInsertTailList
* RtlInitUnicodeString
* MmMapLockedPagesSpecifyCache
* IoFreeMdl
* InterlockedDecrement
* InterlockedIncrement
* InterlockedExchange
* IoDeleteSymbolicLink
* IoDeleteDevice
* ExfInterlockedRemoveHeadList
* IofCompleteRequest
* ExAllocatePoolWithTag
* strncmp
* ExFreePool
* KfAcquireSpinLock
* KfReleaseSpinLock
* KeInitializeApc
* KeInsertQueueApc
* KeAttachProcess
* KeDetachProcess
* NtQuerySystemInformation
* NdisAllocatePacket
* NdisCopyFromPacketToPacket
* NdisAllocateMemory
* NdisFreePacket
* NdisAllocateBuffer
* NdisSetEvent
* NdisResetEvent
* NdisFreeBufferPool
* NdisFreePacketPool
* NdisFreeMemory
* NdisWaitEvent
* NdisQueryAdapterInstanceName
* NdisOpenAdapter
* NdisInitializeEvent
* NdisAllocatePacketPool
* NdisRegisterProtocol
* NdisAllocateBufferPool
* NdisCloseAdapter
* NdisDeregisterProtocol
{{< /details >}}
#### ExportedFunctions
{{< details "Expand" >}}{{< /details >}}



[*source*](https://github.com/magicsword-io/LOLDrivers/tree/main/yaml/ntbios.yaml)

*last_updated:* 2023-04-19








{{< /column >}}
{{< /block >}}
