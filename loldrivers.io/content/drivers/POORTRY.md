+++

description = ""
title = "POORTRY.sys"
weight = 10

+++


{{< block "grid-1" >}}
{{< column "mt-2 pt-1">}}


# POORTRY.sys ![:inline](/images/twitter_verified.png) 


### Description

Driver categorized as POORTRY by Mandiant.

- **Created**: 2023-03-04
- **Author**: Michael Haag
- **Acknowledgement**:  | [](https://twitter.com/)

{{< button "https://github.com/magicsword-io/LOLDrivers/raw/main/drivers/7f9309f5e4defec132b622fadbcad511.bin" "Download" >}}
{{< tip "warning" >}}
This download link contains the malicious driver!

{{< /tip >}}

### Commands

```
sc.exe create POORTRY.sys binPath=C:\windows\temp\POORTRY.sys type=kernel &amp;&amp; sc.exe start POORTRY.sys
```

| Use Case | Privileges | Operating System | 
|:---- | ---- | ---- |
| Elevate privileges | kernel | Windows 10 |

### Resources
<br>
<li><a href="https://www.mandiant.com/resources/blog/hunting-attestation-signed-malware">https://www.mandiant.com/resources/blog/hunting-attestation-signed-malware</a></li>
<li><a href=""></a></li>
<br>

### Known Vulnerable Samples

| Property           | Value |
|:-------------------|:------|
| Filename           | POORTRY.sys |
| MD5                | [7f9309f5e4defec132b622fadbcad511](https://www.virustotal.com/gui/file/7f9309f5e4defec132b622fadbcad511) |
| SHA1               | [a3ed5cbfbc17b58243289f3cf575bf04be49591d](https://www.virustotal.com/gui/file/a3ed5cbfbc17b58243289f3cf575bf04be49591d) |
| SHA256             | [6b5cf41512255237064e9274ca8f8a3fef820c45aa6067c9c6a0e6f5751a0421](https://www.virustotal.com/gui/file/6b5cf41512255237064e9274ca8f8a3fef820c45aa6067c9c6a0e6f5751a0421) |
| Authentihash MD5   | [103f3c1ce174dff5dfc79a428d4bf385](https://www.virustotal.com/gui/search/authentihash%253A103f3c1ce174dff5dfc79a428d4bf385) |
| Authentihash SHA1  | [b4d007b0c6ae6b4cfd96aab617f239cd8ebc8afb](https://www.virustotal.com/gui/search/authentihash%253Ab4d007b0c6ae6b4cfd96aab617f239cd8ebc8afb) |
| Authentihash SHA256| [45b9eee68266d1128bc252087f4a8ae18dbb0e0b6317e28bc248b25ca2431a56](https://www.virustotal.com/gui/search/authentihash%253A45b9eee68266d1128bc252087f4a8ae18dbb0e0b6317e28bc248b25ca2431a56) |
| Signature         | Microsoft Windows Hardware Compatibility Publisher, Microsoft Windows Third Party Component CA 2014, Microsoft Root Certificate Authority 2010   |


#### Imports
{{< details "Expand" >}}
* NETIO.SYS
* ntoskrnl.exe
* WDFLDR.SYS

{{< /details >}}
#### ImportedFunctions
{{< details "Expand" >}}
* WskCaptureProviderNPI
* WskReleaseProviderNPI
* WskDeregister
* WskRegister
* RtlDeleteElementGenericTableAvl
* vsprintf_s
* RtlEqualUnicodeString
* MmBuildMdlForNonPagedPool
* ObfDereferenceObject
* IoAllocateMdl
* ZwCreateSection
* ExAcquireResourceExclusiveLite
* ObCloseHandle
* IoCreateFileEx
* RtlInitUnicodeString
* RtlLookupElementGenericTableAvl
* ObReferenceObjectByHandleWithTag
* ZwQueryVirtualMemory
* IoFileObjectType
* KeStackAttachProcess
* ZwAllocateVirtualMemory
* PsLookupProcessByProcessId
* RtlImageNtHeader
* ZwMapViewOfSection
* RtlInitAnsiString
* RtlCaptureContext
* ExReleaseResourceLite
* _vsnprintf_s
* KeCapturePersistentThreadState
* IoFreeMdl
* wcsstr
* RtlCompareString
* ZwSetSystemInformation
* MmGetSystemRoutineAddress
* _stricmp
* ZwDeleteFile
* ExFreePoolWithTag
* ZwOpenFile
* ObReferenceObjectByName
* MmUnmapLockedPages
* IoDriverObjectType
* MmFlushImageSection
* ZwClose
* KeUnstackDetachProcess
* MmMapLockedPages
* __C_specific_handler
* MmIsAddressValid
* MmUnlockPages
* MmProbeAndLockPages
* IoFreeIrp
* KeSetEvent
* IoAllocateIrp
* KeInitializeEvent
* KeWaitForSingleObject
* ZwReadFile
* RtlCopyUnicodeString
* ZwUnmapViewOfSection
* ZwQuerySystemInformation
* ExAllocatePool
* RtlGetVersion
* __chkstk
* WdfVersionBindClass
* WdfVersionBind
* WdfVersionUnbind
* WdfVersionUnbindClass

{{< /details >}}
#### ExportedFunctions
{{< details "Expand" >}}

{{< /details >}}


[*source*](https://github.com/magicsword-io/LOLDrivers/tree/main/yaml/poortry.yaml)

*last_updated:* 2023-04-20








{{< /column >}}
{{< /block >}}
