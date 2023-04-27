+++

description = ""
title = "viragt.sys"
weight = 10

+++


{{< block "grid-1" >}}
{{< column "mt-2 pt-1">}}


# viragt.sys ![:inline](/images/twitter_verified.png) 


### Description

viragt.sys is a vulnerable driver and more information will be added as found.

- **Created**: 2023-01-09
- **Author**: Michael Haag
- **Acknowledgement**:  | [](https://twitter.com/)

{{< button "https://github.com/magicsword-io/LOLDrivers/raw/main/drivers/e79c91c27df3eaf82fb7bd1280172517.bin" "Download" >}}
{{< tip "warning" >}}
This download link contains the vulnerable driver!

{{< /tip >}}

### Commands

```
sc.exe create viragt.sys binPath=C:\windows\temp\viragt.sys type=kernel &amp;&amp; sc.exe start viragt.sys
```

| Use Case | Privileges | Operating System | 
|:---- | ---- | ---- |
| Elevate privileges | kernel | Windows 10 |

### Resources
<br>
<li><a href=" https://github.com/elastic/protections-artifacts/search?q=VulnDriver"> https://github.com/elastic/protections-artifacts/search?q=VulnDriver</a></li>
<li><a href="https://github.com/elastic/protections-artifacts/search?q=VulnDriver">https://github.com/elastic/protections-artifacts/search?q=VulnDriver</a></li>
<br>

### Known Vulnerable Samples

| Property           | Value |
|:-------------------|:------|
| Filename           | viragt.sys |
| MD5                | [e79c91c27df3eaf82fb7bd1280172517](https://www.virustotal.com/gui/file/e79c91c27df3eaf82fb7bd1280172517) |
| SHA1               | [cb22723faa5ae2809476e5c5e9b9a597b26cab9b](https://www.virustotal.com/gui/file/cb22723faa5ae2809476e5c5e9b9a597b26cab9b) |
| SHA256             | [e05eeb2b8c18ad2cb2d1038c043d770a0d51b96b748bc34be3e7fc6f3790ce53](https://www.virustotal.com/gui/file/e05eeb2b8c18ad2cb2d1038c043d770a0d51b96b748bc34be3e7fc6f3790ce53) |
| Authentihash MD5   | [333822355a23fbdfb2599a909b3bbc60](https://www.virustotal.com/gui/search/authentihash%253A333822355a23fbdfb2599a909b3bbc60) |
| Authentihash SHA1  | [72886a692656ebe64592a43273d3f59432cfbf9a](https://www.virustotal.com/gui/search/authentihash%253A72886a692656ebe64592a43273d3f59432cfbf9a) |
| Authentihash SHA256| [9f86fc8a6eaa3b38f33be4a0d552c184e575afa50a60df7383c06a394e3926d8](https://www.virustotal.com/gui/search/authentihash%253A9f86fc8a6eaa3b38f33be4a0d552c184e575afa50a60df7383c06a394e3926d8) |
| Signature         | TG Soft S.a.s. Di Tonello Gianfranco e C., VeriSign Class 3 Code Signing 2010 CA, VeriSign   |
| Company           | TG Soft S.a.s. |
| Description       | VirIT Agent System |
| Product           | VirIT Agent System |
| OriginalFilename  | viragt.sys |


#### Imports
{{< details "Expand" >}}
* ntoskrnl.exe
* HAL.dll

{{< /details >}}
#### ImportedFunctions
{{< details "Expand" >}}
* RtlInitAnsiString
* wcstombs
* ZwOpenKey
* ZwSetValueKey
* ZwDeleteKey
* RtlFormatCurrentUserKeyPath
* ZwEnumerateKey
* ZwEnumerateValueKey
* ZwCreateFile
* KeWaitForSingleObject
* IofCallDriver
* IoBuildSynchronousFsdRequest
* KeInitializeEvent
* ObfDereferenceObject
* IoGetRelatedDeviceObject
* ObReferenceObjectByHandle
* ZwReadFile
* ZwWriteFile
* ZwSetInformationFile
* ZwOpenProcess
* ZwTerminateProcess
* _strupr
* ZwQuerySystemInformation
* IoFreeMdl
* MmUnlockPages
* MmIsAddressValid
* MmProbeAndLockPages
* MmMapLockedPagesSpecifyCache
* MmBuildMdlForNonPagedPool
* IoAllocateMdl
* MmIsNonPagedSystemAddressValid
* IoGetCurrentProcess
* PsLookupProcessByProcessId
* IoDeleteDevice
* IoDeleteSymbolicLink
* RtlInitUnicodeString
* sprintf
* RtlTimeToTimeFields
* ExSystemTimeToLocalTime
* KeQuerySystemTime
* strstr
* KeServiceDescriptorTable
* KeReleaseMutex
* KeDelayExecutionThread
* RtlAnsiStringToUnicodeString
* ExQueueWorkItem
* KeInsertQueueDpc
* KeSetTargetProcessorDpc
* KeInitializeDpc
* KeNumberProcessors
* IofCompleteRequest
* memcpy
* IoCreateSymbolicLink
* IoCreateDevice
* PsCreateSystemThread
* KeInitializeMutex
* ObOpenObjectByName
* IoDriverObjectType
* ZwOpenDirectoryObject
* RtlUnicodeStringToAnsiString
* ZwQueryDirectoryObject
* IoFileObjectType
* swprintf
* DbgPrint
* IoFreeIrp
* MmUnmapLockedPages
* KeSetEvent
* MmLockPagableSectionByHandle
* MmLockPagableDataSection
* IoAllocateIrp
* _wcsnicmp
* RtlCompareMemory
* IoBuildDeviceIoControlRequest
* _alldiv
* wcsrchr
* ZwQueryVolumeInformationFile
* ZwDeviceIoControlFile
* _strnicmp
* ZwFsControlFile
* _allmul
* ObfReferenceObject
* _allrem
* _stricmp
* strrchr
* KeQueryActiveProcessors
* KeTickCount
* KeBugCheckEx
* ZwCreateKey
* ZwQueryValueKey
* ExAllocatePoolWithTag
* ExFreePoolWithTag
* mbstowcs
* ZwClose
* memset
* PsTerminateSystemThread
* ZwQueryInformationFile
* RtlUnwind
* KeRaiseIrqlToDpcLevel
* KfRaiseIrql
* KfLowerIrql
* KeGetCurrentIrql
* READ_PORT_ULONG
* WRITE_PORT_UCHAR
* READ_PORT_UCHAR
* READ_PORT_BUFFER_UCHAR
* KeStallExecutionProcessor

{{< /details >}}
#### ExportedFunctions
{{< details "Expand" >}}

{{< /details >}}
-----



[*source*](https://github.com/magicsword-io/LOLDrivers/tree/main/yaml/viragt.yaml)

*last_updated:* 2023-04-27








{{< /column >}}
{{< /block >}}
