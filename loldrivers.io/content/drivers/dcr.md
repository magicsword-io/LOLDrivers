+++

description = ""
title = "dcr.sys"
weight = 10

+++


{{< block "grid-1" >}}
{{< column "mt-2 pt-1">}}


# dcr.sys ![:inline](/images/twitter_verified.png) 


### Description

DriveCrypt Dcr.sys vulnerability exploit for bypassing x64 DSE

- **Created**: 2023-04-14
- **Author**: Michael Haag
- **Acknowledgement**:  | [](https://twitter.com/)

{{< button "https://github.com/magicsword-io/LOLDrivers/raw/main/drivers/c24800c382b38707e556af957e9e94fd.bin" "Download" >}}
{{< tip "warning" >}}
This download link contains the vulnerable driver!

{{< /tip >}}

### Commands

```
sc.exe create dcr.sys binPath=C:\windows\temp\dcr.sys type=kernel &amp;&amp; sc.exe start dcr.sys
```

| Use Case | Privileges | Operating System | 
|:---- | ---- | ---- |
| Elevate privileges | kernel | Windows 10 |

### Resources
<br>
<li><a href="https://github.com/wjcsharp/DriveCrypt">https://github.com/wjcsharp/DriveCrypt</a></li>
<br>

### Known Vulnerable Samples

| Property           | Value |
|:-------------------|:------|
| Filename           | dcr.sys |
| MD5                | [c24800c382b38707e556af957e9e94fd](https://www.virustotal.com/gui/file/c24800c382b38707e556af957e9e94fd) |
| SHA1               | [b49ac8fefc6d1274d84fef44c1e5183cc7accba1](https://www.virustotal.com/gui/file/b49ac8fefc6d1274d84fef44c1e5183cc7accba1) |
| SHA256             | [3c6f9917418e991ed41540d8d882c8ca51d582a82fd01bff6cdf26591454faf5](https://www.virustotal.com/gui/file/3c6f9917418e991ed41540d8d882c8ca51d582a82fd01bff6cdf26591454faf5) |
| Authentihash MD5   | [accf79b751fafb101c1ce17fb7611b70](https://www.virustotal.com/gui/search/authentihash%253Aaccf79b751fafb101c1ce17fb7611b70) |
| Authentihash SHA1  | [8f2f1684a7305f32015d54c402790a47c6c7a0c9](https://www.virustotal.com/gui/search/authentihash%253A8f2f1684a7305f32015d54c402790a47c6c7a0c9) |
| Authentihash SHA256| [2b60228db4f3092063e115537b5731ef3487ecf55c036e812605c5149071332c](https://www.virustotal.com/gui/search/authentihash%253A2b60228db4f3092063e115537b5731ef3487ecf55c036e812605c5149071332c) |


#### Imports
{{< details "Expand" >}}
* ntoskrnl.exe

{{< /details >}}
#### ImportedFunctions
{{< details "Expand" >}}
* ExFreePoolWithTag
* RtlInitAnsiString
* IoCreateSymbolicLink
* PsTerminateSystemThread
* PoStartNextPowerIrp
* ObfDereferenceObject
* KeInitializeMutex
* ZwClose
* RtlAnsiStringToUnicodeString
* IofCompleteRequest
* wcsncat
* IoCreateDevice
* KeInitializeSemaphore
* ZwReadFile
* ObReferenceObjectByHandle
* KeWaitForSingleObject
* ZwSetInformationFile
* IoSetHardErrorOrVerifyDevice
* ZwWriteFile
* sprintf
* KeSetPriorityThread
* RtlFreeUnicodeString
* IoInitializeTimer
* IoStartTimer
* RtlDeleteRegistryValue
* RtlWriteRegistryValue
* RtlCreateRegistryKey
* ExAllocatePoolWithTag
* RtlInitUnicodeString
* ZwCreateFile
* IoAttachDevice
* ProbeForRead
* IoDeleteDevice
* PoCallDriver
* KeSetEvent
* IofCallDriver
* KeClearEvent
* ProbeForWrite
* PsCreateSystemThread
* KeReleaseSemaphore
* ExInterlockedRemoveHeadList
* ExInterlockedInsertTailList
* KeInitializeEvent
* IoDeleteSymbolicLink
* RtlQueryRegistryValues
* IoGetRelatedDeviceObject
* IoSetThreadHardErrorMode
* MmBuildMdlForNonPagedPool
* IoFreeMdl
* KeReleaseMutex
* IoFileObjectType
* MmMapLockedPagesSpecifyCache
* IoGetDeviceObjectPointer
* IoFreeIrp
* MmUnlockPages
* ZwQueryInformationFile
* IoAllocateMdl
* MmUnmapLockedPages
* IoBuildDeviceIoControlRequest
* IoAllocateIrp
* ZwDeviceIoControlFile
* ZwFsControlFile
* __C_specific_handler
* __chkstk

{{< /details >}}
#### ExportedFunctions
{{< details "Expand" >}}

{{< /details >}}
-----



[*source*](https://github.com/magicsword-io/LOLDrivers/tree/main/yaml/dcr.yaml)

*last_updated:* 2023-04-26








{{< /column >}}
{{< /block >}}
