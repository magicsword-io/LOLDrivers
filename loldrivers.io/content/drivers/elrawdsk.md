+++

description = ""
title = "elrawdsk.sys"
weight = 10

+++


{{< block "grid-1" >}}
{{< column "mt-2 pt-1">}}


# elrawdsk.sys ![:inline](/images/twitter_verified.png) 


### Description

elrawdsk.sys is a vulnerable driver and more information will be added as found.

- **Created**: 2023-01-09
- **Author**: Michael Haag
- **Acknowledgement**:  | [](https://twitter.com/)

{{< button "https://github.com/magicsword-io/LOLDrivers/raw/main/drivers/1493d342e7a36553c56b2adea150949e.bin" "Download" >}}
{{< tip "warning" >}}
This download link contains the vulnerable driver!

{{< /tip >}}

### Commands

```
sc.exe create elrawdsk.sys binPath=C:\windows\temp\elrawdsk.sys type=kernel &amp;&amp; sc.exe start elrawdsk.sys
```

| Use Case | Privileges | Operating System | 
|:---- | ---- | ---- |
| Elevate privileges | kernel | Windows 10 |

### Resources
<br>
<li><a href=" https://github.com/jbaines-r7/dellicious"> https://github.com/jbaines-r7/dellicious</a></li>
<li><a href=" https://www.rapid7.com/blog/post/2021/12/13/driver-based-attacks-past-and-present/"> https://www.rapid7.com/blog/post/2021/12/13/driver-based-attacks-past-and-present/</a></li>
<li><a href="https://securelist.com/shamoon-the-wiper-further-details-part-ii/57784/">https://securelist.com/shamoon-the-wiper-further-details-part-ii/57784/</a></li>
<li><a href="https://github.com/Yara-Rules/rules/blob/master/malware/MALW_Shamoon.yar">https://github.com/Yara-Rules/rules/blob/master/malware/MALW_Shamoon.yar</a></li>
<li><a href="https://github.com/jbaines-r7/dellicious and https://www.rapid7.com/blog/post/2021/12/13/driver-based-attacks-past-and-present/">https://github.com/jbaines-r7/dellicious and https://www.rapid7.com/blog/post/2021/12/13/driver-based-attacks-past-and-present/</a></li>
<br>

### Known Vulnerable Samples

| Property           | Value |
|:-------------------|:------|
| Filename           | elrawdsk.sys |
| MD5                | [1493d342e7a36553c56b2adea150949e](https://www.virustotal.com/gui/file/1493d342e7a36553c56b2adea150949e) |
| SHA1               | [ce549714a11bd43b52be709581c6e144957136ec](https://www.virustotal.com/gui/file/ce549714a11bd43b52be709581c6e144957136ec) |
| SHA256             | [4744df6ac02ff0a3f9ad0bf47b15854bbebb73c936dd02f7c79293a2828406f6](https://www.virustotal.com/gui/file/4744df6ac02ff0a3f9ad0bf47b15854bbebb73c936dd02f7c79293a2828406f6) |
| Authentihash MD5   | [20f14b58e9548b6ea99b35006f631197](https://www.virustotal.com/gui/search/authentihash%253A20f14b58e9548b6ea99b35006f631197) |
| Authentihash SHA1  | [174bd2e0965b996cff4a26ac511e551788fbc894](https://www.virustotal.com/gui/search/authentihash%253A174bd2e0965b996cff4a26ac511e551788fbc894) |
| Authentihash SHA256| [98a55dc61046f4509d2465cbc373a9391c07125e5f4a242d2f475f14f32e5430](https://www.virustotal.com/gui/search/authentihash%253A98a55dc61046f4509d2465cbc373a9391c07125e5f4a242d2f475f14f32e5430) |
| Signature         | EldoS Corporation, GlobalSign ObjectSign CA, GlobalSign Primary Object Publishing CA, GlobalSign Root CA - R1   |
| Company           | EldoS Corporation |
| Description       | RawDisk Driver. Allows write access to files and raw disk sectors for user mode applications in Windows 2000 and later. |
| Product           | RawDisk |
| OriginalFilename  | elrawdsk.sys |


#### Imports
{{< details "Expand" >}}
* ntoskrnl.exe
* HAL.dll

{{< /details >}}
#### ImportedFunctions
{{< details "Expand" >}}
* MmUnlockPages
* KeSetEvent
* IoDeleteDevice
* IoDeleteSymbolicLink
* RtlInitUnicodeString
* RtlPrefixUnicodeString
* FsRtlIsNtstatusExpected
* MmProbeAndLockPages
* ExRaiseStatus
* IoAllocateMdl
* MmMapLockedPagesSpecifyCache
* KeWaitForSingleObject
* IofCallDriver
* IoBuildDeviceIoControlRequest
* KeInitializeEvent
* ExAllocatePoolWithTag
* memcpy
* ZwClose
* ObfDereferenceObject
* ObQueryNameString
* ObReferenceObjectByHandle
* IoFileObjectType
* ZwOpenFile
* RtlAppendUnicodeStringToString
* KeUnstackDetachProcess
* MmSystemRangeStart
* KeStackAttachProcess
* ZwQueryInformationProcess
* ObOpenObjectByPointer
* PsLookupProcessByProcessId
* IoBuildAsynchronousFsdRequest
* IoBuildSynchronousFsdRequest
* IoFreeMdl
* PsGetCurrentProcessId
* KeQuerySystemTime
* RtlFreeAnsiString
* RtlUnicodeStringToAnsiString
* PsGetVersion
* MmGetSystemRoutineAddress
* IoCreateSymbolicLink
* IoCreateDevice
* ObfReferenceObject
* IoGetAttachedDevice
* memset
* KeLeaveCriticalRegion
* ExReleaseFastMutexUnsafe
* IoGetRelatedDeviceObject
* ExAcquireFastMutexUnsafe
* KeEnterCriticalRegion
* KeGetCurrentThread
* ZwCreateFile
* IoAllocateIrp
* IoReuseIrp
* KeResetEvent
* CcPurgeCacheSection
* ExReleaseResourceLite
* ExAcquireResourceExclusiveLite
* CcFlushCache
* _allrem
* RtlCompareMemory
* MmUnmapIoSpace
* MmMapIoSpace
* KeTickCount
* ExFreePoolWithTag
* IoFreeIrp
* RtlCompareUnicodeString
* IofCompleteRequest
* RtlUnwind
* KeBugCheckEx
* KeGetCurrentIrql

{{< /details >}}
#### ExportedFunctions
{{< details "Expand" >}}

{{< /details >}}| Property           | Value |
|:-------------------|:------|
| Filename           | elrawdsk.sys |
| MD5                | [76c643ab29d497317085e5db8c799960](https://www.virustotal.com/gui/file/76c643ab29d497317085e5db8c799960) |
| SHA1               | [1292c7dd60214d96a71e7705e519006b9de7968f](https://www.virustotal.com/gui/file/1292c7dd60214d96a71e7705e519006b9de7968f) |
| SHA256             | [5a826b4fa10891cf63aae832fc645ce680a483b915c608ca26cedbb173b1b80a](https://www.virustotal.com/gui/file/5a826b4fa10891cf63aae832fc645ce680a483b915c608ca26cedbb173b1b80a) |
| Authentihash MD5   | [c1afcba807a13aa25a0b363a22c760d6](https://www.virustotal.com/gui/search/authentihash%253Ac1afcba807a13aa25a0b363a22c760d6) |
| Authentihash SHA1  | [8422fb53e48b27a42cc7595ca7c7ae0597168db6](https://www.virustotal.com/gui/search/authentihash%253A8422fb53e48b27a42cc7595ca7c7ae0597168db6) |
| Authentihash SHA256| [29a2ae6439381ea2aa3116df7025cbb5c6c7c07cc8d19508e6021e4d6177a565](https://www.virustotal.com/gui/search/authentihash%253A29a2ae6439381ea2aa3116df7025cbb5c6c7c07cc8d19508e6021e4d6177a565) |
| Signature         | EldoS Corporation, GlobalSign ObjectSign CA, GlobalSign Primary Object Publishing CA, GlobalSign Root CA - R1   |
| Company           | EldoS Corporation |
| Description       | RawDisk Driver. Allows write access to files and raw disk sectors for user mode applications in Windows 2000 and later. |
| Product           | RawDisk |
| OriginalFilename  | elrawdsk.sys |


#### Imports
{{< details "Expand" >}}
* ntoskrnl.exe

{{< /details >}}
#### ImportedFunctions
{{< details "Expand" >}}
* MmSystemRangeStart
* ExAllocatePoolWithTag
* ExRaiseStatus
* IoBuildDeviceIoControlRequest
* IoDeleteSymbolicLink
* ExFreePoolWithTag
* PsLookupProcessByProcessId
* IoBuildSynchronousFsdRequest
* RtlInitUnicodeString
* IoDeleteDevice
* KeSetEvent
* MmGetSystemRoutineAddress
* KeInitializeEvent
* RtlUnicodeStringToAnsiString
* IoFreeMdl
* KeUnstackDetachProcess
* MmMapLockedPagesSpecifyCache
* IoBuildAsynchronousFsdRequest
* RtlPrefixUnicodeString
* ZwClose
* IofCompleteRequest
* ObReferenceObjectByHandle
* KeWaitForSingleObject
* IoFreeIrp
* RtlFreeAnsiString
* MmProbeAndLockPages
* PsGetVersion
* RtlCompareUnicodeString
* MmUnlockPages
* ZwQueryInformationProcess
* IoCreateSymbolicLink
* PsGetCurrentProcessId
* ObfDereferenceObject
* IoCreateDevice
* ZwOpenFile
* FsRtlIsNtstatusExpected
* ObOpenObjectByPointer
* KeStackAttachProcess
* IoAllocateMdl
* IofCallDriver
* ExReleaseFastMutexUnsafe
* KeLeaveCriticalRegion
* IoGetAttachedDevice
* IoGetRelatedDeviceObject
* KeEnterCriticalRegion
* ExAcquireFastMutexUnsafe
* ObfReferenceObject
* ExAcquireResourceExclusiveLite
* IoReuseIrp
* KeResetEvent
* CcPurgeCacheSection
* CcFlushCache
* ZwCreateFile
* ExReleaseResourceLite
* IoAllocateIrp
* RtlCompareMemory
* MmUnmapIoSpace
* MmMapIoSpace
* KeBugCheckEx
* __C_specific_handler

{{< /details >}}
#### ExportedFunctions
{{< details "Expand" >}}

{{< /details >}}


[*source*](https://github.com/magicsword-io/LOLDrivers/tree/main/yaml/elrawdsk.yaml)

*last_updated:* 2023-04-20








{{< /column >}}
{{< /block >}}
