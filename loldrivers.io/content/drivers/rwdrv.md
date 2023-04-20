+++

description = ""
title = "rwdrv.sys"
weight = 10

+++


{{< block "grid-1" >}}
{{< column "mt-2 pt-1">}}


# rwdrv.sys ![:inline](/images/twitter_verified.png) 


### Description

This utility access almost all the computer hardware, including PCI (PCI Express), PCI Index/Data, Memory, Memory Index/Data, I/O Space, I/O Index/Data, Super I/O, Clock Generator, DIMM SPD, SMBus Device, CPU MSR Registers, ATA/ATAPI Identify Data, Disk Read Write, ACPI Tables Dump (include AML decode), Embedded Controller, USB Information, SMBIOS Structures, PCI Option ROMs, MP Configuration Table, E820, EDID and Remote Access. And also a Command Window is provided to access hardware manually.


- **Created**: 2023-01-09
- **Author**: Michael Haag
- **Acknowledgement**:  | [](https://twitter.com/)

{{< button "https://github.com/magicsword-io/LOLDrivers/raw/main/drivers/257483d5d8b268d0d679956c7acdf02d.bin" "Download" >}}
{{< tip "warning" >}}
This download link contains the vulnerable driver!

{{< /tip >}}

### Commands

```
sc.exe create rwdrv.sys binPath=C:\windows\temp\rwdrv.sys type=kernel &amp;&amp; sc.exe start rwdrv.sys
```

| Use Case | Privileges | Operating System | 
|:---- | ---- | ---- |
| Elevate privileges | kernel | Windows 10 |

### Resources
<br>
<li><a href=" https://github.com/jbaines-r7/dellicious"> https://github.com/jbaines-r7/dellicious</a></li>
<li><a href=" https://www.rapid7.com/blog/post/2021/12/13/driver-based-attacks-past-and-present/"> https://www.rapid7.com/blog/post/2021/12/13/driver-based-attacks-past-and-present/</a></li>
<li><a href="http://rweverything.com/">http://rweverything.com/</a></li>
<li><a href="https://github.com/jbaines-r7/dellicious and https://www.rapid7.com/blog/post/2021/12/13/driver-based-attacks-past-and-present/">https://github.com/jbaines-r7/dellicious and https://www.rapid7.com/blog/post/2021/12/13/driver-based-attacks-past-and-present/</a></li>
<br>

### Known Vulnerable Samples

| Property           | Value |
|:-------------------|:------|
| Filename           | rwdrv.sys |
| MD5                | [257483d5d8b268d0d679956c7acdf02d](https://www.virustotal.com/gui/file/257483d5d8b268d0d679956c7acdf02d) |
| SHA1               | [fbf8b0613a2f7039aeb9fa09bd3b40c8ff49ded2](https://www.virustotal.com/gui/file/fbf8b0613a2f7039aeb9fa09bd3b40c8ff49ded2) |
| SHA256             | [ea0b9eecf4ad5ec8c14aec13de7d661e7615018b1a3c65464bf5eca9bbf6ded3](https://www.virustotal.com/gui/file/ea0b9eecf4ad5ec8c14aec13de7d661e7615018b1a3c65464bf5eca9bbf6ded3) |
| Authentihash MD5   | [3cd1454d2308cee5c59b45d5f952e70b](https://www.virustotal.com/gui/search/authentihash%253A3cd1454d2308cee5c59b45d5f952e70b) |
| Authentihash SHA1  | [2c3b01ff8ce024f70f9daad31ea6c78de54f239b](https://www.virustotal.com/gui/search/authentihash%253A2c3b01ff8ce024f70f9daad31ea6c78de54f239b) |
| Authentihash SHA256| [acb65f96f1d5c986b52d980a1c5ea009292ff472087fdd8a98a485404948f585](https://www.virustotal.com/gui/search/authentihash%253Aacb65f96f1d5c986b52d980a1c5ea009292ff472087fdd8a98a485404948f585) |
| Signature         | ChongKim Chan, GlobalSign CodeSigning CA - G2, GlobalSign Root CA - R1   |
| Company           | RW-Everything |
| Description       | RwDrv Driver |
| Product           | RwDrv Driver |
| OriginalFilename  | RwDrv.sys |


#### Imports
{{< details "Expand" >}}
* ntoskrnl.exe
* HAL.dll

{{< /details >}}
#### ImportedFunctions
{{< details "Expand" >}}
* ObfDereferenceObject
* IoUnregisterPlugPlayNotification
* ExFreePoolWithTag
* MmUnmapIoSpace
* MmMapIoSpace
* RtlCompareMemory
* ExAllocatePoolWithTag
* memcpy
* memset
* MmGetPhysicalAddress
* MmAllocateContiguousMemorySpecifyCache
* MmFreeContiguousMemorySpecifyCache
* IoFreeIrp
* IoFreeMdl
* MmUnlockPages
* RtlInitUnicodeString
* IoBuildAsynchronousFsdRequest
* KeWaitForSingleObject
* IoBuildDeviceIoControlRequest
* KeInitializeEvent
* RtlQueryRegistryValues
* IoFreeWorkItem
* IoGetDeviceObjectPointer
* ExfInterlockedInsertTailList
* IoQueueWorkItem
* IoAllocateWorkItem
* RtlCopyUnicodeString
* IoRegisterPlugPlayNotification
* IoCreateSymbolicLink
* IoCreateDevice
* KeTickCount
* IoDeleteSymbolicLink
* IoDeleteDevice
* IofCallDriver
* IofCompleteRequest
* KfReleaseSpinLock
* KeStallExecutionProcessor
* KfAcquireSpinLock

{{< /details >}}
#### ExportedFunctions
{{< details "Expand" >}}

{{< /details >}}
-----



[*source*](https://github.com/magicsword-io/LOLDrivers/tree/main/yaml/rwdrv.yaml)

*last_updated:* 2023-04-20








{{< /column >}}
{{< /block >}}
