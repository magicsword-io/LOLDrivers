+++

description = ""
title = "rtkio64.sys"
weight = 10

+++


{{< block "grid-1" >}}
{{< column "mt-2 pt-1">}}


# rtkio64.sys ![:inline](/images/twitter_verified.png) 


### Description

rtkio64.sys is a vulnerable driver and more information will be added as found.

- **Created**: 2023-01-09
- **Author**: Michael Haag
- **Acknowledgement**:  | [](https://twitter.com/)

{{< button "https://github.com/magicsword-io/LOLDrivers/raw/main/drivers/70dcd07d38017b43f710061f37cb4a91.bin" "Download" >}}
{{< tip "warning" >}}
This download link contains the vulnerable driver!

{{< /tip >}}

### Commands

```
sc.exe create rtkio64.sys binPath=C:\windows\temp\rtkio64.sys type=kernel &amp;&amp; sc.exe start rtkio64.sys
```

| Use Case | Privileges | Operating System | 
|:---- | ---- | ---- |
| Elevate privileges | kernel | Windows 10 |

### Resources
<br>
<li><a href=" https://github.com/eclypsium/Screwed-Drivers/blob/master/DRIVERS.md"> https://github.com/eclypsium/Screwed-Drivers/blob/master/DRIVERS.md</a></li>
<li><a href="https://github.com/eclypsium/Screwed-Drivers/blob/master/DRIVERS.md">https://github.com/eclypsium/Screwed-Drivers/blob/master/DRIVERS.md</a></li>
<br>

### Known Vulnerable Samples

| Property           | Value |
|:-------------------|:------|
| Filename           | rtkio64.sys |
| MD5                | [70dcd07d38017b43f710061f37cb4a91](https://www.virustotal.com/gui/file/70dcd07d38017b43f710061f37cb4a91) |
| SHA1               | [99201c9555e5faf6e8d82da793b148311f8aa4b8](https://www.virustotal.com/gui/file/99201c9555e5faf6e8d82da793b148311f8aa4b8) |
| SHA256             | [7133a461aeb03b4d69d43f3d26cd1a9e3ee01694e97a0645a3d8aa1a44c39129](https://www.virustotal.com/gui/file/7133a461aeb03b4d69d43f3d26cd1a9e3ee01694e97a0645a3d8aa1a44c39129) |
| Authentihash MD5   | [dbe68427fd1f2194715b4d146dedeae7](https://www.virustotal.com/gui/search/authentihash%253Adbe68427fd1f2194715b4d146dedeae7) |
| Authentihash SHA1  | [118ebc5c7ac859d17c14ceeaa8ab973d694fdd7b](https://www.virustotal.com/gui/search/authentihash%253A118ebc5c7ac859d17c14ceeaa8ab973d694fdd7b) |
| Authentihash SHA256| [e46bb410c3bb95a1f3d61ced157c679bfac7dc997534e46b83b234a6fc5cbb14](https://www.virustotal.com/gui/search/authentihash%253Ae46bb410c3bb95a1f3d61ced157c679bfac7dc997534e46b83b234a6fc5cbb14) |
| Signature         | Realtek Semiconductor Corp., DigiCert EV Code Signing CA, DigiCert   |
| Company           | Realtek                                             |
| Description       | Realtek IO Driver |
| Product           | Realtek IO Driver                       |
| OriginalFilename  | rtkio64.sys  |


#### Imports
{{< details "Expand" >}}
* ntoskrnl.exe
* HAL.dll

{{< /details >}}
#### ImportedFunctions
{{< details "Expand" >}}
* MmMapIoSpace
* MmUnmapLockedPages
* ExUnregisterCallback
* ExAllocatePoolWithTag
* IoWMIRegistrationControl
* KeQueryActiveProcessors
* IoDeleteSymbolicLink
* ExFreePoolWithTag
* IoWMIWriteEvent
* IoRegisterShutdownNotification
* RtlInitUnicodeString
* IoDeleteDevice
* MmGetSystemRoutineAddress
* MmBuildMdlForNonPagedPool
* IoFreeMdl
* MmUnmapIoSpace
* ZwQueryValueKey
* IoUnregisterShutdownNotification
* ZwClose
* IofCompleteRequest
* ExRegisterCallback
* RtlCompareMemory
* IoCreateSymbolicLink
* KeSetSystemAffinityThread
* ObfDereferenceObject
* IoCreateDevice
* ExCreateCallback
* IoAllocateMdl
* ZwOpenKey
* KeBugCheckEx
* MmMapLockedPagesSpecifyCache
* _vsnprintf
* __C_specific_handler
* KeStallExecutionProcessor

{{< /details >}}
#### ExportedFunctions
{{< details "Expand" >}}

{{< /details >}}


[*source*](https://github.com/magicsword-io/LOLDrivers/tree/main/yaml/rtkio64.yaml)

*last_updated:* 2023-04-20








{{< /column >}}
{{< /block >}}
