+++

description = ""
title = "Agent64.sys"
weight = 10

+++


{{< block "grid-1" >}}
{{< column "mt-2 pt-1">}}


# Agent64.sys ![:inline](/images/twitter_verified.png) 


### Description

Agent64.sys is a vulnerable driver and more information will be added as found.

- **Created**: 2023-01-09
- **Author**: Michael Haag
- **Acknowledgement**:  | [](https://twitter.com/)

{{< button "https://github.com/magicsword-io/LOLDrivers/raw/main/drivers/8407ddfab85ae664e507c30314090385.bin" "Download" >}}
{{< tip "warning" >}}
This download link contains the vulnerable driver!

{{< /tip >}}

### Commands

```
sc.exe create Agent64.sys binPath=C:\windows\temp\Agent64.sys type=kernel &amp;&amp; sc.exe start Agent64.sys
```

| Use Case | Privileges | Operating System | 
|:---- | ---- | ---- |
| Elevate privileges | kernel | Windows 10 |

### Resources
<br>
<li><a href=" https://github.com/namazso/physmem_drivers"> https://github.com/namazso/physmem_drivers</a></li>
<li><a href="https://github.com/namazso/physmem_drivers">https://github.com/namazso/physmem_drivers</a></li>
<br>

### Known Vulnerable Samples

| Property           | Value |
|:-------------------|:------|
| Filename           | Agent64.sys |
| MD5                | [8407ddfab85ae664e507c30314090385](https://www.virustotal.com/gui/file/8407ddfab85ae664e507c30314090385) |
| SHA1               | [8db869c0674221a2d3280143cbb0807fac08e0cc](https://www.virustotal.com/gui/file/8db869c0674221a2d3280143cbb0807fac08e0cc) |
| SHA256             | [05f052c64d192cf69a462a5ec16dda0d43ca5d0245900c9fcb9201685a2e7748](https://www.virustotal.com/gui/file/05f052c64d192cf69a462a5ec16dda0d43ca5d0245900c9fcb9201685a2e7748) |
| Authentihash MD5   | [d86884546c97e614b73d16c600cfb2df](https://www.virustotal.com/gui/search/authentihash%253Ad86884546c97e614b73d16c600cfb2df) |
| Authentihash SHA1  | [94f7575a6bb378d0cf85b3dc65941c95415e7a80](https://www.virustotal.com/gui/search/authentihash%253A94f7575a6bb378d0cf85b3dc65941c95415e7a80) |
| Authentihash SHA256| [3bc0cec99dce687304dad8f7a6daf772e695cbd0169d346d03ae12500361a1e8](https://www.virustotal.com/gui/search/authentihash%253A3bc0cec99dce687304dad8f7a6daf772e695cbd0169d346d03ae12500361a1e8) |
| Publisher         | &#34;eSupport.com, Inc.&#34;, Phoenix Technologies Ltd, &#34;eSupport.com, Inc&#34;  |
| Signature         | eSupport.com, Inc., GlobalSign CodeSigning CA - SHA256 - G2, GlobalSign, GlobalSign Root CA - R1   |
| Company           | Phoenix Technologies |
| Description       | DriverAgent Direct I/O for 64-bit Windows |
| Product           | DriverAgent |
| OriginalFilename  | Agent64.sys |


#### Imports
{{< details "Expand" >}}
* ntoskrnl.exe
* HAL.dll

{{< /details >}}
#### ImportedFunctions
{{< details "Expand" >}}
* KeInitializeDpc
* IofCompleteRequest
* IoCreateSymbolicLink
* IoCreateDevice
* IofCallDriver
* ExFreePoolWithTag
* ExAllocatePool
* ZwClose
* MmUnmapLockedPages
* IoDeleteDevice
* KeSetEvent
* MmFreeContiguousMemory
* MmUnmapIoSpace
* IoFreeMdl
* ZwUnmapViewOfSection
* IoConnectInterrupt
* IoDisconnectInterrupt
* IoStartNextPacket
* KeInsertQueueDpc
* MmMapLockedPages
* ZwMapViewOfSection
* MmBuildMdlForNonPagedPool
* MmGetPhysicalAddress
* MmMapLockedPagesSpecifyCache
* ObReferenceObjectByHandle
* ZwOpenSection
* IoAllocateMdl
* MmAllocateContiguousMemory
* KeBugCheckEx
* RtlInitUnicodeString
* _snwprintf
* IoCreateNotificationEvent
* IoDeleteSymbolicLink
* HalTranslateBusAddress
* HalGetInterruptVector
* KeStallExecutionProcessor

{{< /details >}}
#### ExportedFunctions
{{< details "Expand" >}}

{{< /details >}}
-----
| Property           | Value |
|:-------------------|:------|
| Filename           | Agent64.sys |
| MD5                | [1ed08a6264c5c92099d6d1dae5e8f530](https://www.virustotal.com/gui/file/1ed08a6264c5c92099d6d1dae5e8f530) |
| SHA1               | [27d3ebea7655a72e6e8b95053753a25db944ec0f](https://www.virustotal.com/gui/file/27d3ebea7655a72e6e8b95053753a25db944ec0f) |
| SHA256             | [4045ae77859b1dbf13972451972eaaf6f3c97bea423e9e78f1c2f14330cd47ca](https://www.virustotal.com/gui/file/4045ae77859b1dbf13972451972eaaf6f3c97bea423e9e78f1c2f14330cd47ca) |
| Authentihash MD5   | [d86884546c97e614b73d16c600cfb2df](https://www.virustotal.com/gui/search/authentihash%253Ad86884546c97e614b73d16c600cfb2df) |
| Authentihash SHA1  | [94f7575a6bb378d0cf85b3dc65941c95415e7a80](https://www.virustotal.com/gui/search/authentihash%253A94f7575a6bb378d0cf85b3dc65941c95415e7a80) |
| Authentihash SHA256| [3bc0cec99dce687304dad8f7a6daf772e695cbd0169d346d03ae12500361a1e8](https://www.virustotal.com/gui/search/authentihash%253A3bc0cec99dce687304dad8f7a6daf772e695cbd0169d346d03ae12500361a1e8) |
| Publisher         | &#34;eSupport.com, Inc.&#34;, Phoenix Technologies Ltd, &#34;eSupport.com, Inc&#34;  |
| Signature         | Phoenix Technologies Ltd, GlobalSign ObjectSign CA, GlobalSign Primary Object Publishing CA, GlobalSign Root CA - R1   |
| Company           | Phoenix Technologies |
| Description       | DriverAgent Direct I/O for 64-bit Windows |
| Product           | DriverAgent |
| OriginalFilename  | Agent64.sys |


#### Imports
{{< details "Expand" >}}
* ntoskrnl.exe
* HAL.dll

{{< /details >}}
#### ImportedFunctions
{{< details "Expand" >}}
* KeInitializeDpc
* IofCompleteRequest
* IoCreateSymbolicLink
* IoCreateDevice
* IofCallDriver
* ExFreePoolWithTag
* ExAllocatePool
* ZwClose
* MmUnmapLockedPages
* IoDeleteDevice
* KeSetEvent
* MmFreeContiguousMemory
* MmUnmapIoSpace
* IoFreeMdl
* ZwUnmapViewOfSection
* IoConnectInterrupt
* IoDisconnectInterrupt
* IoStartNextPacket
* KeInsertQueueDpc
* MmMapLockedPages
* ZwMapViewOfSection
* MmBuildMdlForNonPagedPool
* MmGetPhysicalAddress
* MmMapLockedPagesSpecifyCache
* ObReferenceObjectByHandle
* ZwOpenSection
* IoAllocateMdl
* MmAllocateContiguousMemory
* KeBugCheckEx
* RtlInitUnicodeString
* _snwprintf
* IoCreateNotificationEvent
* IoDeleteSymbolicLink
* HalTranslateBusAddress
* HalGetInterruptVector
* KeStallExecutionProcessor

{{< /details >}}
#### ExportedFunctions
{{< details "Expand" >}}

{{< /details >}}
-----
| Property           | Value |
|:-------------------|:------|
| Filename           | Agent64.sys |
| MD5                | [ddc2ffe0ab3fcd48db898ab13c38d88d](https://www.virustotal.com/gui/file/ddc2ffe0ab3fcd48db898ab13c38d88d) |
| SHA1               | [33cdab3bbc8b3adce4067a1b042778607dce2acd](https://www.virustotal.com/gui/file/33cdab3bbc8b3adce4067a1b042778607dce2acd) |
| SHA256             | [6948480954137987a0be626c24cf594390960242cd75f094cd6aaa5c2e7a54fa](https://www.virustotal.com/gui/file/6948480954137987a0be626c24cf594390960242cd75f094cd6aaa5c2e7a54fa) |
| Authentihash MD5   | [d86884546c97e614b73d16c600cfb2df](https://www.virustotal.com/gui/search/authentihash%253Ad86884546c97e614b73d16c600cfb2df) |
| Authentihash SHA1  | [94f7575a6bb378d0cf85b3dc65941c95415e7a80](https://www.virustotal.com/gui/search/authentihash%253A94f7575a6bb378d0cf85b3dc65941c95415e7a80) |
| Authentihash SHA256| [3bc0cec99dce687304dad8f7a6daf772e695cbd0169d346d03ae12500361a1e8](https://www.virustotal.com/gui/search/authentihash%253A3bc0cec99dce687304dad8f7a6daf772e695cbd0169d346d03ae12500361a1e8) |
| Publisher         | &#34;eSupport.com, Inc.&#34;, Phoenix Technologies Ltd, &#34;eSupport.com, Inc&#34;  |
| Signature         | Phoenix Technologies Ltd, GlobalSign ObjectSign CA, GlobalSign Primary Object Publishing CA, GlobalSign Root CA - R1   |
| Company           | Phoenix Technologies |
| Description       | DriverAgent Direct I/O for 64-bit Windows |
| Product           | DriverAgent |
| OriginalFilename  | Agent64.sys |


#### Imports
{{< details "Expand" >}}
* ntoskrnl.exe
* HAL.dll

{{< /details >}}
#### ImportedFunctions
{{< details "Expand" >}}
* KeInitializeDpc
* IofCompleteRequest
* IoCreateSymbolicLink
* IoCreateDevice
* IofCallDriver
* ExFreePoolWithTag
* ExAllocatePool
* ZwClose
* MmUnmapLockedPages
* IoDeleteDevice
* KeSetEvent
* MmFreeContiguousMemory
* MmUnmapIoSpace
* IoFreeMdl
* ZwUnmapViewOfSection
* IoConnectInterrupt
* IoDisconnectInterrupt
* IoStartNextPacket
* KeInsertQueueDpc
* MmMapLockedPages
* ZwMapViewOfSection
* MmBuildMdlForNonPagedPool
* MmGetPhysicalAddress
* MmMapLockedPagesSpecifyCache
* ObReferenceObjectByHandle
* ZwOpenSection
* IoAllocateMdl
* MmAllocateContiguousMemory
* KeBugCheckEx
* RtlInitUnicodeString
* _snwprintf
* IoCreateNotificationEvent
* IoDeleteSymbolicLink
* HalTranslateBusAddress
* HalGetInterruptVector
* KeStallExecutionProcessor

{{< /details >}}
#### ExportedFunctions
{{< details "Expand" >}}

{{< /details >}}
-----
| Property           | Value |
|:-------------------|:------|
| Filename           | Agent64.sys |
| MD5                | [29ccff428e5eb70ae429c3da8968e1ec](https://www.virustotal.com/gui/file/29ccff428e5eb70ae429c3da8968e1ec) |
| SHA1               | [21e6c104fe9731c874fab5c9560c929b2857b918](https://www.virustotal.com/gui/file/21e6c104fe9731c874fab5c9560c929b2857b918) |
| SHA256             | [8cb62c5d41148de416014f80bd1fd033fd4d2bd504cb05b90eeb6992a382d58f](https://www.virustotal.com/gui/file/8cb62c5d41148de416014f80bd1fd033fd4d2bd504cb05b90eeb6992a382d58f) |
| Authentihash MD5   | [d86884546c97e614b73d16c600cfb2df](https://www.virustotal.com/gui/search/authentihash%253Ad86884546c97e614b73d16c600cfb2df) |
| Authentihash SHA1  | [94f7575a6bb378d0cf85b3dc65941c95415e7a80](https://www.virustotal.com/gui/search/authentihash%253A94f7575a6bb378d0cf85b3dc65941c95415e7a80) |
| Authentihash SHA256| [3bc0cec99dce687304dad8f7a6daf772e695cbd0169d346d03ae12500361a1e8](https://www.virustotal.com/gui/search/authentihash%253A3bc0cec99dce687304dad8f7a6daf772e695cbd0169d346d03ae12500361a1e8) |
| Publisher         | &#34;eSupport.com, Inc.&#34;, Phoenix Technologies Ltd, &#34;eSupport.com, Inc&#34;  |
| Signature         | eSupport.com, Inc, GlobalSign CodeSigning CA - G2, GlobalSign Root CA - R1   |
| Company           | Phoenix Technologies |
| Description       | DriverAgent Direct I/O for 64-bit Windows |
| Product           | DriverAgent |
| OriginalFilename  | Agent64.sys |


#### Imports
{{< details "Expand" >}}
* ntoskrnl.exe
* HAL.dll

{{< /details >}}
#### ImportedFunctions
{{< details "Expand" >}}
* KeInitializeDpc
* IofCompleteRequest
* IoCreateSymbolicLink
* IoCreateDevice
* IofCallDriver
* ExFreePoolWithTag
* ExAllocatePool
* ZwClose
* MmUnmapLockedPages
* IoDeleteDevice
* KeSetEvent
* MmFreeContiguousMemory
* MmUnmapIoSpace
* IoFreeMdl
* ZwUnmapViewOfSection
* IoConnectInterrupt
* IoDisconnectInterrupt
* IoStartNextPacket
* KeInsertQueueDpc
* MmMapLockedPages
* ZwMapViewOfSection
* MmBuildMdlForNonPagedPool
* MmGetPhysicalAddress
* MmMapLockedPagesSpecifyCache
* ObReferenceObjectByHandle
* ZwOpenSection
* IoAllocateMdl
* MmAllocateContiguousMemory
* KeBugCheckEx
* RtlInitUnicodeString
* _snwprintf
* IoCreateNotificationEvent
* IoDeleteSymbolicLink
* HalTranslateBusAddress
* HalGetInterruptVector
* KeStallExecutionProcessor

{{< /details >}}
#### ExportedFunctions
{{< details "Expand" >}}

{{< /details >}}
-----
| Property           | Value |
|:-------------------|:------|
| Filename           | Agent64.sys |
| MD5                | [a57b47489febc552515778dd0fd1e51c](https://www.virustotal.com/gui/file/a57b47489febc552515778dd0fd1e51c) |
| SHA1               | [d979353d04bf65cc92ad3412605bc81edbb75ec2](https://www.virustotal.com/gui/file/d979353d04bf65cc92ad3412605bc81edbb75ec2) |
| SHA256             | [b1d96233235a62dbb21b8dbe2d1ae333199669f67664b107bff1ad49b41d9414](https://www.virustotal.com/gui/file/b1d96233235a62dbb21b8dbe2d1ae333199669f67664b107bff1ad49b41d9414) |
| Authentihash MD5   | [d86884546c97e614b73d16c600cfb2df](https://www.virustotal.com/gui/search/authentihash%253Ad86884546c97e614b73d16c600cfb2df) |
| Authentihash SHA1  | [94f7575a6bb378d0cf85b3dc65941c95415e7a80](https://www.virustotal.com/gui/search/authentihash%253A94f7575a6bb378d0cf85b3dc65941c95415e7a80) |
| Authentihash SHA256| [3bc0cec99dce687304dad8f7a6daf772e695cbd0169d346d03ae12500361a1e8](https://www.virustotal.com/gui/search/authentihash%253A3bc0cec99dce687304dad8f7a6daf772e695cbd0169d346d03ae12500361a1e8) |
| Publisher         | &#34;eSupport.com, Inc.&#34;, Phoenix Technologies Ltd, &#34;eSupport.com, Inc&#34;  |
| Signature         | eSupport.com, Inc., GlobalSign Extended Validation CodeSigning CA - SHA256 - G2, GlobalSign, GlobalSign Root CA - R1   |
| Company           | Phoenix Technologies |
| Description       | DriverAgent Direct I/O for 64-bit Windows |
| Product           | DriverAgent |
| OriginalFilename  | Agent64.sys |


#### Imports
{{< details "Expand" >}}
* ntoskrnl.exe
* HAL.dll

{{< /details >}}
#### ImportedFunctions
{{< details "Expand" >}}
* KeInitializeDpc
* IofCompleteRequest
* IoCreateSymbolicLink
* IoCreateDevice
* IofCallDriver
* ExFreePoolWithTag
* ExAllocatePool
* ZwClose
* MmUnmapLockedPages
* IoDeleteDevice
* KeSetEvent
* MmFreeContiguousMemory
* MmUnmapIoSpace
* IoFreeMdl
* ZwUnmapViewOfSection
* IoConnectInterrupt
* IoDisconnectInterrupt
* IoStartNextPacket
* KeInsertQueueDpc
* MmMapLockedPages
* ZwMapViewOfSection
* MmBuildMdlForNonPagedPool
* MmGetPhysicalAddress
* MmMapLockedPagesSpecifyCache
* ObReferenceObjectByHandle
* ZwOpenSection
* IoAllocateMdl
* MmAllocateContiguousMemory
* KeBugCheckEx
* RtlInitUnicodeString
* _snwprintf
* IoCreateNotificationEvent
* IoDeleteSymbolicLink
* HalTranslateBusAddress
* HalGetInterruptVector
* KeStallExecutionProcessor

{{< /details >}}
#### ExportedFunctions
{{< details "Expand" >}}

{{< /details >}}
-----



[*source*](https://github.com/magicsword-io/LOLDrivers/tree/main/yaml/agent64.yaml)

*last_updated:* 2023-05-06








{{< /column >}}
{{< /block >}}
