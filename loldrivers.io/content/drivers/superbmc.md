+++

description = ""
title = "superbmc.sys"
weight = 10

+++


{{< block "grid-1" >}}
{{< column "mt-2 pt-1">}}


# superbmc.sys ![:inline](/images/twitter_verified.png) 


### Description

superbmc.sys is a vulnerable driver and more information will be added as found.

- **Created**: 2023-01-09
- **Author**: Michael Haag
- **Acknowledgement**:  | [](https://twitter.com/)

{{< button "https://github.com/magicsword-io/LOLDrivers/raw/main/drivers/3473faea65fba5d4fbe54c0898a3c044.bin" "Download" >}}
{{< tip "warning" >}}
This download link contains the vulnerable driver!

{{< /tip >}}

### Commands

```
sc.exe create superbmc.sys binPath=C:\windows\temp\superbmc.sys type=kernel &amp;&amp; sc.exe start superbmc.sys
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
| Filename           | superbmc.sys |
| MD5                | [3473faea65fba5d4fbe54c0898a3c044](https://www.virustotal.com/gui/file/3473faea65fba5d4fbe54c0898a3c044) |
| SHA1               | [910cb12aa49e9f35ecc4907e8304adf0dcca8cf1](https://www.virustotal.com/gui/file/910cb12aa49e9f35ecc4907e8304adf0dcca8cf1) |
| SHA256             | [f8430bdc6fd01f42217d66d87a3ef6f66cb2700ebb39c4f25c8b851858cc4b35](https://www.virustotal.com/gui/file/f8430bdc6fd01f42217d66d87a3ef6f66cb2700ebb39c4f25c8b851858cc4b35) |
| Authentihash MD5   | [70f41d3749f4608b64902dd2c1f1e14f](https://www.virustotal.com/gui/search/authentihash%253A70f41d3749f4608b64902dd2c1f1e14f) |
| Authentihash SHA1  | [c6609cad7208669e4c34f71f682af1a6bcddc11f](https://www.virustotal.com/gui/search/authentihash%253Ac6609cad7208669e4c34f71f682af1a6bcddc11f) |
| Authentihash SHA256| [9c4ffe4815b5755d2609be21ba53c9157e8f71137f06fe35044406b968b80320](https://www.virustotal.com/gui/search/authentihash%253A9c4ffe4815b5755d2609be21ba53c9157e8f71137f06fe35044406b968b80320) |
| Signature         | Super Micro Computer, Inc., VeriSign Class 3 Code Signing 2010 CA, VeriSign   |
| Company           | Super Micro Computer, Inc. |
| Description       | superbmc |
| Product           | superbmc |
| OriginalFilename  | superbmc.sys |


#### Imports
{{< details "Expand" >}}
* ntoskrnl.exe
* HAL.dll

{{< /details >}}
#### ImportedFunctions
{{< details "Expand" >}}
* KeClearEvent
* IoCreateNotificationEvent
* IoRegisterShutdownNotification
* PsCreateSystemThread
* IoDeleteDevice
* IoCreateSymbolicLink
* KeInitializeDpc
* KeInitializeTimer
* KeInitializeSemaphore
* IoCreateDevice
* RtlAppendUnicodeToString
* ExAllocatePool
* RtlInitUnicodeString
* IoDeleteSymbolicLink
* ZwClose
* IoUnregisterShutdownNotification
* ObfDereferenceObject
* KeWaitForSingleObject
* IoAllocateErrorLogEntry
* ObReferenceObjectByHandle
* IofCompleteRequest
* ExInterlockedInsertTailList
* ZwUnmapViewOfSection
* KeResetEvent
* ExInterlockedRemoveHeadList
* PsTerminateSystemThread
* KeSetPriorityThread
* KeSetTimer
* KeCancelTimer
* KeDelayExecutionThread
* ExSetTimerResolution
* KeInitializeEvent
* KeSetEvent
* ZwMapViewOfSection
* ZwOpenSection
* KeBugCheckEx
* KeReleaseSemaphore
* ExFreePoolWithTag
* HalTranslateBusAddress

{{< /details >}}
#### ExportedFunctions
{{< details "Expand" >}}

{{< /details >}}
-----



[*source*](https://github.com/magicsword-io/LOLDrivers/tree/main/yaml/superbmc.yaml)

*last_updated:* 2023-04-27








{{< /column >}}
{{< /block >}}
