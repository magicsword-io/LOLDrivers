+++

description = ""
title = "Lv561av.sys"
weight = 10

+++


{{< block "grid-1" >}}
{{< column "mt-2 pt-1">}}


# Lv561av.sys 


{{< tip "warning" >}}
We were not able to verify the hash of this driver successfully, it has not been confirmed.
{{< /tip >}}


### Description

Lv561av.sys is a vulnerable driver and more information will be added as found.

- **Created**: 2023-01-09
- **Author**: Michael Haag
- **Acknowledgement**:  | [](https://twitter.com/)

{{< button "https://github.com/magicsword-io/LOLDrivers/raw/main/drivers/b47dee29b5e6e1939567a926c7a3e6a4.bin" "Download" >}}
{{< tip "warning" >}}
This download link contains the vulnerable driver!

{{< /tip >}}

### Commands

```
sc.exe create Lv561av.sys binPath=C:\windows\temp\Lv561av.sys type=kernel &amp;&amp; sc.exe start Lv561av.sys
```

| Use Case | Privileges | Operating System | 
|:---- | ---- | ---- |
| Elevate privileges | kernel | Windows 10 |

### Resources
<br>
<li><a href=" https://learn.microsoft.com/en-us/windows/security/threat-protection/windows-defender-application-control/microsoft-recommended-driver-block-rules"> https://learn.microsoft.com/en-us/windows/security/threat-protection/windows-defender-application-control/microsoft-recommended-driver-block-rules</a></li>
<li><a href="https://learn.microsoft.com/en-us/windows/security/threat-protection/windows-defender-application-control/microsoft-recommended-driver-block-rules">https://learn.microsoft.com/en-us/windows/security/threat-protection/windows-defender-application-control/microsoft-recommended-driver-block-rules</a></li>
<br>

### Known Vulnerable Samples

| Property           | Value |
|:-------------------|:------|
| Filename           | Lv561av.sys |
| MD5                | [b47dee29b5e6e1939567a926c7a3e6a4](https://www.virustotal.com/gui/file/b47dee29b5e6e1939567a926c7a3e6a4) |
| SHA1               | [351cbd352b3ec0d5f4f58c84af732a0bf41b4463](https://www.virustotal.com/gui/file/351cbd352b3ec0d5f4f58c84af732a0bf41b4463) |
| SHA256             | [e86cb77de7b6a8025f9a546f6c45d135f471e664963cf70b381bee2dfd0fdef4](https://www.virustotal.com/gui/file/e86cb77de7b6a8025f9a546f6c45d135f471e664963cf70b381bee2dfd0fdef4) |
| Authentihash MD5   | [92a9fa0ebbb45b600397611e247710b1](https://www.virustotal.com/gui/search/authentihash%253A92a9fa0ebbb45b600397611e247710b1) |
| Authentihash SHA1  | [ed3e97c7290768216c5b3abbd4a29dde856eb3c7](https://www.virustotal.com/gui/search/authentihash%253Aed3e97c7290768216c5b3abbd4a29dde856eb3c7) |
| Authentihash SHA256| [c54ffa9a32cd99972ca905dcf99e20f8429e3cfd45bc1ddf4f9af8b3ed688c88](https://www.virustotal.com/gui/search/authentihash%253Ac54ffa9a32cd99972ca905dcf99e20f8429e3cfd45bc1ddf4f9af8b3ed688c88) |
| Signature         | Logitech Inc, VeriSign Class 3 Code Signing 2004 CA, VeriSign Class 3 Public Primary CA   |
| Company           | Logitech Inc. |
| Description       | Logitech Video Driver |
| Product           | Logitech Webcam Software |
| OriginalFilename  | Lv561av.sys |


#### Imports
{{< details "Expand" >}}
* NTOSKRNL.exe
* ntoskrnl.exe
* HAL.DLL
* USBD.SYS
* ks.sys

{{< /details >}}
#### ImportedFunctions
{{< details "Expand" >}}
* KeWaitForSingleObject
* IoBuildSynchronousFsdRequest
* ZwWriteFile
* ExFreePool
* RtlQueryRegistryValues
* RtlInitAnsiString
* RtlCompareMemory
* ExAllocatePoolWithTag
* KeReleaseMutex
* ZwClose
* KeDelayExecutionThread
* DbgPrint
* RtlFreeUnicodeString
* ObfDereferenceObject
* ZwCreateFile
* KeSetPriorityThread
* ObReferenceObjectByHandle
* RtlInitUnicodeString
* PsCreateSystemThread
* KeSetEvent
* KeResetEvent
* RtlWriteRegistryValue
* KeInitializeMutex
* swprintf
* RtlAnsiStringToUnicodeString
* KeInitializeEvent
* sprintf
* PsTerminateSystemThread
* IoIsWdmVersionAvailable
* RtlUnicodeStringToInteger
* IoOpenDeviceRegistryKey
* ZwQueryValueKey
* ExDeleteNPagedLookasideList
* KeAcquireSpinLockRaiseToDpc
* vsprintf
* ExInitializeNPagedLookasideList
* ExpInterlockedPushEntrySList
* KeReleaseSpinLock
* ExpInterlockedPopEntrySList
* ExDeletePagedLookasideList
* DbgBreakPoint
* ExQueryDepthSList
* ExInitializePagedLookasideList
* ZwOpenKey
* ZwCreateKey
* ZwSetValueKey
* KeBugCheckEx
* ExAllocatePool
* IoAllocateWorkItem
* IoQueueWorkItem
* IoFreeWorkItem
* IoAllocateDriverObjectExtension
* IoGetDriverObjectExtension
* ExInterlockedInsertTailList
* ExInterlockedRemoveHeadList
* IoAllocateIrp
* IoReleaseRemoveLockEx
* IoInitializeRemoveLockEx
* KeInitializeTimerEx
* KeInitializeDpc
* KeCancelTimer
* IoAcquireRemoveLockEx
* IoReleaseRemoveLockAndWaitEx
* KeSetTimerEx
* IoFreeIrp
* IoReleaseCancelSpinLock
* IoAcquireCancelSpinLock
* IoGetAttachedDeviceReference
* KeInitializeSemaphore
* IoCancelIrp
* KeReleaseSemaphore
* KeSetTimer
* KeAcquireSpinLockAtDpcLevel
* KeReleaseSpinLockFromDpcLevel
* IofCompleteRequest
* IoInitializeIrp
* IofCallDriver
* ExInterlockedInsertHeadList
* _snwprintf
* IoCreateSynchronizationEvent
* ObReferenceObjectByPointer
* ExEventObjectType
* KeClearEvent
* RtlGUIDFromString
* IoBuildDeviceIoControlRequest
* IoGetDeviceInterfaces
* wcsrchr
* RtlCompareUnicodeString
* IoGetDeviceObjectPointer
* PoRequestPowerIrp
* KeWaitForMultipleObjects
* __C_specific_handler
* PsGetCurrentProcessId
* KeQueryPerformanceCounter
* USBD_ParseConfigurationDescriptorEx
* USBD_CreateConfigurationRequestEx
* KsGenerateEvents
* KsGetNextSibling
* KsGetFirstChild
* KsInitializeDriver
* KsGetDeviceForDeviceObject
* KsGetPinFromIrp
* KsGetObjectFromFileObject
* KsCreateFilterFactory
* KsRemoveItemFromObjectBag
* _KsEdit
* KsGetFilterFromIrp
* KsAddItemToObjectBag
* KsGetDevice
* KsStreamPointerSetStatusCode
* KsPinGetReferenceClockInterface
* KsPinAttemptProcessing
* KsPinGetLeadingEdgeStreamPointer
* KsStreamPointerGetIrp
* KsStreamPointerClone
* KsStreamPointerUnlock
* KsStreamPointerDelete
* KsStreamPointerAdvance
* KsDefaultAddEventHandler

{{< /details >}}
#### ExportedFunctions
{{< details "Expand" >}}

{{< /details >}}
-----



[*source*](https://github.com/magicsword-io/LOLDrivers/tree/main/yaml/lv561av.yaml)

*last_updated:* 2023-04-22








{{< /column >}}
{{< /block >}}
