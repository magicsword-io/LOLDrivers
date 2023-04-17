+++

description = ""
title = "vboxdrv.sys"
weight = 10

+++


{{< block "grid-1" >}}
{{< column "mt-2 pt-1">}}


# vboxdrv.sys ![:inline](/images/twitter_verified.png) 


### Description

Used by unknown actor in Acid Rain malware. vboxdrv.sys is a vulnerable driver.

- **Created**: 2023-01-09
- **Author**: Michael Haag
- **Acknowledgement**:  | [](https://twitter.com/)

{{< button "https://github.com/magicsword-io/LOLDrivers/raw/main/drivers/bce7f34912ff59a3926216b206deb09f.bin" "Download" >}}
{{< tip "warning" >}}
This download link contains the malcious driver!
{{< /tip >}}

### Commands

```
sc.exe create vboxdrv.sys binPath=C:\windows\temp\vboxdrv.sys type=kernel &amp;&amp; sc.exe start vboxdrv.sys
```

| Use Case | Privileges | Operating System | 
|:---- | ---- | ---- |
| Elevate privileges | kernel | Windows 10 |

### Resources
<br>
<li><a href="https://unit42.paloaltonetworks.com/acidbox-rare-malware/">https://unit42.paloaltonetworks.com/acidbox-rare-malware/</a></li>
<li><a href="https://www.coresecurity.com/core-labs/advisories/virtualbox-privilege-escalation-vulnerability">https://www.coresecurity.com/core-labs/advisories/virtualbox-privilege-escalation-vulnerability</a></li>
<li><a href="https://unit42.paloaltonetworks.com/acidbox-rare-malware/">https://unit42.paloaltonetworks.com/acidbox-rare-malware/</a></li>
<br>

### Known Vulnerable Samples

| Filename | vboxdrv.sys |
|:---- | ---- | 
| MD5 | <a href="https://www.virustotal.com/gui/file/bce7f34912ff59a3926216b206deb09f">bce7f34912ff59a3926216b206deb09f</a> |
| SHA1 | <a href="https://www.virustotal.com/gui/file/696d68bdbe1d684029aaad2861c49af56694473a">696d68bdbe1d684029aaad2861c49af56694473a</a> |
| SHA256 | <a href="https://www.virustotal.com/gui/file/78827fa00ea48d96ac9af8d1c1e317d02ce11793e7f7f6e4c7aac7b5d7dd490f">78827fa00ea48d96ac9af8d1c1e317d02ce11793e7f7f6e4c7aac7b5d7dd490f</a> |
| Authentihash MD5 | <a href="https://www.virustotal.com/gui/search/authentihash%253A368a4f14c62575191a0f1f3464513964">368a4f14c62575191a0f1f3464513964</a> || Authentihash SHA1 | <a href="https://www.virustotal.com/gui/search/authentihash%253A3ce88266cfc41e8980d4c185235fd55999f5a67a">3ce88266cfc41e8980d4c185235fd55999f5a67a</a> || Authentihash SHA256 | <a href="https://www.virustotal.com/gui/search/authentihash%253Aa5a2fe8ab935cf47f21e0c5e0de11a98271054109827dc930293b947d3b05079">a5a2fe8ab935cf47f21e0c5e0de11a98271054109827dc930293b947d3b05079</a> || Signature | Sun Microsystems, Inc., VeriSign Class 3 Code Signing 2004 CA, VeriSign Class 3 Public Primary CA   || Company | Sun Microsystems, Inc. || Description | VirtualBox Support Driver || Product | Sun VirtualBox || OriginalFilename | VBoxDrv.sys |
#### Imports
{{< details "Expand" >}}* ntoskrnl.exe
{{< /details >}}
#### ImportedFunctions
{{< details "Expand" >}}* IoDeleteDevice
* IoDeleteSymbolicLink
* RtlInitUnicodeString
* ObfDereferenceObject
* ExUnregisterCallback
* IofCompleteRequest
* DbgPrint
* IoIs32bitProcess
* ExRegisterCallback
* ExCreateCallback
* IoCreateSymbolicLink
* IoCreateDevice
* IoGetStackLimits
* memchr
* strncmp
* KeInitializeEvent
* ExAcquireFastMutex
* ExReleaseFastMutex
* KeSetEvent
* KeWaitForSingleObject
* KeResetEvent
* KeAcquireSpinLockRaiseToDpc
* KeReleaseSpinLock
* KeDelayExecutionThread
* ZwYieldExecution
* ExFreePoolWithTag
* KeInsertQueueDpc
* KeSetTargetProcessorDpc
* KeSetImportanceDpc
* KeInitializeDpc
* ExAllocatePoolWithTag
* KeQueryActiveProcessors
* strchr
* PsGetCurrentProcessId
* IoGetCurrentProcess
* KeSetTimerEx
* KeRemoveQueueDpc
* KeCancelTimer
* KeInitializeTimerEx
* KeQueryTimeIncrement
* MmGetSystemRoutineAddress
* MmFreeContiguousMemory
* MmGetPhysicalAddress
* MmAllocateContiguousMemory
* MmUnmapIoSpace
* MmUnlockPages
* IoFreeMdl
* MmFreePagesFromMdl
* MmUnsecureVirtualMemory
* MmUnmapLockedPages
* MmProtectMdlSystemAddress
* MmBuildMdlForNonPagedPool
* IoAllocateMdl
* MmAllocatePagesForMdl
* __C_specific_handler
* MmSecureVirtualMemory
* MmProbeAndLockPages
* MmMapIoSpace
* MmMapLockedPagesSpecifyCache
{{< /details >}}
#### ExportedFunctions
{{< details "Expand" >}}* AssertMsg1
* AssertMsg2
* RTAssertShouldPanic
* RTErrConvertFromNtStatus
* RTLogCloneRC
* RTLogComPrintf
* RTLogComPrintfV
* RTLogCopyGroupsAndFlags
* RTLogCreate
* RTLogCreateEx
* RTLogCreateExV
* RTLogDefaultInit
* RTLogDefaultInstance
* RTLogDestroy
* RTLogFlags
* RTLogFlush
* RTLogFlushRC
* RTLogFlushToLogger
* RTLogFormatV
* RTLogGetDefaultInstance
* RTLogGroupSettings
* RTLogLogger
* RTLogLoggerEx
* RTLogLoggerExV
* RTLogLoggerV
* RTLogPrintf
* RTLogPrintfV
* RTLogRelDefaultInstance
* RTLogRelLoggerV
* RTLogRelPrintfV
* RTLogRelSetDefaultInstance
* RTLogSetDefaultInstance
* RTLogSetDefaultInstanceThread
* RTLogWriteCom
* RTLogWriteDebugger
* RTLogWriteStdErr
* RTLogWriteStdOut
* RTLogWriteUser
* RTMemAlloc
* RTMemAllocZ
* RTMemContAlloc
* RTMemContFree
* RTMemDup
* RTMemDupEx
* RTMemExecAlloc
* RTMemExecFree
* RTMemFree
* RTMemRealloc
* RTMemTmpAlloc
* RTMemTmpAllocZ
* RTMemTmpFree
* RTMpCpuId
* RTMpCpuIdFromSetIndex
* RTMpCpuIdToSetIndex
* RTMpGetCount
* RTMpGetMaxCpuId
* RTMpGetOnlineCount
* RTMpGetOnlineSet
* RTMpGetSet
* RTMpIsCpuOnline
* RTMpIsCpuPossible
* RTMpIsCpuWorkPending
* RTMpNotificationDeregister
* RTMpNotificationRegister
* RTMpOnAll
* RTMpOnOthers
* RTMpOnSpecific
* RTPowerNotificationDeregister
* RTPowerNotificationRegister
* RTPowerSignalEvent
* RTProcSelf
* RTR0Init
* RTR0MemObjAddress
* RTR0MemObjAddressR3
* RTR0MemObjAllocCont
* RTR0MemObjAllocLow
* RTR0MemObjAllocPage
* RTR0MemObjAllocPhys
* RTR0MemObjAllocPhysNC
* RTR0MemObjEnterPhys
* RTR0MemObjFree
* RTR0MemObjGetPagePhysAddr
* RTR0MemObjIsMapping
* RTR0MemObjLockKernel
* RTR0MemObjLockUser
* RTR0MemObjMapKernel
* RTR0MemObjMapKernelEx
* RTR0MemObjMapUser
* RTR0MemObjReserveKernel
* RTR0MemObjReserveUser
* RTR0MemObjSize
* RTR0ProcHandleSelf
* RTR0Term
* RTSemEventCreate
* RTSemEventDestroy
* RTSemEventMultiCreate
* RTSemEventMultiDestroy
* RTSemEventMultiReset
* RTSemEventMultiSignal
* RTSemEventMultiWait
* RTSemEventMultiWaitNoResume
* RTSemEventSignal
* RTSemEventWait
* RTSemEventWaitNoResume
* RTSemFastMutexCreate
* RTSemFastMutexDestroy
* RTSemFastMutexRelease
* RTSemFastMutexRequest
* RTSpinlockAcquire
* RTSpinlockAcquireNoInts
* RTSpinlockCreate
* RTSpinlockDestroy
* RTSpinlockRelease
* RTSpinlockReleaseNoInts
* RTStrFormat
* RTStrFormatNumber
* RTStrFormatTypeDeregister
* RTStrFormatTypeRegister
* RTStrFormatTypeSetUser
* RTStrFormatV
* RTStrPrintf
* RTStrPrintfEx
* RTStrPrintfExV
* RTStrPrintfV
* RTStrToInt16
* RTStrToInt16Ex
* RTStrToInt16Full
* RTStrToInt32
* RTStrToInt32Ex
* RTStrToInt32Full
* RTStrToInt64
* RTStrToInt64Ex
* RTStrToInt64Full
* RTStrToInt8
* RTStrToInt8Ex
* RTStrToInt8Full
* RTStrToUInt16
* RTStrToUInt16Ex
* RTStrToUInt16Full
* RTStrToUInt32
* RTStrToUInt32Ex
* RTStrToUInt32Full
* RTStrToUInt64
* RTStrToUInt64Ex
* RTStrToUInt64Full
* RTStrToUInt8
* RTStrToUInt8Ex
* RTStrToUInt8Full
* RTThreadNativeSelf
* RTThreadPreemptDisable
* RTThreadPreemptIsEnabled
* RTThreadPreemptRestore
* RTThreadSleep
* RTThreadYield
* RTTimeMilliTS
* RTTimeNanoTS
* RTTimeNow
* RTTimeSystemMilliTS
* RTTimeSystemNanoTS
* RTTimerCreateEx
* RTTimerDestroy
* RTTimerGetSystemGranularity
* RTTimerReleaseSystemGranularity
* RTTimerRequestSystemGranularity
* RTTimerStart
* RTTimerStop
* SUPR0ComponentDeregisterFactory
* SUPR0ComponentQueryFactory
* SUPR0ComponentRegisterFactory
* SUPR0ContAlloc
* SUPR0ContFree
* SUPR0EnableVTx
* SUPR0GetPagingMode
* SUPR0GipMap
* SUPR0GipUnmap
* SUPR0LockMem
* SUPR0LowAlloc
* SUPR0LowFree
* SUPR0MemAlloc
* SUPR0MemFree
* SUPR0MemGetPhys
* SUPR0ObjAddRef
* SUPR0ObjAddRefEx
* SUPR0ObjRegister
* SUPR0ObjRelease
* SUPR0ObjVerifyAccess
* SUPR0PageAlloc
* SUPR0PageAllocEx
* SUPR0PageFree
* SUPR0PageMapKernel
* SUPR0UnlockMem
* g_szRTAssertMsg1
* g_szRTAssertMsg2
{{< /details >}}
| Filename | vboxdrv.sys |
|:---- | ---- | 
| MD5 | <a href="https://www.virustotal.com/gui/file/eaea9ccb40c82af8f3867cd0f4dd5e9d">eaea9ccb40c82af8f3867cd0f4dd5e9d</a> |
| SHA1 | <a href="https://www.virustotal.com/gui/file/7c1b25518dee1e30b5a6eaa1ea8e4a3780c24d0c">7c1b25518dee1e30b5a6eaa1ea8e4a3780c24d0c</a> |
| SHA256 | <a href="https://www.virustotal.com/gui/file/cf3a7d4285d65bf8688215407bce1b51d7c6b22497f09021f0fce31cbeb78986">cf3a7d4285d65bf8688215407bce1b51d7c6b22497f09021f0fce31cbeb78986</a> |
| Authentihash MD5 | <a href="https://www.virustotal.com/gui/search/authentihash%253Ad146876f270e848875465ed081396d3b">d146876f270e848875465ed081396d3b</a> || Authentihash SHA1 | <a href="https://www.virustotal.com/gui/search/authentihash%253Ac54fe31ff5c3cfe1937b7b0906882a1786f453b6">c54fe31ff5c3cfe1937b7b0906882a1786f453b6</a> || Authentihash SHA256 | <a href="https://www.virustotal.com/gui/search/authentihash%253A597e7d5feb149d9087888926d1454dc06f1078ab18c948b44f090910da8645f8">597e7d5feb149d9087888926d1454dc06f1078ab18c948b44f090910da8645f8</a> || Signature | innotek GmbH, GlobalSign ObjectSign CA, GlobalSign Primary Object Publishing CA, GlobalSign Root CA - R1   |
#### Imports
{{< details "Expand" >}}* ntoskrnl.exe
{{< /details >}}
#### ImportedFunctions
{{< details "Expand" >}}* IofCompleteRequest
* DbgPrint
* IoIs32bitProcess
* MmFreeContiguousMemory
* IoFreeMdl
* MmGetSystemRoutineAddress
* RtlInitUnicodeString
* KeCancelTimer
* KeInsertQueueDpc
* __C_specific_handler
* MmMapLockedPagesSpecifyCache
* MmUnmapLockedPages
* KeSetTimerEx
* ExSetTimerResolution
* IoDeleteDevice
* IoDeleteSymbolicLink
* KeSetTargetProcessorDpc
* KeSetImportanceDpc
* KeInitializeDpc
* KeInitializeTimerEx
* MmGetPhysicalAddress
* KeQueryActiveProcessors
* MmBuildMdlForNonPagedPool
* IoAllocateMdl
* MmAllocateContiguousMemory
* IoCreateSymbolicLink
* IoCreateDevice
* memchr
* strncmp
* PsGetCurrentProcessId
* IoGetCurrentProcess
* ExFreePoolWithTag
* ExAllocatePoolWithTag
* KeDelayExecutionThread
* ZwYieldExecution
* KeAcquireSpinLockRaiseToDpc
* KeReleaseSpinLock
* KeInitializeEvent
* KeSetEvent
* KeResetEvent
* KeWaitForSingleObject
* ExAcquireFastMutex
* ExReleaseFastMutex
* MmUnmapIoSpace
* MmUnlockPages
* MmFreePagesFromMdl
* MmUnsecureVirtualMemory
* MmProtectMdlSystemAddress
* MmAllocatePagesForMdl
* MmSecureVirtualMemory
* MmProbeAndLockPages
* MmMapIoSpace
{{< /details >}}
#### ExportedFunctions
{{< details "Expand" >}}* AssertMsg1
* RTAssertDoBreakpoint
* RTErrConvertFromNtStatus
* RTLogDefaultInstance
* RTLogLogger
* RTLogLoggerEx
* RTLogLoggerExV
* RTLogPrintf
* RTLogPrintfV
* RTLogRelDefaultInstance
* RTLogSetDefaultInstanceThread
* RTMemAlloc
* RTMemAllocZ
* RTMemContAlloc
* RTMemContFree
* RTMemExecAlloc
* RTMemExecFree
* RTMemFree
* RTMemRealloc
* RTMemTmpAlloc
* RTMemTmpAllocZ
* RTMemTmpFree
* RTMpCpuId
* RTMpCpuIdFromSetIndex
* RTMpCpuIdToSetIndex
* RTMpDoesCpuExist
* RTMpGetCount
* RTMpGetMaxCpuId
* RTMpGetOnlineCount
* RTMpGetOnlineSet
* RTMpGetSet
* RTMpIsCpuOnline
* RTMpOnAll
* RTMpOnOthers
* RTMpOnSpecific
* RTProcSelf
* RTR0MemObjAddress
* RTR0MemObjAddressR3
* RTR0MemObjAllocCont
* RTR0MemObjAllocLow
* RTR0MemObjAllocPage
* RTR0MemObjAllocPhys
* RTR0MemObjAllocPhysNC
* RTR0MemObjEnterPhys
* RTR0MemObjFree
* RTR0MemObjGetPagePhysAddr
* RTR0MemObjIsMapping
* RTR0MemObjLockKernel
* RTR0MemObjLockUser
* RTR0MemObjMapKernel
* RTR0MemObjMapUser
* RTR0MemObjReserveKernel
* RTR0MemObjReserveUser
* RTR0MemObjSize
* RTR0ProcHandleSelf
* RTSemEventCreate
* RTSemEventDestroy
* RTSemEventMultiCreate
* RTSemEventMultiDestroy
* RTSemEventMultiReset
* RTSemEventMultiSignal
* RTSemEventMultiWait
* RTSemEventMultiWaitNoResume
* RTSemEventSignal
* RTSemEventWait
* RTSemEventWaitNoResume
* RTSemFastMutexCreate
* RTSemFastMutexDestroy
* RTSemFastMutexRelease
* RTSemFastMutexRequest
* RTSpinlockAcquire
* RTSpinlockAcquireNoInts
* RTSpinlockCreate
* RTSpinlockDestroy
* RTSpinlockRelease
* RTSpinlockReleaseNoInts
* RTThreadNativeSelf
* RTThreadSleep
* RTThreadYield
* SUPR0ContAlloc
* SUPR0ContFree
* SUPR0GipMap
* SUPR0GipUnmap
* SUPR0LockMem
* SUPR0LowAlloc
* SUPR0LowFree
* SUPR0MemAlloc
* SUPR0MemFree
* SUPR0MemGetPhys
* SUPR0ObjAddRef
* SUPR0ObjRegister
* SUPR0ObjRelease
* SUPR0ObjVerifyAccess
* SUPR0PageAlloc
* SUPR0PageFree
* SUPR0UnlockMem
{{< /details >}}



[*source*](https://github.com/magicsword-io/LOLDrivers/tree/main/yaml/vboxdrv.yaml)

*last_updated:* 2023-04-17








{{< /column >}}
{{< /block >}}
