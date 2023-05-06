+++

description = ""
title = "LgDCatcher.sys"
weight = 10

+++


{{< block "grid-1" >}}
{{< column "mt-2 pt-1">}}


# LgDCatcher.sys 


{{< tip "warning" >}}
We were not able to verify the hash of this driver successfully, it has not been confirmed.
{{< /tip >}}


### Description

LgDCatcher.sys is a vulnerable driver and more information will be added as found.

- **Created**: 2023-01-09
- **Author**: Michael Haag
- **Acknowledgement**:  | [](https://twitter.com/)

{{< button "https://github.com/magicsword-io/LOLDrivers/raw/main/drivers/ed6348707f177629739df73b97ba1b6e.bin" "Download" >}}
{{< tip "warning" >}}
This download link contains the vulnerable driver!

{{< /tip >}}

### Commands

```
sc.exe create LgDCatcher.sys binPath=C:\windows\temp\LgDCatcher.sys type=kernel &amp;&amp; sc.exe start LgDCatcher.sys
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
| Filename           | LgDCatcher.sys |
| MD5                | [ed6348707f177629739df73b97ba1b6e](https://www.virustotal.com/gui/file/ed6348707f177629739df73b97ba1b6e) |
| SHA1               | [806832983bb8cb1e26001e60ea3b7c3ade4d3471](https://www.virustotal.com/gui/file/806832983bb8cb1e26001e60ea3b7c3ade4d3471) |
| SHA256             | [58c071cfe72e9ee867bba85cbd0abe72eb223d27978d6f0650d0103553839b59](https://www.virustotal.com/gui/file/58c071cfe72e9ee867bba85cbd0abe72eb223d27978d6f0650d0103553839b59) |
| Authentihash MD5   | [0011ec462e11bd6288e1dc38def9be06](https://www.virustotal.com/gui/search/authentihash%253A0011ec462e11bd6288e1dc38def9be06) |
| Authentihash SHA1  | [c6f2e631f12737a5fa96db2e18c8ebf950d64eb6](https://www.virustotal.com/gui/search/authentihash%253Ac6f2e631f12737a5fa96db2e18c8ebf950d64eb6) |
| Authentihash SHA256| [3ba724dd78864cd527a99673fde1bf7f9f85f2415c91708e7380fbe5e2c085dd](https://www.virustotal.com/gui/search/authentihash%253A3ba724dd78864cd527a99673fde1bf7f9f85f2415c91708e7380fbe5e2c085dd) |
| Signature         | 雷神（武汉）信息技术有限公司, DigiCert SHA2 Assured ID Code Signing CA, DigiCert   |


#### Imports
{{< details "Expand" >}}
* ntoskrnl.exe
* fwpkclnt.sys
* NDIS.SYS
* WDFLDR.SYS

{{< /details >}}
#### ImportedFunctions
{{< details "Expand" >}}
* ExpInterlockedPushEntrySList
* ExInitializeNPagedLookasideList
* ExDeleteNPagedLookasideList
* MmBuildMdlForNonPagedPool
* MmMapLockedPagesSpecifyCache
* MmUnmapLockedPages
* MmAllocatePagesForMdl
* MmFreePagesFromMdl
* PsCreateSystemThread
* PsTerminateSystemThread
* IoAllocateMdl
* IofCompleteRequest
* IoCreateDevice
* IoCreateSymbolicLink
* IoDeleteDevice
* IoDeleteSymbolicLink
* IoFreeMdl
* IoReleaseCancelSpinLock
* ObReferenceObjectByHandle
* ExpInterlockedPopEntrySList
* ZwClose
* ZwOpenKey
* ZwQueryValueKey
* PsGetCurrentProcessId
* ZwSetInformationThread
* RtlLengthSid
* RtlCreateAcl
* RtlAddAccessAllowedAce
* PsLookupProcessByProcessId
* ObOpenObjectByPointer
* ZwSetSecurityObject
* __C_specific_handler
* SeExports
* RtlGetVersion
* _stricmp
* ExAllocatePool
* ZwQuerySystemInformation
* RtlValidSid
* KeGetCurrentIrql
* KeWaitForSingleObject
* ExFreePoolWithTag
* ExQueryDepthSList
* KeSetEvent
* KeInitializeEvent
* RtlSetDaclSecurityDescriptor
* RtlCreateSecurityDescriptor
* RtlAppendUnicodeToString
* MmGetSystemRoutineAddress
* RtlInitUnicodeString
* swprintf_s
* ExUuidCreate
* ExAllocatePoolWithTag
* RtlCopyUnicodeString
* KeReleaseInStackQueuedSpinLock
* KeAcquireInStackQueuedSpinLock
* ObfDereferenceObject
* RtlCompareMemory
* FwpsFreeNetBufferList0
* NdisInitializeEvent
* NdisAdvanceNetBufferDataStart
* NdisGetDataBuffer
* NdisAllocateGenericObject
* NdisFreeNetBufferListPool
* NdisAllocateNetBufferListPool
* NdisWaitEvent
* NdisFreeGenericObject
* NdisRetreatNetBufferDataStart
* WdfVersionUnbind
* WdfVersionBind
* WdfVersionBindClass
* WdfVersionUnbindClass

{{< /details >}}
#### ExportedFunctions
{{< details "Expand" >}}

{{< /details >}}
-----



[*source*](https://github.com/magicsword-io/LOLDrivers/tree/main/yaml/lgdcatcher.yaml)

*last_updated:* 2023-05-06








{{< /column >}}
{{< /block >}}
