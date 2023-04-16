+++

description = ""
title = "AMDPowerProfiler.sys"
weight = 10

+++


{{< block "grid-1" >}}
{{< column "mt-2 pt-1">}}


# AMDPowerProfiler.sys ![:inline](/images/twitter_verified.png) 


### Description

AMDPowerProfiler.sys is a vulnerable driver and more information will be added as found.

- **Created**: 2023-01-09
- **Author**: Michael Haag
- **Acknowledgement**:  | [](https://twitter.com/)


{{< button "https://github.com/magicsword-io/LOLDrivers/raw/main/drivers/0ae30291c6cbfa7be39320badd6e8de0.bin" "Download" >}}

{{< tip "warning" >}}
This download link contains the malcious driver!
{{< /tip >}}

### Commands

```
sc.exe create AMDPowerProfiler.sys binPath=C:\windows\temp\AMDPowerProfiler.sys     type=kernel type=kernel &amp;&amp; sc.exe start AMDPowerProfiler.sys
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

| Filename | AMDPowerProfiler.sys |
|:---- | ---- | 
| MD5 | <a href="https://www.virustotal.com/gui/file/e4266262a77fffdea2584283f6c4f51d">e4266262a77fffdea2584283f6c4f51d</a> |
| SHA1 | <a href="https://www.virustotal.com/gui/file/b480c54391a2a2f917a44f91a5e9e4590648b332">b480c54391a2a2f917a44f91a5e9e4590648b332</a> |
| SHA256 | <a href="https://www.virustotal.com/gui/file/0af5ccb3d33a9ba92071c9637be6254030d61998733a5eb3583e865e17844e05">0af5ccb3d33a9ba92071c9637be6254030d61998733a5eb3583e865e17844e05</a> |
| Authentihash MD5 | <a href="https://www.virustotal.com/gui/search/authentihash%7ed9c787e267b2606441010b65767771">7ed9c787e267b2606441010b65767771</a> || Authentihash SHA1 | <a href="https://www.virustotal.com/gui/search/authentihash%07a5aac8abb0a85822bf792607b9e90914b454dc">07a5aac8abb0a85822bf792607b9e90914b454dc</a> || Authentihash SHA256 | <a href="https://www.virustotal.com/gui/search/authentihash%e1d3963c55c7ffa96d16e47ec4bbb4e171f828650ce853eb0b83c90ae9c6265a">e1d3963c55c7ffa96d16e47ec4bbb4e171f828650ce853eb0b83c90ae9c6265a</a> || Signature | Advanced Micro Devices Inc., Sectigo RSA Code Signing CA, USERTrust RSA Certification Authority, Sectigo (AAA)   || Company | Advanced Micro Devices, Inc. || Description | AMD Power Profiling Driver || Product | AMD uProf || OriginalFilename | AMDPowerProfiler.sys |
#### Imports
{{< details "Expand" >}}* AMDPCore.SYS
* ntoskrnl.exe
* HAL.dll
{{< /details >}}
#### ImportedFunctions
{{< details "Expand" >}}* PcoreRemoveAllConfigurations
* PcoreIsLoaded
* PcoreAddConfiguration
* PcoreUnregister
* PcoreVersion
* PcoreRegister
* PcoreGetResourceCount
* KeGetProcessorNumberFromIndex
* KeInitializeDpc
* KeSetTargetProcessorDpcEx
* MmMapIoSpace
* MmUnmapIoSpace
* KeQueryActiveGroupCount
* KeSetEvent
* ExAllocatePoolWithTag
* ExFreePoolWithTag
* KeInitializeEvent
* KeWaitForSingleObject
* KeQueryActiveProcessorCountEx
* ExSystemTimeToLocalTime
* KeGetCurrentProcessorNumberEx
* RtlInitUnicodeString
* IoDeleteDevice
* IoDeleteSymbolicLink
* RtlGetVersion
* IofCompleteRequest
* IoCreateSymbolicLink
* MmUnlockPages
* PsRemoveLoadImageNotifyRoutine
* ZwOpenSection
* ZwUnmapViewOfSection
* MmProbeAndLockPages
* PsSetLoadImageNotifyRoutine
* ObfDereferenceObject
* IoAllocateMdl
* PsRemoveCreateThreadNotifyRoutine
* ZwMapViewOfSection
* ObReferenceObjectByHandle
* IoFreeMdl
* MmIsAddressValid
* PsSetCreateThreadNotifyRoutine
* PsSetCreateProcessNotifyRoutine
* ZwClose
* IoSizeofWorkItem
* ZwQueryVolumeInformationFile
* IoQueryFileDosDeviceName
* IoInitializeWorkItem
* IoQueueWorkItemEx
* ObfReferenceObject
* IoUninitializeWorkItem
* ZwOpenFile
* IoIs32bitProcess
* MmGetSystemRoutineAddress
* ZwSetSecurityObject
* IoDeviceObjectType
* IoCreateDevice
* ObOpenObjectByPointer
* RtlGetDaclSecurityDescriptor
* RtlGetGroupSecurityDescriptor
* RtlGetOwnerSecurityDescriptor
* RtlGetSaclSecurityDescriptor
* SeCaptureSecurityDescriptor
* _snwprintf
* RtlLengthSecurityDescriptor
* SeExports
* RtlCreateSecurityDescriptor
* _wcsnicmp
* wcschr
* RtlAbsoluteToSelfRelativeSD
* RtlAddAccessAllowedAce
* RtlLengthSid
* IoIsWdmVersionAvailable
* RtlSetDaclSecurityDescriptor
* ZwOpenKey
* ZwSetValueKey
* ZwQueryValueKey
* ZwCreateKey
* RtlFreeUnicodeString
* KeBugCheckEx
* KeInsertQueueDpc
* KeSetImportanceDpc
* DbgPrint
* MmMapLockedPagesSpecifyCache
* RtlIsNtDdiVersionAvailable
* ZwCreateFile
* ZwWriteFile
* __C_specific_handler
* strcmp
* KeQueryPerformanceCounter
* HalAllocateHardwareCounters
* HalFreeHardwareCounters
{{< /details >}}
#### ExportedFunctions
{{< details "Expand" >}}{{< /details >}}



[*source*](https://github.com/magicsword-io/LOLDrivers/tree/main/yaml/amdpowerprofiler.yaml)

*last_updated:* 2023-04-15








{{< /column >}}
{{< /block >}}
