+++

description = ""
title = "libnicm.sys"
weight = 10

+++


{{< block "grid-1" >}}
{{< column "mt-2 pt-1">}}


# libnicm.sys ![:inline](/images/twitter_verified.png) 


### Description

libnicm.sys is a vulnerable driver and more information will be added as found.

- **Created**: 2023-01-09
- **Author**: Michael Haag
- **Acknowledgement**:  | [](https://twitter.com/)

{{< button "https://github.com/magicsword-io/LOLDrivers/raw/main/drivers/c1fce7aac4e9dd7a730997e2979fa1e2.bin" "Download" >}}
{{< tip "warning" >}}
This download link contains the vulnerable driver!

{{< /tip >}}

### Commands

```
sc.exe create libnicm.sys binPath=C:\windows\temp\libnicm.sys type=kernel &amp;&amp; sc.exe start libnicm.sys
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

| Property           | Value |
|:-------------------|:------|
| Filename           | libnicm.sys |
| MD5                | [c1fce7aac4e9dd7a730997e2979fa1e2](https://www.virustotal.com/gui/file/c1fce7aac4e9dd7a730997e2979fa1e2) |
| SHA1               | [25d812a5ece19ea375178ef9d60415841087726e](https://www.virustotal.com/gui/file/25d812a5ece19ea375178ef9d60415841087726e) |
| SHA256             | [95d50c69cdbf10c9c9d61e64fe864ac91e6f6caa637d128eb20e1d3510e776d3](https://www.virustotal.com/gui/file/95d50c69cdbf10c9c9d61e64fe864ac91e6f6caa637d128eb20e1d3510e776d3) |
| Authentihash MD5   | [f4c87edbb9a270058e01fdc58f29692a](https://www.virustotal.com/gui/search/authentihash%253Af4c87edbb9a270058e01fdc58f29692a) |
| Authentihash SHA1  | [e82346880e59a3d7652896128eb91512f5ee3d53](https://www.virustotal.com/gui/search/authentihash%253Ae82346880e59a3d7652896128eb91512f5ee3d53) |
| Authentihash SHA256| [bd1d579a15ec3c1120cc6e0c8ff6b265623980de3570a5dd2f57d0c5981334d8](https://www.virustotal.com/gui/search/authentihash%253Abd1d579a15ec3c1120cc6e0c8ff6b265623980de3570a5dd2f57d0c5981334d8) |
| Signature         | Microsoft Windows Hardware Compatibility Publisher, Microsoft Windows Third Party Component CA 2014, Microsoft Root Certificate Authority 2010   |
| Company           | Micro Focus |
| Description       | XTier COM Services Driver |
| Product           | Micro Focus XTier |
| OriginalFilename  | libnicm.sys |


#### Imports
{{< details "Expand" >}}
* ntoskrnl.exe

{{< /details >}}
#### ImportedFunctions
{{< details "Expand" >}}
* ExAcquireResourceExclusiveLite
* ExAllocatePoolWithTag
* ExFreePoolWithTag
* strstr
* RtlInitAnsiString
* ExAcquireResourceSharedLite
* ExReleaseResourceLite
* RtlEqualString
* MmUnmapLockedPages
* ProbeForRead
* IoDeleteSymbolicLink
* IoRegisterShutdownNotification
* KeInitializeMutex
* KeLeaveCriticalRegion
* IoDeleteDevice
* ProbeForWrite
* IoFreeMdl
* KeEnterCriticalRegion
* KeReleaseMutex
* ZwCreateFile
* MmMapLockedPagesSpecifyCache
* IoUnregisterShutdownNotification
* ZwClose
* IofCompleteRequest
* IoSetTopLevelIrp
* KeWaitForSingleObject
* MmProbeAndLockPages
* MmUnlockPages
* ExDeleteResourceLite
* IoGetTopLevelIrp
* IoCreateSymbolicLink
* IoCreateDevice
* ExInitializeResourceLite
* NtSetSecurityObject
* DbgPrintEx
* DbgPrint
* IoAllocateMdl
* RtlCreateSecurityDescriptor
* IoGetCurrentProcess
* ZwCreateKey
* RtlAnsiStringToUnicodeString
* ZwReadFile
* RtlInitUnicodeString
* RtlAppendUnicodeToString
* RtlUnicodeStringToAnsiString
* ZwSetValueKey
* ZwQuerySystemInformation
* RtlInitString
* KeDelayExecutionThread
* RtlFreeUnicodeString
* ZwWaitForSingleObject
* ZwQueryValueKey
* ZwQueryDirectoryFile
* RtlAppendUnicodeStringToString
* RtlCopyString
* MmIsAddressValid
* ZwOpenFile
* ZwQueryInformationFile
* ZwLoadDriver
* ZwOpenKey
* KeBugCheckEx
* __C_specific_handler

{{< /details >}}
#### ExportedFunctions
{{< details "Expand" >}}
* NicmCreateInstance
* NicmDeregisterClassFactory
* NicmGetVersion
* NicmRegisterClassFactory
* XTComCreateInstance
* XTComDeregisterClassFactory
* XTComFreeUnusedLibrariesEx
* XTComGetClassObject
* XTComGetVersion
* XTComInitialize
* XTComRegisterClassFactory

{{< /details >}}
-----



[*source*](https://github.com/magicsword-io/LOLDrivers/tree/main/yaml/libnicm.yaml)

*last_updated:* 2023-04-26








{{< /column >}}
{{< /block >}}
