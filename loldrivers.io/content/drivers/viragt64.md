+++

description = ""
title = "viragt64.sys"
weight = 10

+++


{{< block "grid-1" >}}
{{< column "mt-2 pt-1">}}


# viragt64.sys ![:inline](/images/twitter_verified.png) 


### Description

viragt64.sys is a vulnerable driver and more information will be added as found.

- **Created**: 2023-01-09
- **Author**: Michael Haag
- **Acknowledgement**:  | [](https://twitter.com/)


{{< button "https://github.com/magicsword-io/LOLDrivers/raw/main/drivers/0ae30291c6cbfa7be39320badd6e8de0.bin" "Download" >}}

{{< tip "warning" >}}
This download link contains the malcious driver!
{{< /tip >}}

### Commands

```
sc.exe create viragt64.sys binPath=C:\windows\temp\viragt64.sys type=kernel &amp;&amp; sc.exe start viragt64.sys
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

| Filename | viragt64.sys |
|:---- | ---- | 
| MD5 | <a href="https://www.virustotal.com/gui/file/43830326cd5fae66f5508e27cbec39a0">43830326cd5fae66f5508e27cbec39a0</a> |
| SHA1 | <a href="https://www.virustotal.com/gui/file/05c0c49e8bcf11b883d41441ce87a2ee7a3aba1d">05c0c49e8bcf11b883d41441ce87a2ee7a3aba1d</a> |
| SHA256 | <a href="https://www.virustotal.com/gui/file/58a74dceb2022cd8a358b92acd1b48a5e01c524c3b0195d7033e4bd55eff4495">58a74dceb2022cd8a358b92acd1b48a5e01c524c3b0195d7033e4bd55eff4495</a> |
| Authentihash MD5 | <a href="https://www.virustotal.com/gui/search/authentihash%68a2f77cfa5aec4556b4276852be637f">68a2f77cfa5aec4556b4276852be637f</a> || Authentihash SHA1 | <a href="https://www.virustotal.com/gui/search/authentihash%0188096c79f0cdde9233e52d4117c0f53e667e3d">0188096c79f0cdde9233e52d4117c0f53e667e3d</a> || Authentihash SHA256 | <a href="https://www.virustotal.com/gui/search/authentihash%54e969dc477af9a3e5b53dc4edaebc41a7b73c87ecca13dc1fbb8dfc86c0fd78">54e969dc477af9a3e5b53dc4edaebc41a7b73c87ecca13dc1fbb8dfc86c0fd78</a> || Signature | TG Soft S.a.s. Di Tonello Gianfranco e C., VeriSign Class 3 Code Signing 2010 CA, VeriSign   || Company | TG Soft S.a.s. || Description | VirIT Agent System || Product | VirIT Agent System || OriginalFilename | viragt64.sys |
#### Imports
{{< details "Expand" >}}* ntoskrnl.exe
* HAL.dll
{{< /details >}}
#### ImportedFunctions
{{< details "Expand" >}}* mbstowcs
* ExAllocatePoolWithTag
* KeSetTargetProcessorDpc
* ZwCreateKey
* IoDeleteSymbolicLink
* ExFreePoolWithTag
* KeInitializeMutex
* RtlAnsiStringToUnicodeString
* ZwReadFile
* strstr
* RtlInitUnicodeString
* IoDeleteDevice
* RtlInitAnsiString
* ZwSetValueKey
* _strupr
* KeInitializeDpc
* ZwQuerySystemInformation
* MmBuildMdlForNonPagedPool
* IoFreeMdl
* ZwSetInformationFile
* KeReleaseMutex
* KeDelayExecutionThread
* ZwCreateFile
* PsCreateSystemThread
* MmMapLockedPagesSpecifyCache
* ExSystemTimeToLocalTime
* ZwQueryValueKey
* PsTerminateSystemThread
* KeInsertQueueDpc
* ZwEnumerateValueKey
* ZwClose
* sprintf
* ObReferenceObjectByHandle
* KeWaitForSingleObject
* RtlTimeToTimeFields
* MmProbeAndLockPages
* ZwOpenProcess
* MmUnlockPages
* IoCreateSymbolicLink
* MmIsAddressValid
* ObfDereferenceObject
* IoCreateDevice
* ZwTerminateProcess
* KeNumberProcessors
* ZwQueryInformationFile
* MmIsNonPagedSystemAddressValid
* ZwWriteFile
* ZwDeleteKey
* RtlFormatCurrentUserKeyPath
* ZwEnumerateKey
* IoAllocateMdl
* ZwOpenKey
* ObOpenObjectByName
* swprintf
* RtlUnicodeStringToAnsiString
* ZwOpenDirectoryObject
* IoFileObjectType
* IoDriverObjectType
* ZwQueryDirectoryObject
* wcstombs
* KeQueryActiveProcessors
* KeBugCheckEx
* IofCompleteRequest
* ExQueueWorkItem
* __C_specific_handler
* __chkstk
* KeStallExecutionProcessor
{{< /details >}}
#### ExportedFunctions
{{< details "Expand" >}}{{< /details >}}



[*source*](https://github.com/magicsword-io/LOLDrivers/tree/main/yaml/viragt64.yaml)

*last_updated:* 2023-04-15








{{< /column >}}
{{< /block >}}
