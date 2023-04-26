+++

description = ""
title = "AsrDrv106.sys"
weight = 10

+++


{{< block "grid-1" >}}
{{< column "mt-2 pt-1">}}


# AsrDrv106.sys ![:inline](/images/twitter_verified.png) 


### Description

AsrDrv106.sys is a vulnerable driver and more information will be added as found.

- **Created**: 2023-01-09
- **Author**: Michael Haag
- **Acknowledgement**:  | [](https://twitter.com/)

{{< button "https://github.com/magicsword-io/LOLDrivers/raw/main/drivers/12908c285b9d68ee1f39186110df0f1e.bin" "Download" >}}
{{< tip "warning" >}}
This download link contains the vulnerable driver!

{{< /tip >}}

### Commands

```
sc.exe create AsrDrv106.sys binPath=C:\windows\temp\AsrDrv106.sys type=kernel &amp;&amp; sc.exe start AsrDrv106.sys
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
| Filename           | AsrDrv106.sys |
| MD5                | [12908c285b9d68ee1f39186110df0f1e](https://www.virustotal.com/gui/file/12908c285b9d68ee1f39186110df0f1e) |
| SHA1               | [b0032b8d8e6f4bd19a31619ce38d8e010f29a816](https://www.virustotal.com/gui/file/b0032b8d8e6f4bd19a31619ce38d8e010f29a816) |
| SHA256             | [3943a796cc7c5352aa57ccf544295bfd6fb69aae147bc8235a00202dc6ed6838](https://www.virustotal.com/gui/file/3943a796cc7c5352aa57ccf544295bfd6fb69aae147bc8235a00202dc6ed6838) |
| Authentihash MD5   | [f67b148a13ad3caa51c3c2ef142791ea](https://www.virustotal.com/gui/search/authentihash%253Af67b148a13ad3caa51c3c2ef142791ea) |
| Authentihash SHA1  | [f621633290173daac18bb14ca3f52bc027cd2721](https://www.virustotal.com/gui/search/authentihash%253Af621633290173daac18bb14ca3f52bc027cd2721) |
| Authentihash SHA256| [ac7b3c3b74e6e282c7f50c17a6213b81b181f779cd7c0c78e3cb426c427a98db](https://www.virustotal.com/gui/search/authentihash%253Aac7b3c3b74e6e282c7f50c17a6213b81b181f779cd7c0c78e3cb426c427a98db) |
| Signature         | ASROCK INC., GlobalSign GCC R45 EV CodeSigning CA 2020, GlobalSign Code Signing Root R45, GlobalSign, GlobalSign Root CA - R1   |
| Company           | ASRock Incorporation |
| Description       | ASRock IO Driver |
| Product           | ASRock IO Driver |
| OriginalFilename  | AsrDrv.sys |


#### Imports
{{< details "Expand" >}}
* ntoskrnl.exe
* HAL.dll
* cng.sys

{{< /details >}}
#### ImportedFunctions
{{< details "Expand" >}}
* RtlQueryRegistryValues
* MmUnmapIoSpace
* IoFreeMdl
* MmGetPhysicalAddress
* IoBuildAsynchronousFsdRequest
* MmMapIoSpace
* IofCompleteRequest
* IoFreeIrp
* RtlCompareMemory
* MmUnlockPages
* IoCreateSymbolicLink
* MmAllocateContiguousMemorySpecifyCache
* IofCallDriver
* KeBugCheckEx
* IoDeleteDevice
* MmGetSystemRoutineAddress
* IoCreateDevice
* ZwClose
* ObOpenObjectByPointer
* ZwSetSecurityObject
* IoDeviceObjectType
* _snwprintf
* RtlLengthSecurityDescriptor
* SeCaptureSecurityDescriptor
* RtlCreateSecurityDescriptor
* RtlSetDaclSecurityDescriptor
* RtlAbsoluteToSelfRelativeSD
* IoIsWdmVersionAvailable
* SeExports
* wcschr
* _wcsnicmp
* RtlLengthSid
* RtlAddAccessAllowedAce
* RtlGetSaclSecurityDescriptor
* RtlGetDaclSecurityDescriptor
* RtlGetGroupSecurityDescriptor
* RtlGetOwnerSecurityDescriptor
* ZwOpenKey
* ZwCreateKey
* ZwQueryValueKey
* ZwSetValueKey
* RtlFreeUnicodeString
* RtlInitUnicodeString
* MmFreeContiguousMemorySpecifyCache
* ExFreePoolWithTag
* IoDeleteSymbolicLink
* ExAllocatePoolWithTag
* KeStallExecutionProcessor
* BCryptCloseAlgorithmProvider
* BCryptGenerateSymmetricKey
* BCryptOpenAlgorithmProvider
* BCryptDecrypt
* BCryptDestroyKey

{{< /details >}}
#### ExportedFunctions
{{< details "Expand" >}}

{{< /details >}}
-----



[*source*](https://github.com/magicsword-io/LOLDrivers/tree/main/yaml/asrdrv106.yaml)

*last_updated:* 2023-04-26








{{< /column >}}
{{< /block >}}
