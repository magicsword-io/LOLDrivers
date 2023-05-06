+++

description = ""
title = "otipcibus.sys"
weight = 10

+++


{{< block "grid-1" >}}
{{< column "mt-2 pt-1">}}


# otipcibus.sys 


{{< tip "warning" >}}
We were not able to verify the hash of this driver successfully, it has not been confirmed.
{{< /tip >}}


### Description

otipcibus.sys is a vulnerable driver and more information will be added as found.

- **Created**: 2023-01-09
- **Author**: Michael Haag
- **Acknowledgement**:  | [](https://twitter.com/)

{{< button "https://github.com/magicsword-io/LOLDrivers/raw/main/drivers/d5a642329cce4df94b8dc1ba9660ae34.bin" "Download" >}}
{{< tip "warning" >}}
This download link contains the vulnerable driver!

{{< /tip >}}

### Commands

```
sc.exe create otipcibus.sys binPath=C:\windows\temp\otipcibus.sys type=kernel &amp;&amp; sc.exe start otipcibus.sys
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
| Filename           | otipcibus.sys |
| MD5                | [d5a642329cce4df94b8dc1ba9660ae34](https://www.virustotal.com/gui/file/d5a642329cce4df94b8dc1ba9660ae34) |
| SHA1               | [ccdd3a1ebe9a1c8f8a72af20a05a10f11da1d308](https://www.virustotal.com/gui/file/ccdd3a1ebe9a1c8f8a72af20a05a10f11da1d308) |
| SHA256             | [4e3eb5b9bce2fd9f6878ae36288211f0997f6149aa8c290ed91228ba4cdfae80](https://www.virustotal.com/gui/file/4e3eb5b9bce2fd9f6878ae36288211f0997f6149aa8c290ed91228ba4cdfae80) |
| Authentihash MD5   | [0fc8a346a333624a7b6645da7a1b6b8b](https://www.virustotal.com/gui/search/authentihash%253A0fc8a346a333624a7b6645da7a1b6b8b) |
| Authentihash SHA1  | [fd172c7f8bdc81988fcf1642881078a8ca8415f6](https://www.virustotal.com/gui/search/authentihash%253Afd172c7f8bdc81988fcf1642881078a8ca8415f6) |
| Authentihash SHA256| [1cda1a6e33d14d5dd06344425102bf840f8149e817ecfb01c59a2190d3367024](https://www.virustotal.com/gui/search/authentihash%253A1cda1a6e33d14d5dd06344425102bf840f8149e817ecfb01c59a2190d3367024) |
| Signature         | Ours Technology Inc., Symantec Class 3 SHA256 Code Signing CA, VeriSign   |
| Company           | OTi |
| Description       | Hardware Access Driver |
| Product           | Kernel Mode Driver To Access Physical Memory And Ports |
| OriginalFilename  | otipcibus64.sys |


#### Imports
{{< details "Expand" >}}
* ntoskrnl.exe
* WDFLDR.SYS

{{< /details >}}
#### ImportedFunctions
{{< details "Expand" >}}
* ExAllocatePool
* ExFreePoolWithTag
* MmBuildMdlForNonPagedPool
* MmMapLockedPages
* MmMapLockedPagesSpecifyCache
* MmUnmapLockedPages
* MmMapIoSpace
* MmUnmapIoSpace
* RtlInitUnicodeString
* IofCompleteRequest
* IoCreateDevice
* IoCreateSymbolicLink
* IoDeleteDevice
* IoDeleteSymbolicLink
* IoFreeMdl
* IoGetDeviceObjectPointer
* RtlCopyUnicodeString
* IofCallDriver
* IoBuildSynchronousFsdRequest
* KeWaitForSingleObject
* IoAllocateMdl
* KeInitializeEvent
* WdfVersionBindClass
* WdfVersionUnbind
* WdfVersionBind
* WdfVersionUnbindClass

{{< /details >}}
#### ExportedFunctions
{{< details "Expand" >}}

{{< /details >}}
-----



[*source*](https://github.com/magicsword-io/LOLDrivers/tree/main/yaml/otipcibus.yaml)

*last_updated:* 2023-05-06








{{< /column >}}
{{< /block >}}
