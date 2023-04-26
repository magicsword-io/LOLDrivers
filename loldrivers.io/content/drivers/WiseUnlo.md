+++

description = ""
title = "WiseUnlo.sys"
weight = 10

+++


{{< block "grid-1" >}}
{{< column "mt-2 pt-1">}}


# WiseUnlo.sys 


{{< tip "warning" >}}
We were not able to verify the hash of this driver successfully, it has not been confirmed.
{{< /tip >}}


### Description

WiseUnlo.sys is a vulnerable driver and more information will be added as found.

- **Created**: 2023-01-09
- **Author**: Michael Haag
- **Acknowledgement**:  | [](https://twitter.com/)

{{< button "https://github.com/magicsword-io/LOLDrivers/raw/main/drivers/356bda2bf0f6899a2c08b2da3ec69f13.bin" "Download" >}}
{{< tip "warning" >}}
This download link contains the vulnerable driver!

{{< /tip >}}

### Commands

```
sc.exe create WiseUnlo.sys binPath=C:\windows\temp\WiseUnlo.sys type=kernel &amp;&amp; sc.exe start WiseUnlo.sys
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
| Filename           | WiseUnlo.sys |
| MD5                | [356bda2bf0f6899a2c08b2da3ec69f13](https://www.virustotal.com/gui/file/356bda2bf0f6899a2c08b2da3ec69f13) |
| SHA1               | [b9807b8840327c6d7fbdde45fc27de921f1f1a82](https://www.virustotal.com/gui/file/b9807b8840327c6d7fbdde45fc27de921f1f1a82) |
| SHA256             | [358ac54be252673841a1d65bfc2fb6d549c1a4c877fa7f5e1bfa188f30375d69](https://www.virustotal.com/gui/file/358ac54be252673841a1d65bfc2fb6d549c1a4c877fa7f5e1bfa188f30375d69) |
| Authentihash MD5   | [6d1e6e5682f9a5e8a64dc8d2ec6ddfac](https://www.virustotal.com/gui/search/authentihash%253A6d1e6e5682f9a5e8a64dc8d2ec6ddfac) |
| Authentihash SHA1  | [49fb554b77c8d533e4a1ff30bbc60ef7f80b7055](https://www.virustotal.com/gui/search/authentihash%253A49fb554b77c8d533e4a1ff30bbc60ef7f80b7055) |
| Authentihash SHA256| [c36ace67f4e25f391e8709776348397e4fd3930e641b32c1b0da398e59199ca7](https://www.virustotal.com/gui/search/authentihash%253Ac36ace67f4e25f391e8709776348397e4fd3930e641b32c1b0da398e59199ca7) |
| Signature         | Lespeed Technology Co., Ltd, COMODO RSA Extended Validation Code Signing CA, Sectigo (formerly Comodo CA)   |
| Company           | WiseCleaner.com |
| Description       | WiseUnlo |
| Product           | WiseUnlo |
| OriginalFilename  | WiseUnlo.sys |


#### Imports
{{< details "Expand" >}}
* ntoskrnl.exe

{{< /details >}}
#### ImportedFunctions
{{< details "Expand" >}}
* IoDeleteSymbolicLink
* IoGetRelatedDeviceObject
* RtlInitUnicodeString
* IoDeleteDevice
* KeSetEvent
* IoCreateFile
* KeInitializeEvent
* IoFileObjectType
* ZwClose
* IofCompleteRequest
* ObReferenceObjectByHandle
* KeWaitForSingleObject
* IoFreeIrp
* IoAllocateIrp
* IoCreateSymbolicLink
* ObfDereferenceObject
* IoCreateDevice
* DbgPrint
* IofCallDriver

{{< /details >}}
#### ExportedFunctions
{{< details "Expand" >}}

{{< /details >}}
-----



[*source*](https://github.com/magicsword-io/LOLDrivers/tree/main/yaml/wiseunlo.yaml)

*last_updated:* 2023-04-26








{{< /column >}}
{{< /block >}}
