+++

description = ""
title = "LenovoDiagnosticsDriver.sys"
weight = 10

+++


{{< block "grid-1" >}}
{{< column "mt-2 pt-1">}}


# LenovoDiagnosticsDriver.sys ![:inline](/images/twitter_verified.png) 


### Description

The aforementioned driver has been identified as vulnerable to CVE-2022-3699

- **Created**: 2023-01-09
- **Author**: Michael Haag
- **Acknowledgement**: Mike Alfaro | [alfarom256](https://twitter.com/alfarom256)

{{< button "https://github.com/magicsword-io/LOLDrivers/raw/main/drivers/b941c8364308990ee4cc6eadf7214e0f.bin" "Download" >}}
{{< tip "warning" >}}
This download link contains the vulnerable driver!

{{< /tip >}}

### Commands

```
sc.exe create LenovoDiagnosticsDriver.sys binPath=C:\windows\temp\LenovoDiagnosticsDriver.sys type=kernel &amp;&amp; sc.exe start LenovoDiagnosticsDriver.sys
```

| Use Case | Privileges | Operating System | 
|:---- | ---- | ---- |
| Elevate privileges | kernel | Windows 10 |

### Resources
<br>
<li><a href=" https://learn.microsoft.com/en-us/windows/security/threat-protection/windows-defender-application-control/microsoft-recommended-driver-block-rules"> https://learn.microsoft.com/en-us/windows/security/threat-protection/windows-defender-application-control/microsoft-recommended-driver-block-rules</a></li>
<li><a href="https://learn.microsoft.com/en-us/windows/security/threat-protection/windows-defender-application-control/microsoft-recommended-driver-block-rules">https://learn.microsoft.com/en-us/windows/security/threat-protection/windows-defender-application-control/microsoft-recommended-driver-block-rules</a></li>
<li><a href="https://nephosec.com/cve-2022-3699-lenovo-diagnostics-driver-eop-arbitrary-r-w/">https://nephosec.com/cve-2022-3699-lenovo-diagnostics-driver-eop-arbitrary-r-w/</a></li>
<li><a href="https://github.com/alfarom256/CVE-2022-3699">https://github.com/alfarom256/CVE-2022-3699</a></li>
<li><a href="https://support.lenovo.com/us/en/product_security/LEN-94532">https://support.lenovo.com/us/en/product_security/LEN-94532</a></li>
<br>

### Known Vulnerable Samples

| Property           | Value |
|:-------------------|:------|
| Filename           | LenovoDiagnosticsDriver.sys |
| MD5                | [b941c8364308990ee4cc6eadf7214e0f](https://www.virustotal.com/gui/file/b941c8364308990ee4cc6eadf7214e0f) |
| SHA1               | [b89a8eef5aeae806af5ba212a8068845cafdab6f](https://www.virustotal.com/gui/file/b89a8eef5aeae806af5ba212a8068845cafdab6f) |
| SHA256             | [f05b1ee9e2f6ab704b8919d5071becbce6f9d0f9d0ba32a460c41d5272134abe](https://www.virustotal.com/gui/file/f05b1ee9e2f6ab704b8919d5071becbce6f9d0f9d0ba32a460c41d5272134abe) |
| Authentihash MD5   | [56b6144e389ce3b1e2a0a96a954aa7d8](https://www.virustotal.com/gui/search/authentihash%253A56b6144e389ce3b1e2a0a96a954aa7d8) |
| Authentihash SHA1  | [6d9543725aca0c9c8f403425952692ccc1d2d7f2](https://www.virustotal.com/gui/search/authentihash%253A6d9543725aca0c9c8f403425952692ccc1d2d7f2) |
| Authentihash SHA256| [34e6a56c60746c51034b45a7b2a36617205b598d0bbcc695f92404605a0975d5](https://www.virustotal.com/gui/search/authentihash%253A34e6a56c60746c51034b45a7b2a36617205b598d0bbcc695f92404605a0975d5) |
| Signature         | Lenovo, DigiCert Trusted G4 Code Signing RSA4096 SHA384 2021 CA1, DigiCert Trusted Root G4   |
| Company           | Lenovo Group Limited (R) |
| Description       | Lenovo Diagnostics Driver for Windows 10 and later. |
| Product           | Lenovo Diagnostics |
| OriginalFilename  | LenovoDiagnosticsDriver.sys |


#### Imports
{{< details "Expand" >}}
* ntoskrnl.exe
* HAL.dll

{{< /details >}}
#### ImportedFunctions
{{< details "Expand" >}}
* MmMapIoSpace
* MmUnmapIoSpace
* IofCompleteRequest
* IoCreateSymbolicLink
* IoDeleteDevice
* IoDeleteSymbolicLink
* __C_specific_handler
* MmGetSystemRoutineAddress
* RtlInitUnicodeString
* ExFreePoolWithTag
* ZwClose
* ZwSetSecurityObject
* IoDeviceObjectType
* IoCreateDevice
* ObOpenObjectByPointer
* RtlGetDaclSecurityDescriptor
* RtlGetGroupSecurityDescriptor
* ExAllocatePoolWithTag
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
* RtlGetOwnerSecurityDescriptor
* DbgPrintEx
* HalGetBusDataByOffset
* HalSetBusDataByOffset

{{< /details >}}
#### ExportedFunctions
{{< details "Expand" >}}

{{< /details >}}


[*source*](https://github.com/magicsword-io/LOLDrivers/tree/main/yaml/lenovodiagnosticsdriver.yaml)

*last_updated:* 2023-04-20








{{< /column >}}
{{< /block >}}
