+++

description = ""
title = "LenovoDiagnosticsDriver.sys"
weight = 10

+++


{{< block "grid-1" >}}
{{< column "mt-2 pt-1">}}


# LenovoDiagnosticsDriver.sys 


{{< tip "warning" >}}
We were not able to verify the hash of this driver successfully, it has not been confirmed.
{{< /tip >}}


### Description

LenovoDiagnosticsDriver.sys is a vulnerable driver and more information will be added as found.

- **Created**: 2023-01-09
- **Author**: Michael Haag
- **Acknowledgement**: Mike Alfaro | [alfarom256](https://twitter.com/alfarom256)

### Commands

```
sc.exe create LenovoDiagnosticsDriver.sys binPath=C:\windows\temp\LenovoDiagnosticsDriver.sys type=kernel
sc.exe start LenovoDiagnosticsDriver.sys
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

| Filename | LenovoDiagnosticsDriver.sys |
|:---- | ---- | 
| MD5 | <a href="https://www.virustotal.com/gui/file/b941c8364308990ee4cc6eadf7214e0f">b941c8364308990ee4cc6eadf7214e0f</a> |
| SHA1 | <a href="https://www.virustotal.com/gui/file/b89a8eef5aeae806af5ba212a8068845cafdab6f">b89a8eef5aeae806af5ba212a8068845cafdab6f</a> |
| SHA256 | <a href="https://www.virustotal.com/gui/file/f05b1ee9e2f6ab704b8919d5071becbce6f9d0f9d0ba32a460c41d5272134abe">f05b1ee9e2f6ab704b8919d5071becbce6f9d0f9d0ba32a460c41d5272134abe</a> |
| Signature | Lenovo, DigiCert Trusted G4 Code Signing RSA4096 SHA384 2021 CA1, DigiCert Trusted Root G4   || Company | Lenovo Group Limited (R) || Description | Lenovo Diagnostics Driver for Windows 10 and later. || Product | Lenovo Diagnostics || OriginalFilename | LenovoDiagnosticsDriver.sys |


[*source*](https://github.com/magicsword-io/LOLDrivers/tree/main/yaml/lenovodiagnosticsdriver.yaml)

*last_updated:* 2023-04-10








{{< /column >}}
{{< /block >}}
