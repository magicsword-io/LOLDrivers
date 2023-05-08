+++

description = ""
title = "cacc48e6-6ed8-431c-abee-88ee6c2dc3c1"
weight = 10

+++


{{< block "grid-1" >}}
{{< column "mt-2 pt-1">}}


# nt2.sys


{{< tip "warning" >}}
We were not able to verify the hash of this driver successfully, it has not been confirmed.
{{< /tip >}}


### Description

cacc48e6-6ed8-431c-abee-88ee6c2dc3c1 is a vulnerable driver and more information will be added as found.
- **UUID**: cacc48e6-6ed8-431c-abee-88ee6c2dc3c1
- **Created**: 2023-01-09
- **Author**: Michael Haag
- **Acknowledgement**:  | [](https://twitter.com/)

{{< button "https://github.com/magicsword-io/LOLDrivers/raw/main/drivers/.bin" "Download" >}}
{{< tip "warning" >}}
This download link contains the vulnerable driver!

{{< /tip >}}

### Commands

```
sc.exe create nt2.sys binPath=C:\windows\temp \n \n \n  t2.sys type=kernel &amp;&amp; sc.exe start nt2.sys
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
| Filename           | nt2.sys |
| MD5                | [](https://www.virustotal.com/gui/file/) |
| SHA1               | [](https://www.virustotal.com/gui/file/) |
| SHA256             | [cb9890d4e303a4c03095d7bc176c42dee1b47d8aa58e2f442ec1514c8f9e3cec](https://www.virustotal.com/gui/file/cb9890d4e303a4c03095d7bc176c42dee1b47d8aa58e2f442ec1514c8f9e3cec) |


#### Imports
{{< details "Expand" >}}

{{< /details >}}
#### ImportedFunctions
{{< details "Expand" >}}

{{< /details >}}
#### ExportedFunctions
{{< details "Expand" >}}

{{< /details >}}

#### Signature
{{< details "Expand" >}}

{{< /details >}}
-----



[*source*](https://github.com/magicsword-io/LOLDrivers/tree/main/yaml/cacc48e6-6ed8-431c-abee-88ee6c2dc3c1.yaml)

*last_updated:* 2023-05-08








{{< /column >}}
{{< /block >}}
