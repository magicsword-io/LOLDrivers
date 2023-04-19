+++

description = ""
title = "TGSafe.sys"
weight = 10

+++


{{< block "grid-1" >}}
{{< column "mt-2 pt-1">}}


# TGSafe.sys 


{{< tip "warning" >}}
We were not able to verify the hash of this driver successfully, it has not been confirmed.
{{< /tip >}}


### Description

TGSafe.sys is a vulnerable driver and more information will be added as found.

- **Created**: 2023-01-09
- **Author**: Michael Haag
- **Acknowledgement**:  | [](https://twitter.com/)

{{< button "https://github.com/magicsword-io/LOLDrivers/raw/main/drivers/-.bin" "Download" >}}
{{< tip "warning" >}}
{% if driver.Category == "vulnerable driver" %}
This download link contains the vulnerable driver!
{% elif driver.Category == "malicious" %}
This download link contains the malicious driver!
{% endif %}
{{< /tip >}}

### Commands

```
sc.exe create TGSafe.sys binPath=C:\windows\temp\TGSafe.sys type=kernel &amp;&amp; sc.exe start TGSafe.sys
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

| Filename | TGSafe.sys |
|:---- | ---- | 
| MD5 | <a href="https://www.virustotal.com/gui/file/-">-</a> |
| SHA1 | <a href="https://www.virustotal.com/gui/file/-">-</a> |
| SHA256 | <a href="https://www.virustotal.com/gui/file/3a95cc82173032b82a0ffc7d2e438df64c13bc16b4574214c9fe3be37250925e">3a95cc82173032b82a0ffc7d2e438df64c13bc16b4574214c9fe3be37250925e</a> |
| Signature | -   |
#### Imports
{{< details "Expand" >}}{{< /details >}}
#### ImportedFunctions
{{< details "Expand" >}}{{< /details >}}
#### ExportedFunctions
{{< details "Expand" >}}{{< /details >}}



[*source*](https://github.com/magicsword-io/LOLDrivers/tree/main/yaml/tgsafe.yaml)

*last_updated:* 2023-04-19








{{< /column >}}
{{< /block >}}
