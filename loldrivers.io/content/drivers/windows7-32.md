+++

description = ""
title = "windows7-32.sys"
weight = 10

+++


{{< block "grid-1" >}}
{{< column "mt-2 pt-1">}}


# windows7-32.sys 


{{< tip "warning" >}}
We were not able to verify the hash of this driver successfully, it has not been confirmed.
{{< /tip >}}


### Description

windows7-32.sys is a vulnerable driver and more information will be added as found.

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
sc.exe create windows7-32.sys binPath=C:\windows\temp\windows7-32.sys     type=kernel type=kernel &amp;&amp; sc.exe start windows7-32.sys
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

| Filename | windows7-32.sys |
|:---- | ---- | 
| MD5 | <a href="https://www.virustotal.com/gui/file/-">-</a> |
| SHA1 | <a href="https://www.virustotal.com/gui/file/-">-</a> |
| SHA256 | <a href="https://www.virustotal.com/gui/file/4941c4298f4560fc1e59d0f16f84bab5c060793700b82be2fd7c63735f1657a8">4941c4298f4560fc1e59d0f16f84bab5c060793700b82be2fd7c63735f1657a8</a> |
| Signature | -   |
#### Imports
{{< details "Expand" >}}{{< /details >}}
#### ImportedFunctions
{{< details "Expand" >}}{{< /details >}}
#### ExportedFunctions
{{< details "Expand" >}}{{< /details >}}



[*source*](https://github.com/magicsword-io/LOLDrivers/tree/main/yaml/windows7-32.yaml)

*last_updated:* 2023-04-19








{{< /column >}}
{{< /block >}}
