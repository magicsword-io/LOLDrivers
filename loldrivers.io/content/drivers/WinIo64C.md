+++

description = ""
title = "WinIo64C.sys"
weight = 10

+++


{{< block "grid-1" >}}
{{< column "mt-2 pt-1">}}


# WinIo64C.sys 


{{< tip "warning" >}}
We were not able to verify the hash of this driver successfully, it has not been confirmed.
{{< /tip >}}


### Description

WinIo64C.sys is a vulnerable driver and more information will be added as found.

- **Created**: 2023-01-09
- **Author**: Michael Haag
- **Acknowledgement**:  | [](https://twitter.com/)

{{< button "https://github.com/magicsword-io/LOLDrivers/raw/main/drivers/-.bin" "Download" >}}
{{< tip "warning" >}}
This download link contains the vulnerable driver!

{{< /tip >}}

### Commands

```
sc.exe create WinIo64C.sys binPath=C:\windows\temp\WinIo64C.sys type=kernel &amp;&amp; sc.exe start WinIo64C.sys
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
| Filename           | WinIo64C.sys |
| MD5                | [-](https://www.virustotal.com/gui/file/-) |
| SHA1               | [b242b0332b9c9e8e17ec27ef10d75503d20d97b6](https://www.virustotal.com/gui/file/b242b0332b9c9e8e17ec27ef10d75503d20d97b6) |
| SHA256             | [-](https://www.virustotal.com/gui/file/-) |
| Signature         | -   |


#### Imports
{{< details "Expand" >}}

{{< /details >}}
#### ImportedFunctions
{{< details "Expand" >}}

{{< /details >}}
#### ExportedFunctions
{{< details "Expand" >}}

{{< /details >}}
-----
| Property           | Value |
|:-------------------|:------|
| Filename           | WinIo64C.sys |
| MD5                | [-](https://www.virustotal.com/gui/file/-) |
| SHA1               | [a65fabaf64aa1934314aae23f25cdf215cbaa4b6](https://www.virustotal.com/gui/file/a65fabaf64aa1934314aae23f25cdf215cbaa4b6) |
| SHA256             | [-](https://www.virustotal.com/gui/file/-) |
| Signature         | -   |


#### Imports
{{< details "Expand" >}}

{{< /details >}}
#### ImportedFunctions
{{< details "Expand" >}}

{{< /details >}}
#### ExportedFunctions
{{< details "Expand" >}}

{{< /details >}}
-----



[*source*](https://github.com/magicsword-io/LOLDrivers/tree/main/yaml/winio64c.yaml)

*last_updated:* 2023-05-06








{{< /column >}}
{{< /block >}}
