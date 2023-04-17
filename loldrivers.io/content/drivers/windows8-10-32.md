+++

description = ""
title = "windows8-10-32.sys"
weight = 10

+++


{{< block "grid-1" >}}
{{< column "mt-2 pt-1">}}


# windows8-10-32.sys 


{{< tip "warning" >}}
We were not able to verify the hash of this driver successfully, it has not been confirmed.
{{< /tip >}}


### Description

windows8-10-32.sys is a vulnerable driver and more information will be added as found.

- **Created**: 2023-01-09
- **Author**: Michael Haag
- **Acknowledgement**:  | [](https://twitter.com/)

{{< button "https://github.com/magicsword-io/LOLDrivers/raw/main/drivers/-.bin" "Download" >}}
{{< tip "warning" >}}
This download link contains the malcious driver!
{{< /tip >}}

### Commands

```
sc.exe create windows8-10-32.sys binPath=C:\windows\temp\windows8-10-32.sys     type=kernel type=kernel &amp;&amp; sc.exe start windows8-10-32.sys
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

| Filename | windows8-10-32.sys |
|:---- | ---- | 
| MD5 | <a href="https://www.virustotal.com/gui/file/-">-</a> |
| SHA1 | <a href="https://www.virustotal.com/gui/file/-">-</a> |
| SHA256 | <a href="https://www.virustotal.com/gui/file/5b9623da9ba8e5c80c49473f40ffe7ad315dcadffc3230afdc9d9226d60a715a">5b9623da9ba8e5c80c49473f40ffe7ad315dcadffc3230afdc9d9226d60a715a</a> |
| Signature | -   |
#### Imports
{{< details "Expand" >}}{{< /details >}}
#### ImportedFunctions
{{< details "Expand" >}}{{< /details >}}
#### ExportedFunctions
{{< details "Expand" >}}{{< /details >}}



[*source*](https://github.com/magicsword-io/LOLDrivers/tree/main/yaml/windows8-10-32.yaml)

*last_updated:* 2023-04-16








{{< /column >}}
{{< /block >}}
