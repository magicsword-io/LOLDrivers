+++

description = ""
title = "piddrv.sys"
weight = 10

+++


{{< block "grid-1" >}}
{{< column "mt-2 pt-1">}}


# piddrv.sys 


{{< tip "warning" >}}
We were not able to verify the hash of this driver successfully, it has not been confirmed.
{{< /tip >}}


### Description

piddrv.sys is a vulnerable driver and more information will be added as found.

- **Created**: 2023-01-09
- **Author**: Michael Haag
- **Acknowledgement**:  | [](https://twitter.com/)

{{< button "https://github.com/magicsword-io/LOLDrivers/raw/main/drivers/-.bin" "Download" >}}
{{< tip "warning" >}}
This download link contains the vulnerable driver!

{{< /tip >}}

### Commands

```
sc.exe create piddrv.sys binPath=C:\windows\temp\piddrv.sys type=kernel &amp;&amp; sc.exe start piddrv.sys
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
| Filename           | piddrv.sys |
| MD5                | [-](https://www.virustotal.com/gui/file/-) |
| SHA1               | [a7d827a41b2c4b7638495cd1d77926f1ba902978](https://www.virustotal.com/gui/file/a7d827a41b2c4b7638495cd1d77926f1ba902978) |
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
| Filename           | piddrv.sys |
| MD5                | [-](https://www.virustotal.com/gui/file/-) |
| SHA1               | [877c6c36a155109888fe1f9797b93cb30b4957ef](https://www.virustotal.com/gui/file/877c6c36a155109888fe1f9797b93cb30b4957ef) |
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



[*source*](https://github.com/magicsword-io/LOLDrivers/tree/main/yaml/piddrv.yaml)

*last_updated:* 2023-04-22








{{< /column >}}
{{< /block >}}
