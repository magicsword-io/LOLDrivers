+++

description = ""
title = "dbutil.sys"
weight = 10

+++


{{< block "grid-1" >}}
{{< column "mt-2 pt-1">}}


# dbutil.sys 


{{< tip "warning" >}}
We were not able to verify the hash of this driver successfully, it has not been confirmed.
{{< /tip >}}


### Description

dbutil.sys is a vulnerable driver and more information will be added as found.

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
sc.exe create dbutil.sys binPath=C:\windows\temp\dbutil.sys type=kernel &amp;&amp; sc.exe start dbutil.sys
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

| Filename | dbutil.sys |
|:---- | ---- | 
| MD5 | <a href="https://www.virustotal.com/gui/file/-">-</a> |
| SHA1 | <a href="https://www.virustotal.com/gui/file/485c0b9710a196c7177b99ee95e5ddb35b26ddd1">485c0b9710a196c7177b99ee95e5ddb35b26ddd1</a> |
| SHA256 | <a href="https://www.virustotal.com/gui/file/-">-</a> |
| Signature | -   |
#### Imports
{{< details "Expand" >}}{{< /details >}}
#### ImportedFunctions
{{< details "Expand" >}}{{< /details >}}
#### ExportedFunctions
{{< details "Expand" >}}{{< /details >}}
| Filename | dbutil.sys |
|:---- | ---- | 
| MD5 | <a href="https://www.virustotal.com/gui/file/-">-</a> |
| SHA1 | <a href="https://www.virustotal.com/gui/file/50e2bc41f0186fdce970b80e2a2cb296353af586">50e2bc41f0186fdce970b80e2a2cb296353af586</a> |
| SHA256 | <a href="https://www.virustotal.com/gui/file/-">-</a> |
| Signature | -   |
#### Imports
{{< details "Expand" >}}{{< /details >}}
#### ImportedFunctions
{{< details "Expand" >}}{{< /details >}}
#### ExportedFunctions
{{< details "Expand" >}}{{< /details >}}
| Filename | dbutil.sys |
|:---- | ---- | 
| MD5 | <a href="https://www.virustotal.com/gui/file/-">-</a> |
| SHA1 | <a href="https://www.virustotal.com/gui/file/e3c1dd569aa4758552566b0213ee4d1fe6382c4b">e3c1dd569aa4758552566b0213ee4d1fe6382c4b</a> |
| SHA256 | <a href="https://www.virustotal.com/gui/file/-">-</a> |
| Signature | -   |
#### Imports
{{< details "Expand" >}}{{< /details >}}
#### ImportedFunctions
{{< details "Expand" >}}{{< /details >}}
#### ExportedFunctions
{{< details "Expand" >}}{{< /details >}}
| Filename | dbutil.sys |
|:---- | ---- | 
| MD5 | <a href="https://www.virustotal.com/gui/file/-">-</a> |
| SHA1 | <a href="https://www.virustotal.com/gui/file/e09b5e80805b8fe853ea27d8773e31bff262e3f7">e09b5e80805b8fe853ea27d8773e31bff262e3f7</a> |
| SHA256 | <a href="https://www.virustotal.com/gui/file/-">-</a> |
| Signature | -   |
#### Imports
{{< details "Expand" >}}{{< /details >}}
#### ImportedFunctions
{{< details "Expand" >}}{{< /details >}}
#### ExportedFunctions
{{< details "Expand" >}}{{< /details >}}



[*source*](https://github.com/magicsword-io/LOLDrivers/tree/main/yaml/dbutil.yaml)

*last_updated:* 2023-04-19








{{< /column >}}
{{< /block >}}
