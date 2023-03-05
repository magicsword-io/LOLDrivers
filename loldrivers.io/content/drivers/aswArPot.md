+++

description = "CVE-2022-26522, CVE-2022-26523: Both of these vulnerabilities were fixed in version 22.1."
title = "aswArPot.sys"
weight = 10

+++


{{< block "grid-1" >}}
{{< column "mt-2 pt-1">}}


# aswArPot.sys

#### Description


Avast’s “Anti Rootkit” driver (also used by AVG) has been found to be vulnerable to two high severity attacks that could potentially lead to privilege escalation by running code in the kernel from a non-administrator user.


- **Created**: 2023-01-09
- **Author**: Michael Haag
- **Acknowledgement**:  | [@mattnotmax](https://twitter.com/@mattnotmax)

#### Testing

```
sc.exe create aswArPot.sys binPath= C:\windows\temp\aswArPot.sys type= kernel
sc.exe start aswArPot.sys
```

#### Resources
<br>


<li><a href=" https://learn.microsoft.com/en-us/windows/security/threat-protection/windows-defender-application-control/microsoft-recommended-driver-block-rules"> https://learn.microsoft.com/en-us/windows/security/threat-protection/windows-defender-application-control/microsoft-recommended-driver-block-rules</a></li>


<br>


#### Binary Metadata
<br>



- binary: 
- Verified: 
- Date: 2021-02-01 14:09:00
- Publisher: 
- Company: AVAST Software
- Description: Avast Anti Rootkit
- Product: Avast Antivirus

- ProductVersion: 
- FileVersion: 
- MachineType: 
- OriginalFilename: aswArPot.sys

[*source*](https://github.com/magicsword-io/LOLDrivers/tree/main/yaml/aswarpot.sys.yml)

*last_updated:* 2023-03-04


{{< /column >}}
{{< /block >}}
