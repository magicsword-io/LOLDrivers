+++

description = "CVE-2022-26522, CVE-2022-26523: Both of these vulnerabilities were fixed in version 22.1."
title = "aswArPot.sys"
weight = 10

+++


{{< block "grid-1" >}}
{{< column "mt-2 pt-1">}}


# aswArPot.sys ![:inline](/images/twitter_verified.png) 


### Description

Avast’s “Anti Rootkit” driver (also used by AVG) has been found to be vulnerable to two high severity attacks that could potentially lead to privilege escalation by running code in the kernel from a non-administrator user.

- **Created**: 2023-01-09
- **Author**: Michael Haag
- **Acknowledgement**:  | [@mattnotmax](https://twitter.com/@mattnotmax)

### Commands

```
sc.exe create aswArPot.sys binPath=C:\windows\temp\aswArPot.sys type=kernel
sc.exe start aswArPot.sys
```

| Use Case | Privilages | Operating System | 
|:---- | ---- | ---- |
| Elevate privileges | kernel | Windows 10 |

### Resources
<br>
<li><a href=" https://learn.microsoft.com/en-us/windows/security/threat-protection/windows-defender-application-control/microsoft-recommended-driver-block-rules"> https://learn.microsoft.com/en-us/windows/security/threat-protection/windows-defender-application-control/microsoft-recommended-driver-block-rules</a></li>
<br>

### Known Vulnerable Samples

| Filename | aswArPot.sys |
|:---- | ---- | 
| MD5 | <a href="https://www.virustotal.com/gui/file/a179c4093d05a3e1ee73f6ff07f994aa">a179c4093d05a3e1ee73f6ff07f994aa</a> |
| SHA1 | <a href="https://www.virustotal.com/gui/file/5d6b9e80e12bfc595d4d26f6afb099b3cb471dd4">5d6b9e80e12bfc595d4d26f6afb099b3cb471dd4</a> |
| SHA256 | <a href="https://www.virustotal.com/gui/file/4b5229b3250c8c08b98cb710d6c056144271de099a57ae09f5d2097fc41bd4f1">4b5229b3250c8c08b98cb710d6c056144271de099a57ae09f5d2097fc41bd4f1</a> |
| Signature | Avast Software s.r.o., DigiCert High Assurance Code Signing CA-1, DigiCert   || Date | 2021-02-01 14:09:00 || Company | AVAST Software || Description | Avast Anti Rootkit || Product | Avast Antivirus
 || OriginalFilename | aswArPot.sys |


[*source*](https://github.com/magicsword-io/LOLDrivers/tree/main/yaml/aswarpot.sys.yml)

*last_updated:* 2023-04-03








{{< /column >}}
{{< /block >}}
