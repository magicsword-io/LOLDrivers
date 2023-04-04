+++

description = "https://learn.microsoft.com/en-us/windows/security/threat-protection/windows-defender-application-control/microsoft-recommended-driver-block-rules"
title = "Bs_Def.sys"
weight = 10

+++


{{< block "grid-1" >}}
{{< column "mt-2 pt-1">}}


# Bs_Def.sys 


{{< tip "warning" >}}
We were not able to verify the hash of this driver successfully, it has not been confirmed.
{{< /tip >}}


### Description

Bs_Def.sys is a vulnerable driver and more information will be added as found.

- **Created**: 2023-01-09
- **Author**: Michael Haag
- **Acknowledgement**:  | [](https://twitter.com/)

### Commands

```
sc.exe create Bs_Def.sys binPath=C:\windows\temp\Bs_Def.sys type=kernel
sc.exe start Bs_Def.sys
```

| Use Case | Privilages | Operating System | 
|:---- | ---- | ---- |
| Elevate privileges | kernel | Windows 10 |

### Resources
<br>
<li><a href=" https://learn.microsoft.com/en-us/windows/security/threat-protection/windows-defender-application-control/microsoft-recommended-driver-block-rules"> https://learn.microsoft.com/en-us/windows/security/threat-protection/windows-defender-application-control/microsoft-recommended-driver-block-rules</a></li>
<br>

### Known Vulnerable Samples

| Filename | Bs_Def.sys |
|:---- | ---- | 
| MD5 | <a href="https://www.virustotal.com/gui/file/a9f220b1507a3c9a327a99995ff99c82">a9f220b1507a3c9a327a99995ff99c82</a> |
| SHA1 | <a href="https://www.virustotal.com/gui/file/2c5ff272bd345962ed41ab8869aef41da0dfe697">2c5ff272bd345962ed41ab8869aef41da0dfe697</a> |
| SHA256 | <a href="https://www.virustotal.com/gui/file/5f5e5f1c93d961985624768b7c676d488c7c7c1d4c043f6fc1ea1904fefb75be">5f5e5f1c93d961985624768b7c676d488c7c7c1d4c043f6fc1ea1904fefb75be</a> |
| Signature | ASUSTeK Computer Inc., VeriSign Class 3 Code Signing 2004 CA, VeriSign Class 3 Public Primary CA   |


[*source*](https://github.com/magicsword-io/LOLDrivers/tree/main/yaml/bs_def.sys.yml)

*last_updated:* 2023-04-04








{{< /column >}}
{{< /block >}}
