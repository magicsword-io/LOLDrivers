+++

description = ""
title = "MsIo64.sys"
weight = 10

+++


{{< block "grid-1" >}}
{{< column "mt-2 pt-1">}}


# MsIo64.sys ![:inline](/images/twitter_verified.png) 


### Description

The MSI AmbientLink MsIo64 driver 1.0.0.8 has a Buffer Overflow (0x80102040, 0x80102044, 0x80102050,and 0x80102054)

- **Created**: 2023-01-09
- **Author**: Michael Haag
- **Acknowledgement**:  | [](https://twitter.com/)

### Commands

```
sc.exe create MsIo64.sys binPath=C:\windows\temp\MsIo64.sys type=kernel
sc.exe start MsIo64.sys
```

| Use Case | Privileges | Operating System | 
|:---- | ---- | ---- |
| Elevate privileges | kernel | Windows 10 |

### Resources
<br>
<li><a href=" https://github.com/namazso/physmem_drivers"> https://github.com/namazso/physmem_drivers</a></li>
<li><a href=" https://www.matteomalvica.com/blog/2020/09/24/weaponizing-cve-2020-17382/"> https://www.matteomalvica.com/blog/2020/09/24/weaponizing-cve-2020-17382/</a></li>
<li><a href="https://packetstormsecurity.com/files/159315/MSI-Ambient-Link-Driver-1.0.0.8-Privilege-Escalation.html">https://packetstormsecurity.com/files/159315/MSI-Ambient-Link-Driver-1.0.0.8-Privilege-Escalation.html</a></li>
<li><a href="https://www.coresecurity.com/core-labs/advisories/msi-ambient-link-multiple-vulnerabilities">https://www.coresecurity.com/core-labs/advisories/msi-ambient-link-multiple-vulnerabilities</a></li>
<li><a href="https://github.com/Exploitables/CVE-2020-17382">https://github.com/Exploitables/CVE-2020-17382</a></li>
<li><a href="https://github.com/namazso/physmem_drivers">https://github.com/namazso/physmem_drivers</a></li>
<br>

### Known Vulnerable Samples

| Filename | MsIo64.sys |
|:---- | ---- | 
| MD5 | <a href="https://www.virustotal.com/gui/file/dc943bf367ae77016ae399df8e71d38a">dc943bf367ae77016ae399df8e71d38a</a> |
| SHA1 | <a href="https://www.virustotal.com/gui/file/6b54f8f137778c1391285fee6150dfa58a8120b1">6b54f8f137778c1391285fee6150dfa58a8120b1</a> |
| SHA256 | <a href="https://www.virustotal.com/gui/file/43ba8d96d5e8e54cab59d82d495eeca730eeb16e4743ed134cdd495c51a4fc89">43ba8d96d5e8e54cab59d82d495eeca730eeb16e4743ed134cdd495c51a4fc89</a> |
| Signature | Microsoft Windows Hardware Compatibility Publisher, Microsoft Windows Third Party Component CA 2014, Microsoft Root Certificate Authority 2010   |


[*source*](https://github.com/magicsword-io/LOLDrivers/tree/main/yaml/msio64.yaml)

*last_updated:* 2023-04-06








{{< /column >}}
{{< /block >}}
