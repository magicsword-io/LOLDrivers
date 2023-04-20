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

{{< button "https://github.com/magicsword-io/LOLDrivers/raw/main/drivers/dc943bf367ae77016ae399df8e71d38a.bin" "Download" >}}
{{< tip "warning" >}}
This download link contains the vulnerable driver!

{{< /tip >}}

### Commands

```
sc.exe create MsIo64.sys binPath=C:\windows\temp\MsIo64.sys type=kernel &amp;&amp; sc.exe start MsIo64.sys
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

| Property           | Value |
|:-------------------|:------|
| Filename           | MsIo64.sys |
| MD5                | [dc943bf367ae77016ae399df8e71d38a](https://www.virustotal.com/gui/file/dc943bf367ae77016ae399df8e71d38a) |
| SHA1               | [6b54f8f137778c1391285fee6150dfa58a8120b1](https://www.virustotal.com/gui/file/6b54f8f137778c1391285fee6150dfa58a8120b1) |
| SHA256             | [43ba8d96d5e8e54cab59d82d495eeca730eeb16e4743ed134cdd495c51a4fc89](https://www.virustotal.com/gui/file/43ba8d96d5e8e54cab59d82d495eeca730eeb16e4743ed134cdd495c51a4fc89) |
| Authentihash MD5   | [9bb721ac0afc94a499a238ae32418d51](https://www.virustotal.com/gui/search/authentihash%253A9bb721ac0afc94a499a238ae32418d51) |
| Authentihash SHA1  | [04a903f13528536f1d0b1751886754d9aa5cdafa](https://www.virustotal.com/gui/search/authentihash%253A04a903f13528536f1d0b1751886754d9aa5cdafa) |
| Authentihash SHA256| [5bf00eff58e5bbe4cf578ec37b9e13c8fa74511fb2644352fcc091347153a709](https://www.virustotal.com/gui/search/authentihash%253A5bf00eff58e5bbe4cf578ec37b9e13c8fa74511fb2644352fcc091347153a709) |
| Signature         | Microsoft Windows Hardware Compatibility Publisher, Microsoft Windows Third Party Component CA 2014, Microsoft Root Certificate Authority 2010   |
| Company           | MICSYS Technology Co., LTd |
| Description       | MICSYS driver |
| Product           | MsIo64 Driver Version 1.1 |
| OriginalFilename  | MsIo64.sys |


#### Imports
{{< details "Expand" >}}
* ntoskrnl.exe
* HAL.dll

{{< /details >}}
#### ImportedFunctions
{{< details "Expand" >}}
* RtlInitUnicodeString
* DbgPrint
* ZwClose
* ZwMapViewOfSection
* ObReferenceObjectByHandle
* ZwOpenSection
* IoDeleteSymbolicLink
* ZwUnmapViewOfSection
* IofCompleteRequest
* IoCreateSymbolicLink
* IoCreateDevice
* ObfDereferenceObject
* IoDeleteDevice
* HalTranslateBusAddress

{{< /details >}}
#### ExportedFunctions
{{< details "Expand" >}}

{{< /details >}}


[*source*](https://github.com/magicsword-io/LOLDrivers/tree/main/yaml/msio64.yaml)

*last_updated:* 2023-04-20








{{< /column >}}
{{< /block >}}
