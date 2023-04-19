+++

description = ""
title = "PhlashNT.sys"
weight = 10

+++


{{< block "grid-1" >}}
{{< column "mt-2 pt-1">}}


# PhlashNT.sys ![:inline](/images/twitter_verified.png) 


### Description

PhlashNT.sys is a vulnerable driver and more information will be added as found.

- **Created**: 2023-01-09
- **Author**: Michael Haag
- **Acknowledgement**:  | [](https://twitter.com/)

{{< button "https://github.com/magicsword-io/LOLDrivers/raw/main/drivers/e9e786bdba458b8b4f9e93d034f73d00.bin" "Download" >}}
{{< tip "warning" >}}
{% if driver.Category == "vulnerable driver" %}
This download link contains the vulnerable driver!
{% elif driver.Category == "malicious" %}
This download link contains the malicious driver!
{% endif %}
{{< /tip >}}

### Commands

```
sc.exe create PhlashNT.sys binPath=C:\windows\temp\PhlashNT.sys type=kernel &amp;&amp; sc.exe start PhlashNT.sys
```

| Use Case | Privileges | Operating System | 
|:---- | ---- | ---- |
| Elevate privileges | kernel | Windows 10 |

### Resources
<br>
<li><a href=" https://github.com/eclypsium/Screwed-Drivers/blob/master/DRIVERS.md"> https://github.com/eclypsium/Screwed-Drivers/blob/master/DRIVERS.md</a></li>
<li><a href="https://github.com/eclypsium/Screwed-Drivers/blob/master/DRIVERS.md">https://github.com/eclypsium/Screwed-Drivers/blob/master/DRIVERS.md</a></li>
<br>

### Known Vulnerable Samples

| Filename | PhlashNT.sys |
|:---- | ---- | 
| MD5 | <a href="https://www.virustotal.com/gui/file/e9e786bdba458b8b4f9e93d034f73d00">e9e786bdba458b8b4f9e93d034f73d00</a> |
| SHA1 | <a href="https://www.virustotal.com/gui/file/c6d349823bbb1f5b44bae91357895dba653c5861">c6d349823bbb1f5b44bae91357895dba653c5861</a> |
| SHA256 | <a href="https://www.virustotal.com/gui/file/65db1b259e305a52042e07e111f4fa4af16542c8bacd33655f753ef642228890">65db1b259e305a52042e07e111f4fa4af16542c8bacd33655f753ef642228890</a> |
| Authentihash MD5 | <a href="https://www.virustotal.com/gui/search/authentihash%253A5cf72ecb15ffea87586783893b02c43d">5cf72ecb15ffea87586783893b02c43d</a> || Authentihash SHA1 | <a href="https://www.virustotal.com/gui/search/authentihash%253Aef2d7210b761f158a0832083a8407b3ec2f99db9">ef2d7210b761f158a0832083a8407b3ec2f99db9</a> || Authentihash SHA256 | <a href="https://www.virustotal.com/gui/search/authentihash%253Acde02c7db90626bcfbfbbc1315d4ce18d4f15667fa57c16b9ac2b060507c62ad">cde02c7db90626bcfbfbbc1315d4ce18d4f15667fa57c16b9ac2b060507c62ad</a> || Signature | Phoenix Technology Ltd., VeriSign Class 3 Code Signing 2004 CA, VeriSign Class 3 Public Primary CA   || Company | Phoenix Technologies, Ltd. || Description | SWinFlash Driver for Windows NT || Product | WinPhlash || OriginalFilename | PHLASHNT.SYS |
#### Imports
{{< details "Expand" >}}* ntoskrnl.exe
{{< /details >}}
#### ImportedFunctions
{{< details "Expand" >}}* IoDeleteDevice
* IoCreateSymbolicLink
* IoCreateDevice
* RtlInitUnicodeString
* IoDeleteSymbolicLink
* IofCompleteRequest
* MmMapLockedPages
* RtlAssert
* DbgPrint
* MmMapIoSpace
* MmUnmapIoSpace
* ExFreePoolWithTag
* ExAllocatePoolWithTag
{{< /details >}}
#### ExportedFunctions
{{< details "Expand" >}}{{< /details >}}



[*source*](https://github.com/magicsword-io/LOLDrivers/tree/main/yaml/phlashnt.yaml)

*last_updated:* 2023-04-19








{{< /column >}}
{{< /block >}}
