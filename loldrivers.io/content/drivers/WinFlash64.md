+++

description = ""
title = "WinFlash64.sys"
weight = 10

+++


{{< block "grid-1" >}}
{{< column "mt-2 pt-1">}}


# WinFlash64.sys ![:inline](/images/twitter_verified.png) 


### Description

WinFlash64.sys is a vulnerable driver and more information will be added as found.

- **Created**: 2023-01-09
- **Author**: Michael Haag
- **Acknowledgement**:  | [](https://twitter.com/)

{{< button "https://github.com/magicsword-io/LOLDrivers/raw/main/drivers/a4fda97f452b8f8705695a729f5969f7.bin" "Download" >}}
{{< tip "warning" >}}
{% if driver.Category == "vulnerable driver" %}
This download link contains the vulnerable driver!
{% elif driver.Category == "malicious" %}
This download link contains the malicious driver!
{% endif %}
{{< /tip >}}

### Commands

```
sc.exe create WinFlash64.sys binPath=C:\windows\temp\WinFlash64.sys type=kernel &amp;&amp; sc.exe start WinFlash64.sys
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

| Filename | WinFlash64.sys |
|:---- | ---- | 
| MD5 | <a href="https://www.virustotal.com/gui/file/a4fda97f452b8f8705695a729f5969f7">a4fda97f452b8f8705695a729f5969f7</a> |
| SHA1 | <a href="https://www.virustotal.com/gui/file/8183a341ba6c3ce1948bf9be49ab5320e0ee324d">8183a341ba6c3ce1948bf9be49ab5320e0ee324d</a> |
| SHA256 | <a href="https://www.virustotal.com/gui/file/677c0b1add3990fad51f492553d3533115c50a242a919437ccb145943011d2bf">677c0b1add3990fad51f492553d3533115c50a242a919437ccb145943011d2bf</a> |
| Authentihash MD5 | <a href="https://www.virustotal.com/gui/search/authentihash%253A9fd32632e404f7d009ffe1ed34364539">9fd32632e404f7d009ffe1ed34364539</a> || Authentihash SHA1 | <a href="https://www.virustotal.com/gui/search/authentihash%253Ada21f5889f8374c3961856d681adec3d663d2964">da21f5889f8374c3961856d681adec3d663d2964</a> || Authentihash SHA256 | <a href="https://www.virustotal.com/gui/search/authentihash%253Af2b51fbeead17f5ee34d5b4a3a83c848fb76f8f0e80769212e137a7aa539a3bc">f2b51fbeead17f5ee34d5b4a3a83c848fb76f8f0e80769212e137a7aa539a3bc</a> || Signature | Phoenix Technology Ltd., VeriSign Class 3 Code Signing 2004 CA, VeriSign Class 3 Public Primary CA   |
#### Imports
{{< details "Expand" >}}* ntoskrnl.exe
{{< /details >}}
#### ImportedFunctions
{{< details "Expand" >}}* IoDeleteDevice
* RtlFreeUnicodeString
* IoCreateSymbolicLink
* IoCreateDevice
* RtlAnsiStringToUnicodeString
* RtlInitString
* IofCompleteRequest
* MmMapLockedPages
* IoDeleteSymbolicLink
* RtlInitUnicodeString
* ExFreePoolWithTag
* ExAllocatePoolWithTag
* MmUnmapIoSpace
* MmMapIoSpace
* KeBugCheckEx
{{< /details >}}
#### ExportedFunctions
{{< details "Expand" >}}{{< /details >}}



[*source*](https://github.com/magicsword-io/LOLDrivers/tree/main/yaml/winflash64.yaml)

*last_updated:* 2023-04-19








{{< /column >}}
{{< /block >}}
