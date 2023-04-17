+++

description = ""
title = "cpuz_x64.sys"
weight = 10

+++


{{< block "grid-1" >}}
{{< column "mt-2 pt-1">}}


# cpuz_x64.sys ![:inline](/images/twitter_verified.png) 


### Description

cpuz_x64.sys is a vulnerable driver and more information will be added as found.

- **Created**: 2023-01-09
- **Author**: Michael Haag
- **Acknowledgement**:  | [](https://twitter.com/)

{{< button "https://github.com/magicsword-io/LOLDrivers/raw/main/drivers/7d46d0ddaf8c7e1776a70c220bf47524.bin" "Download" >}}
{{< tip "warning" >}}
This download link contains the malcious driver!
{{< /tip >}}

### Commands

```
sc.exe create cpuz_x64.sys binPath=C:\windows\temp\cpuz_x64.sys type=kernel &amp;&amp; sc.exe start cpuz_x64.sys
```

| Use Case | Privileges | Operating System | 
|:---- | ---- | ---- |
| Elevate privileges | kernel | Windows 10 |

### Resources
<br>
<li><a href=" https://github.com/namazso/physmem_drivers"> https://github.com/namazso/physmem_drivers</a></li>
<li><a href="https://github.com/namazso/physmem_drivers">https://github.com/namazso/physmem_drivers</a></li>
<br>

### Known Vulnerable Samples

| Filename | cpuz_x64.sys |
|:---- | ---- | 
| MD5 | <a href="https://www.virustotal.com/gui/file/7d46d0ddaf8c7e1776a70c220bf47524">7d46d0ddaf8c7e1776a70c220bf47524</a> |
| SHA1 | <a href="https://www.virustotal.com/gui/file/d2e6fc9259420f0c9b6b1769be3b1f63eb36dc57">d2e6fc9259420f0c9b6b1769be3b1f63eb36dc57</a> |
| SHA256 | <a href="https://www.virustotal.com/gui/file/3871e16758a1778907667f78589359734f7f62f9dc953ec558946dcdbe6951e3">3871e16758a1778907667f78589359734f7f62f9dc953ec558946dcdbe6951e3</a> |
| Authentihash MD5 | <a href="https://www.virustotal.com/gui/search/authentihash%253A68dbbf7551556cc1f85b2bb03549cc7a">68dbbf7551556cc1f85b2bb03549cc7a</a> || Authentihash SHA1 | <a href="https://www.virustotal.com/gui/search/authentihash%253A21dcf78975dc9df6628e8624a56408ac66dd5218">21dcf78975dc9df6628e8624a56408ac66dd5218</a> || Authentihash SHA256 | <a href="https://www.virustotal.com/gui/search/authentihash%253A539aa921b5352ab385430e1608ac5c0ae36f35e678d471b7a5994ec7c02eadea">539aa921b5352ab385430e1608ac5c0ae36f35e678d471b7a5994ec7c02eadea</a> || Publisher | CPUID || Signature | CPUID, VeriSign Class 3 Code Signing 2004 CA, VeriSign Class 3 Public Primary CA   || Company | Windows (R) Server 2003 DDK provider || Description | CPUID Driver || Product | Windows (R) Server 2003 DDK driver || OriginalFilename | cpuz.sys |
#### Imports
{{< details "Expand" >}}* ntoskrnl.exe
* HAL.dll
{{< /details >}}
#### ImportedFunctions
{{< details "Expand" >}}* IoDeleteDevice
* IoDeleteSymbolicLink
* RtlInitUnicodeString
* MmMapIoSpace
* IoCreateSymbolicLink
* IoCreateDevice
* RtlUnwindEx
* MmUnmapIoSpace
* PsGetVersion
* IofCompleteRequest
* HalSetBusDataByOffset
* HalGetBusDataByOffset
{{< /details >}}
#### ExportedFunctions
{{< details "Expand" >}}{{< /details >}}



[*source*](https://github.com/magicsword-io/LOLDrivers/tree/main/yaml/cpuz_x64.yaml)

*last_updated:* 2023-04-16








{{< /column >}}
{{< /block >}}
