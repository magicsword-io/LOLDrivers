+++

description = ""
title = "WCPU.sys"
weight = 10

+++


{{< block "grid-1" >}}
{{< column "mt-2 pt-1">}}


# WCPU.sys ![:inline](/images/twitter_verified.png) 


### Description

WCPU.sys is a vulnerable driver and more information will be added as found.

- **Created**: 2023-01-09
- **Author**: Michael Haag
- **Acknowledgement**:  | [](https://twitter.com/)

{{< button "https://github.com/magicsword-io/LOLDrivers/raw/main/drivers/c1d063c9422a19944cdaa6714623f2ec.bin" "Download" >}}
{{< tip "warning" >}}
This download link contains the vulnerable driver!

{{< /tip >}}

### Commands

```
sc.exe create WCPU.sys binPath=C:\windows\temp\WCPU.sys type=kernel &amp;&amp; sc.exe start WCPU.sys
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

| Property           | Value |
|:-------------------|:------|
| Filename           | WCPU.sys |
| MD5                | [c1d063c9422a19944cdaa6714623f2ec](https://www.virustotal.com/gui/file/c1d063c9422a19944cdaa6714623f2ec) |
| SHA1               | [f36a47edfacd85e0c6d4d22133dd386aee4eec15](https://www.virustotal.com/gui/file/f36a47edfacd85e0c6d4d22133dd386aee4eec15) |
| SHA256             | [159e7c5a12157af92e0d14a0d3ea116f91c09e21a9831486e6dc592c93c10980](https://www.virustotal.com/gui/file/159e7c5a12157af92e0d14a0d3ea116f91c09e21a9831486e6dc592c93c10980) |
| Authentihash MD5   | [1a77777592eb402fe56bcb43d618d02e](https://www.virustotal.com/gui/search/authentihash%253A1a77777592eb402fe56bcb43d618d02e) |
| Authentihash SHA1  | [81e3e81048e0f323eee8d04aa9b291d77caa21e0](https://www.virustotal.com/gui/search/authentihash%253A81e3e81048e0f323eee8d04aa9b291d77caa21e0) |
| Authentihash SHA256| [54bc506b2f0cf66d12d4a2415ab743c2b2a1f3079089e3e0c0c1f3f49dd7335e](https://www.virustotal.com/gui/search/authentihash%253A54bc506b2f0cf66d12d4a2415ab743c2b2a1f3079089e3e0c0c1f3f49dd7335e) |
| Signature         | ASUSTeK Computer Inc., VeriSign Class 3 Code Signing 2004 CA, VeriSign Class 3 Public Primary CA   |
| Company           | Windows (R) Codename Longhorn DDK provider |
| Description       | ASUS TDE CPU Driver |
| Product           | Windows (R) Codename Longhorn DDK driver |
| OriginalFilename  | CPU Driver |


#### Imports
{{< details "Expand" >}}
* ntoskrnl.exe
* HAL.dll

{{< /details >}}
#### ImportedFunctions
{{< details "Expand" >}}
* ZwUnmapViewOfSection
* ZwClose
* IofCompleteRequest
* ObReferenceObjectByHandle
* IoCreateSymbolicLink
* IoDeleteDevice
* ZwOpenSection
* IoDeleteSymbolicLink
* ZwMapViewOfSection
* KeBugCheckEx
* IoCreateDevice
* RtlInitUnicodeString
* HalTranslateBusAddress

{{< /details >}}
#### ExportedFunctions
{{< details "Expand" >}}

{{< /details >}}


[*source*](https://github.com/magicsword-io/LOLDrivers/tree/main/yaml/wcpu.yaml)

*last_updated:* 2023-04-20








{{< /column >}}
{{< /block >}}
