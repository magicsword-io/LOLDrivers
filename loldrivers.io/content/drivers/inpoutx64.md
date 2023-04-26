+++

description = ""
title = "inpoutx64.sys"
weight = 10

+++


{{< block "grid-1" >}}
{{< column "mt-2 pt-1">}}


# inpoutx64.sys ![:inline](/images/twitter_verified.png) 


### Description

inpoutx64.sys is a vulnerable driver and more information will be added as found.

- **Created**: 2023-01-09
- **Author**: Michael Haag
- **Acknowledgement**:  | [](https://twitter.com/)

{{< button "https://github.com/magicsword-io/LOLDrivers/raw/main/drivers/4d487f77be4471900d6ccbc47242cc25.bin" "Download" >}}
{{< tip "warning" >}}
This download link contains the vulnerable driver!

{{< /tip >}}

### Commands

```
sc.exe create inpoutx64.sys binPath=C:\windows\temp\inpoutx64.sys type=kernel &amp;&amp; sc.exe start inpoutx64.sys
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
| Filename           | inpoutx64.sys |
| MD5                | [4d487f77be4471900d6ccbc47242cc25](https://www.virustotal.com/gui/file/4d487f77be4471900d6ccbc47242cc25) |
| SHA1               | [cc0e0440adc058615e31e8a52372abadf658e6b1](https://www.virustotal.com/gui/file/cc0e0440adc058615e31e8a52372abadf658e6b1) |
| SHA256             | [2d83ccb1ad9839c9f5b3f10b1f856177df1594c66cbbc7661677d4b462ebf44d](https://www.virustotal.com/gui/file/2d83ccb1ad9839c9f5b3f10b1f856177df1594c66cbbc7661677d4b462ebf44d) |
| Authentihash MD5   | [c21e45ae33d6b1f864a276a13ba3aaeb](https://www.virustotal.com/gui/search/authentihash%253Ac21e45ae33d6b1f864a276a13ba3aaeb) |
| Authentihash SHA1  | [94b9b91a2acc786b54e8dbc11b759b05bc15fc3f](https://www.virustotal.com/gui/search/authentihash%253A94b9b91a2acc786b54e8dbc11b759b05bc15fc3f) |
| Authentihash SHA256| [9f70169f9541c8f5b13d3ec1f3514cc4f2607d572ffb4c7e5a98be0856852dd8](https://www.virustotal.com/gui/search/authentihash%253A9f70169f9541c8f5b13d3ec1f3514cc4f2607d572ffb4c7e5a98be0856852dd8) |
| Signature         | RISINTECH INC., VeriSign Class 3 Code Signing 2010 CA, VeriSign   |
| Company           | Highresolution Enterprises [www.highrez.co.uk] |
| Description       | Kernel level port access driver |
| Product           | inpoutx64 Driver Version 1.2 |
| OriginalFilename  | inpoutx64.sys |


#### Imports
{{< details "Expand" >}}
* ntoskrnl.exe
* HAL.dll

{{< /details >}}
#### ImportedFunctions
{{< details "Expand" >}}
* RtlInitUnicodeString
* IoDeleteDevice
* ZwUnmapViewOfSection
* ZwClose
* IofCompleteRequest
* ZwMapViewOfSection
* IoCreateSymbolicLink
* IoCreateDevice
* ZwOpenSection
* KeBugCheckEx
* ObReferenceObjectByHandle
* IoDeleteSymbolicLink
* HalTranslateBusAddress

{{< /details >}}
#### ExportedFunctions
{{< details "Expand" >}}

{{< /details >}}
-----
| Property           | Value |
|:-------------------|:------|
| Filename           | inpoutx64.sys |
| MD5                | [5ca1922ed5ee2b533b5f3dd9be20fd9a](https://www.virustotal.com/gui/file/5ca1922ed5ee2b533b5f3dd9be20fd9a) |
| SHA1               | [5520ac25d81550a255dc16a0bb89d4b275f6f809](https://www.virustotal.com/gui/file/5520ac25d81550a255dc16a0bb89d4b275f6f809) |
| SHA256             | [f581decc2888ef27ee1ea85ea23bbb5fb2fe6a554266ff5a1476acd1d29d53af](https://www.virustotal.com/gui/file/f581decc2888ef27ee1ea85ea23bbb5fb2fe6a554266ff5a1476acd1d29d53af) |
| Authentihash MD5   | [c21e45ae33d6b1f864a276a13ba3aaeb](https://www.virustotal.com/gui/search/authentihash%253Ac21e45ae33d6b1f864a276a13ba3aaeb) |
| Authentihash SHA1  | [94b9b91a2acc786b54e8dbc11b759b05bc15fc3f](https://www.virustotal.com/gui/search/authentihash%253A94b9b91a2acc786b54e8dbc11b759b05bc15fc3f) |
| Authentihash SHA256| [9f70169f9541c8f5b13d3ec1f3514cc4f2607d572ffb4c7e5a98be0856852dd8](https://www.virustotal.com/gui/search/authentihash%253A9f70169f9541c8f5b13d3ec1f3514cc4f2607d572ffb4c7e5a98be0856852dd8) |
| Signature         | RISINTECH INC., VeriSign Class 3 Code Signing 2010 CA, VeriSign   |
| Company           | Highresolution Enterprises [www.highrez.co.uk] |
| Description       | Kernel level port access driver |
| Product           | inpoutx64 Driver Version 1.2 |
| OriginalFilename  | inpoutx64.sys |


#### Imports
{{< details "Expand" >}}
* ntoskrnl.exe
* HAL.dll

{{< /details >}}
#### ImportedFunctions
{{< details "Expand" >}}
* RtlInitUnicodeString
* IoDeleteDevice
* ZwUnmapViewOfSection
* ZwClose
* IofCompleteRequest
* ZwMapViewOfSection
* IoCreateSymbolicLink
* IoCreateDevice
* ZwOpenSection
* KeBugCheckEx
* ObReferenceObjectByHandle
* IoDeleteSymbolicLink
* HalTranslateBusAddress

{{< /details >}}
#### ExportedFunctions
{{< details "Expand" >}}

{{< /details >}}
-----
| Property           | Value |
|:-------------------|:------|
| Filename           | inpoutx64.sys |
| MD5                | [9321a61a25c7961d9f36852ecaa86f55](https://www.virustotal.com/gui/file/9321a61a25c7961d9f36852ecaa86f55) |
| SHA1               | [6afc6b04cf73dd461e4a4956365f25c1f1162387](https://www.virustotal.com/gui/file/6afc6b04cf73dd461e4a4956365f25c1f1162387) |
| SHA256             | [f8965fdce668692c3785afa3559159f9a18287bc0d53abb21902895a8ecf221b](https://www.virustotal.com/gui/file/f8965fdce668692c3785afa3559159f9a18287bc0d53abb21902895a8ecf221b) |
| Authentihash MD5   | [ad4eff45cdb0b12af3990945afff9a8f](https://www.virustotal.com/gui/search/authentihash%253Aad4eff45cdb0b12af3990945afff9a8f) |
| Authentihash SHA1  | [8e1f51761f21148f68ac925cc5f9e9c78f3d5ec4](https://www.virustotal.com/gui/search/authentihash%253A8e1f51761f21148f68ac925cc5f9e9c78f3d5ec4) |
| Authentihash SHA256| [d61ce5874adb89b4e992df8df879b568d9c4136df568718a768cd807d789a726](https://www.virustotal.com/gui/search/authentihash%253Ad61ce5874adb89b4e992df8df879b568d9c4136df568718a768cd807d789a726) |
| Signature         | Red Fox UK Limited, VeriSign Class 3 Code Signing 2004 CA, VeriSign Class 3 Public Primary CA   |
| Company           | Highresolution Enterprises [www.highrez.co.uk] |
| Description       | Kernel level port access driver |
| Product           | inpoutx64 Driver Version 1.2 |
| OriginalFilename  | inpoutx64.sys |


#### Imports
{{< details "Expand" >}}
* ntoskrnl.exe
* HAL.dll

{{< /details >}}
#### ImportedFunctions
{{< details "Expand" >}}
* IoDeleteSymbolicLink
* RtlInitUnicodeString
* ZwClose
* ZwMapViewOfSection
* ObReferenceObjectByHandle
* IoDeleteDevice
* ZwUnmapViewOfSection
* IoCreateSymbolicLink
* IoCreateDevice
* KeBugCheckEx
* ZwOpenSection
* IofCompleteRequest
* HalTranslateBusAddress

{{< /details >}}
#### ExportedFunctions
{{< details "Expand" >}}

{{< /details >}}
-----



[*source*](https://github.com/magicsword-io/LOLDrivers/tree/main/yaml/inpoutx64.yaml)

*last_updated:* 2023-04-26








{{< /column >}}
{{< /block >}}
