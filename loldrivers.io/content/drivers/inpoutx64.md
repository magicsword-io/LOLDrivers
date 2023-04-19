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

| Filename | inpoutx64.sys |
|:---- | ---- | 
| MD5 | <a href="https://www.virustotal.com/gui/file/4d487f77be4471900d6ccbc47242cc25">4d487f77be4471900d6ccbc47242cc25</a> |
| SHA1 | <a href="https://www.virustotal.com/gui/file/cc0e0440adc058615e31e8a52372abadf658e6b1">cc0e0440adc058615e31e8a52372abadf658e6b1</a> |
| SHA256 | <a href="https://www.virustotal.com/gui/file/2d83ccb1ad9839c9f5b3f10b1f856177df1594c66cbbc7661677d4b462ebf44d">2d83ccb1ad9839c9f5b3f10b1f856177df1594c66cbbc7661677d4b462ebf44d</a> |
| Authentihash MD5 | <a href="https://www.virustotal.com/gui/search/authentihash%253Ac21e45ae33d6b1f864a276a13ba3aaeb">c21e45ae33d6b1f864a276a13ba3aaeb</a> || Authentihash SHA1 | <a href="https://www.virustotal.com/gui/search/authentihash%253A94b9b91a2acc786b54e8dbc11b759b05bc15fc3f">94b9b91a2acc786b54e8dbc11b759b05bc15fc3f</a> || Authentihash SHA256 | <a href="https://www.virustotal.com/gui/search/authentihash%253A9f70169f9541c8f5b13d3ec1f3514cc4f2607d572ffb4c7e5a98be0856852dd8">9f70169f9541c8f5b13d3ec1f3514cc4f2607d572ffb4c7e5a98be0856852dd8</a> || Signature | RISINTECH INC., VeriSign Class 3 Code Signing 2010 CA, VeriSign   || Company | Highresolution Enterprises [www.highrez.co.uk] || Description | Kernel level port access driver || Product | inpoutx64 Driver Version 1.2 || OriginalFilename | inpoutx64.sys |
#### Imports
{{< details "Expand" >}}* ntoskrnl.exe
* HAL.dll
{{< /details >}}
#### ImportedFunctions
{{< details "Expand" >}}* RtlInitUnicodeString
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
{{< details "Expand" >}}{{< /details >}}
| Filename | inpoutx64.sys |
|:---- | ---- | 
| MD5 | <a href="https://www.virustotal.com/gui/file/5ca1922ed5ee2b533b5f3dd9be20fd9a">5ca1922ed5ee2b533b5f3dd9be20fd9a</a> |
| SHA1 | <a href="https://www.virustotal.com/gui/file/5520ac25d81550a255dc16a0bb89d4b275f6f809">5520ac25d81550a255dc16a0bb89d4b275f6f809</a> |
| SHA256 | <a href="https://www.virustotal.com/gui/file/f581decc2888ef27ee1ea85ea23bbb5fb2fe6a554266ff5a1476acd1d29d53af">f581decc2888ef27ee1ea85ea23bbb5fb2fe6a554266ff5a1476acd1d29d53af</a> |
| Authentihash MD5 | <a href="https://www.virustotal.com/gui/search/authentihash%253Ac21e45ae33d6b1f864a276a13ba3aaeb">c21e45ae33d6b1f864a276a13ba3aaeb</a> || Authentihash SHA1 | <a href="https://www.virustotal.com/gui/search/authentihash%253A94b9b91a2acc786b54e8dbc11b759b05bc15fc3f">94b9b91a2acc786b54e8dbc11b759b05bc15fc3f</a> || Authentihash SHA256 | <a href="https://www.virustotal.com/gui/search/authentihash%253A9f70169f9541c8f5b13d3ec1f3514cc4f2607d572ffb4c7e5a98be0856852dd8">9f70169f9541c8f5b13d3ec1f3514cc4f2607d572ffb4c7e5a98be0856852dd8</a> || Signature | RISINTECH INC., VeriSign Class 3 Code Signing 2010 CA, VeriSign   || Company | Highresolution Enterprises [www.highrez.co.uk] || Description | Kernel level port access driver || Product | inpoutx64 Driver Version 1.2 || OriginalFilename | inpoutx64.sys |
#### Imports
{{< details "Expand" >}}* ntoskrnl.exe
* HAL.dll
{{< /details >}}
#### ImportedFunctions
{{< details "Expand" >}}* RtlInitUnicodeString
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
{{< details "Expand" >}}{{< /details >}}
| Filename | inpoutx64.sys |
|:---- | ---- | 
| MD5 | <a href="https://www.virustotal.com/gui/file/9321a61a25c7961d9f36852ecaa86f55">9321a61a25c7961d9f36852ecaa86f55</a> |
| SHA1 | <a href="https://www.virustotal.com/gui/file/6afc6b04cf73dd461e4a4956365f25c1f1162387">6afc6b04cf73dd461e4a4956365f25c1f1162387</a> |
| SHA256 | <a href="https://www.virustotal.com/gui/file/f8965fdce668692c3785afa3559159f9a18287bc0d53abb21902895a8ecf221b">f8965fdce668692c3785afa3559159f9a18287bc0d53abb21902895a8ecf221b</a> |
| Authentihash MD5 | <a href="https://www.virustotal.com/gui/search/authentihash%253Aad4eff45cdb0b12af3990945afff9a8f">ad4eff45cdb0b12af3990945afff9a8f</a> || Authentihash SHA1 | <a href="https://www.virustotal.com/gui/search/authentihash%253A8e1f51761f21148f68ac925cc5f9e9c78f3d5ec4">8e1f51761f21148f68ac925cc5f9e9c78f3d5ec4</a> || Authentihash SHA256 | <a href="https://www.virustotal.com/gui/search/authentihash%253Ad61ce5874adb89b4e992df8df879b568d9c4136df568718a768cd807d789a726">d61ce5874adb89b4e992df8df879b568d9c4136df568718a768cd807d789a726</a> || Signature | Red Fox UK Limited, VeriSign Class 3 Code Signing 2004 CA, VeriSign Class 3 Public Primary CA   || Company | Highresolution Enterprises [www.highrez.co.uk] || Description | Kernel level port access driver || Product | inpoutx64 Driver Version 1.2 || OriginalFilename | inpoutx64.sys |
#### Imports
{{< details "Expand" >}}* ntoskrnl.exe
* HAL.dll
{{< /details >}}
#### ImportedFunctions
{{< details "Expand" >}}* IoDeleteSymbolicLink
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
{{< details "Expand" >}}{{< /details >}}



[*source*](https://github.com/magicsword-io/LOLDrivers/tree/main/yaml/inpoutx64.yaml)

*last_updated:* 2023-04-19








{{< /column >}}
{{< /block >}}
