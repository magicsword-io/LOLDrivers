+++

description = ""
title = "WINIODrv.sys"
weight = 10

+++


{{< block "grid-1" >}}
{{< column "mt-2 pt-1">}}


# WINIODrv.sys ![:inline](/images/twitter_verified.png) 


### Description

WINIODrv.sys is a vulnerable driver and more information will be added as found.

- **Created**: 2023-01-09
- **Author**: Michael Haag
- **Acknowledgement**:  | [](https://twitter.com/)

{{< button "https://github.com/magicsword-io/LOLDrivers/raw/main/drivers/a86150f2e29b35369afa2cafd7aa9764.bin" "Download" >}}
{{< tip "warning" >}}
This download link contains the vulnerable driver!

{{< /tip >}}

### Commands

```
sc.exe create WINIODrv.sys binPath=C:\windows\temp\WINIODrv.sys type=kernel &amp;&amp; sc.exe start WINIODrv.sys
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
| Filename           | WINIODrv.sys |
| MD5                | [a86150f2e29b35369afa2cafd7aa9764](https://www.virustotal.com/gui/file/a86150f2e29b35369afa2cafd7aa9764) |
| SHA1               | [460008b1ffd31792a6deadfa6280fb2a30c8a5d2](https://www.virustotal.com/gui/file/460008b1ffd31792a6deadfa6280fb2a30c8a5d2) |
| SHA256             | [3243aab18e273a9b9c4280a57aecef278e10bfff19abb260d7a7820e41739099](https://www.virustotal.com/gui/file/3243aab18e273a9b9c4280a57aecef278e10bfff19abb260d7a7820e41739099) |
| Authentihash MD5   | [83510d09c4d0f9f56c0d6caf40ee63cb](https://www.virustotal.com/gui/search/authentihash%253A83510d09c4d0f9f56c0d6caf40ee63cb) |
| Authentihash SHA1  | [40cc2318ffffd458023c8cd1e285a5ad51adf538](https://www.virustotal.com/gui/search/authentihash%253A40cc2318ffffd458023c8cd1e285a5ad51adf538) |
| Authentihash SHA256| [b3cbb2b364a494f096e68dc48cca89799ed27e6b97b17633036e363a98fd4421](https://www.virustotal.com/gui/search/authentihash%253Ab3cbb2b364a494f096e68dc48cca89799ed27e6b97b17633036e363a98fd4421) |
| Signature         | Partner Tech(Shanghai)Co.,Ltd, VeriSign Class 3 Code Signing 2010 CA, VeriSign   |


#### Imports
{{< details "Expand" >}}
* ntoskrnl.exe
* HAL.dll

{{< /details >}}
#### ImportedFunctions
{{< details "Expand" >}}
* IoCreateDevice
* IoCreateSymbolicLink
* IoDeleteDevice
* IoDeleteSymbolicLink
* ObReferenceObjectByHandle
* IofCompleteRequest
* ZwClose
* ZwOpenSection
* ZwMapViewOfSection
* ZwUnmapViewOfSection
* ObfDereferenceObject
* RtlInitUnicodeString
* HalTranslateBusAddress

{{< /details >}}
#### ExportedFunctions
{{< details "Expand" >}}

{{< /details >}}
-----
| Property           | Value |
|:-------------------|:------|
| Filename           | WINIODrv.sys |
| MD5                | [ad22a7b010de6f9c6f39c350a471a440](https://www.virustotal.com/gui/file/ad22a7b010de6f9c6f39c350a471a440) |
| SHA1               | [738b7918d85e5cb4395df9e3f6fc94ddad90e939](https://www.virustotal.com/gui/file/738b7918d85e5cb4395df9e3f6fc94ddad90e939) |
| SHA256             | [7cfa5e10dff8a99a5d544b011f676bc383991274c693e21e3af40cf6982adb8c](https://www.virustotal.com/gui/file/7cfa5e10dff8a99a5d544b011f676bc383991274c693e21e3af40cf6982adb8c) |
| Authentihash MD5   | [792b743c370ad28281edd4801b22a31e](https://www.virustotal.com/gui/search/authentihash%253A792b743c370ad28281edd4801b22a31e) |
| Authentihash SHA1  | [80ca9c9cce4b5e6afb92a56b5bfd954eca0ff690](https://www.virustotal.com/gui/search/authentihash%253A80ca9c9cce4b5e6afb92a56b5bfd954eca0ff690) |
| Authentihash SHA256| [9199979b9f3ea2108299d028373a6effcc41c81a46eecb430cc6653211d2913d](https://www.virustotal.com/gui/search/authentihash%253A9199979b9f3ea2108299d028373a6effcc41c81a46eecb430cc6653211d2913d) |
| Signature         | Partner Tech(Shanghai)Co.,Ltd, VeriSign Class 3 Code Signing 2010 CA, VeriSign   |


#### Imports
{{< details "Expand" >}}
* ntoskrnl.exe
* HAL.dll

{{< /details >}}
#### ImportedFunctions
{{< details "Expand" >}}
* IoCreateDevice
* IoCreateSymbolicLink
* IoDeleteDevice
* IoDeleteSymbolicLink
* ObReferenceObjectByHandle
* IofCompleteRequest
* ZwClose
* ZwOpenSection
* ZwMapViewOfSection
* ZwUnmapViewOfSection
* ObfDereferenceObject
* RtlInitUnicodeString
* HalTranslateBusAddress

{{< /details >}}
#### ExportedFunctions
{{< details "Expand" >}}

{{< /details >}}
-----
| Property           | Value |
|:-------------------|:------|
| Filename           | WINIODrv.sys |
| MD5                | [0761c357aed5f591142edaefdf0c89c8](https://www.virustotal.com/gui/file/0761c357aed5f591142edaefdf0c89c8) |
| SHA1               | [43419df1f9a07430a18c5f3b3cc74de621be0f8e](https://www.virustotal.com/gui/file/43419df1f9a07430a18c5f3b3cc74de621be0f8e) |
| SHA256             | [c9b49b52b493b53cd49c12c3fa9553e57c5394555b64e32d1208f5b96a5b8c6e](https://www.virustotal.com/gui/file/c9b49b52b493b53cd49c12c3fa9553e57c5394555b64e32d1208f5b96a5b8c6e) |
| Authentihash MD5   | [b2fc995c9a92965a53437c30b53d7096](https://www.virustotal.com/gui/search/authentihash%253Ab2fc995c9a92965a53437c30b53d7096) |
| Authentihash SHA1  | [c21043466942961203e751c9cebcd159e661fa1a](https://www.virustotal.com/gui/search/authentihash%253Ac21043466942961203e751c9cebcd159e661fa1a) |
| Authentihash SHA256| [961012d06eeaabd9eff9b36173e566bf148a5c8f743f3329c70d8918eba26093](https://www.virustotal.com/gui/search/authentihash%253A961012d06eeaabd9eff9b36173e566bf148a5c8f743f3329c70d8918eba26093) |
| Signature         | Partner Tech(Shanghai)Co.,Ltd, VeriSign Class 3 Code Signing 2010 CA, VeriSign   |


#### Imports
{{< details "Expand" >}}
* ntoskrnl.exe
* HAL.dll

{{< /details >}}
#### ImportedFunctions
{{< details "Expand" >}}
* IoCreateDevice
* IoCreateSymbolicLink
* IoDeleteDevice
* IoDeleteSymbolicLink
* ObReferenceObjectByHandle
* IofCompleteRequest
* ZwClose
* ZwOpenSection
* ZwMapViewOfSection
* ZwUnmapViewOfSection
* ObfDereferenceObject
* RtlInitUnicodeString
* HalTranslateBusAddress

{{< /details >}}
#### ExportedFunctions
{{< details "Expand" >}}

{{< /details >}}
-----



[*source*](https://github.com/magicsword-io/LOLDrivers/tree/main/yaml/winiodrv.yaml)

*last_updated:* 2023-04-20








{{< /column >}}
{{< /block >}}
