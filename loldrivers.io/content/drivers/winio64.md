+++

description = ""
title = "winio64.sys"
weight = 10

+++


{{< block "grid-1" >}}
{{< column "mt-2 pt-1">}}


# winio64.sys ![:inline](/images/twitter_verified.png) 


### Description

winio64.sys is a vulnerable driver and more information will be added as found.

- **Created**: 2023-01-09
- **Author**: Michael Haag
- **Acknowledgement**:  | [](https://twitter.com/)

{{< button "https://github.com/magicsword-io/LOLDrivers/raw/main/drivers/97221e16e7a99a00592ca278c49ffbfc.bin" "Download" >}}
{{< tip "warning" >}}
This download link contains the vulnerable driver!

{{< /tip >}}

### Commands

```
sc.exe create winio64.sys binPath=C:\windows\temp\winio64.sys type=kernel &amp;&amp; sc.exe start winio64.sys
```

| Use Case | Privileges | Operating System | 
|:---- | ---- | ---- |
| Elevate privileges | kernel | Windows 10 |

### Resources
<br>
<li><a href=" https://github.com/elastic/protections-artifacts/search?q=VulnDriver"> https://github.com/elastic/protections-artifacts/search?q=VulnDriver</a></li>
<li><a href="https://github.com/elastic/protections-artifacts/search?q=VulnDriver">https://github.com/elastic/protections-artifacts/search?q=VulnDriver</a></li>
<br>

### Known Vulnerable Samples

| Property           | Value |
|:-------------------|:------|
| Filename           | winio64.sys |
| MD5                | [97221e16e7a99a00592ca278c49ffbfc](https://www.virustotal.com/gui/file/97221e16e7a99a00592ca278c49ffbfc) |
| SHA1               | [943593e880b4d340f2548548e6e673ef6f61eed3](https://www.virustotal.com/gui/file/943593e880b4d340f2548548e6e673ef6f61eed3) |
| SHA256             | [e1980c6592e6d2d92c1a65acad8f1071b6a404097bb6fcce494f3c8ac31385cf](https://www.virustotal.com/gui/file/e1980c6592e6d2d92c1a65acad8f1071b6a404097bb6fcce494f3c8ac31385cf) |
| Authentihash MD5   | [241252e4ebe7b4fdf6fd5a34ece5b127](https://www.virustotal.com/gui/search/authentihash%253A241252e4ebe7b4fdf6fd5a34ece5b127) |
| Authentihash SHA1  | [eaba3ed3a83a8ef75db88c1f0def5160c3835a8c](https://www.virustotal.com/gui/search/authentihash%253Aeaba3ed3a83a8ef75db88c1f0def5160c3835a8c) |
| Authentihash SHA256| [cb5ebba562c33ef2ed93558913792726c8c2e5898531923589122ae31db64ebb](https://www.virustotal.com/gui/search/authentihash%253Acb5ebba562c33ef2ed93558913792726c8c2e5898531923589122ae31db64ebb) |
| Signature         | Exacq Technologies, Inc., StartCom Class 3 Primary Intermediate Object CA, StartCom Certification Authority   |


#### Imports
{{< details "Expand" >}}
* ntoskrnl.exe
* HAL.dll
* WDFLDR.SYS

{{< /details >}}
#### ImportedFunctions
{{< details "Expand" >}}
* ObfDereferenceObject
* ZwClose
* ZwOpenSection
* ObReferenceObjectByHandle
* ZwUnmapViewOfSection
* KeBugCheckEx
* IoDeleteSymbolicLink
* IoDeleteDevice
* RtlCopyUnicodeString
* IoCreateSymbolicLink
* IoCreateDevice
* IofCompleteRequest
* ZwMapViewOfSection
* RtlInitUnicodeString
* HalTranslateBusAddress
* WdfVersionUnbind
* WdfVersionBind
* WdfVersionBindClass
* WdfVersionUnbindClass

{{< /details >}}
#### ExportedFunctions
{{< details "Expand" >}}

{{< /details >}}| Property           | Value |
|:-------------------|:------|
| Filename           | winio64.sys |
| MD5                | [11fb599312cb1cf43ca5e879ed6fb71e](https://www.virustotal.com/gui/file/11fb599312cb1cf43ca5e879ed6fb71e) |
| SHA1               | [b4d014b5edd6e19ce0e8395a64faedf49688ecb5](https://www.virustotal.com/gui/file/b4d014b5edd6e19ce0e8395a64faedf49688ecb5) |
| SHA256             | [9fc29480407e5179aa8ea41682409b4ea33f1a42026277613d6484e5419de374](https://www.virustotal.com/gui/file/9fc29480407e5179aa8ea41682409b4ea33f1a42026277613d6484e5419de374) |
| Authentihash MD5   | [198111fd73515aa7fe4387612f027f0f](https://www.virustotal.com/gui/search/authentihash%253A198111fd73515aa7fe4387612f027f0f) |
| Authentihash SHA1  | [651b953cb03928e41424ad59f21d4978d6f4952e](https://www.virustotal.com/gui/search/authentihash%253A651b953cb03928e41424ad59f21d4978d6f4952e) |
| Authentihash SHA256| [ebbaa44277a3ec6e20ad3f6aef5399fdc398306eb4c13aa96e45c9a281820a12](https://www.virustotal.com/gui/search/authentihash%253Aebbaa44277a3ec6e20ad3f6aef5399fdc398306eb4c13aa96e45c9a281820a12) |
| Signature         | Microsoft Windows Hardware Compatibility Publisher, Microsoft Windows Third Party Component CA 2014, Microsoft Root Certificate Authority 2010   |


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
* ObReferenceObjectByHandle
* ZwMapViewOfSection
* ObfDereferenceObject
* IoCreateDevice
* RtlAssert
* ZwOpenSection
* DbgPrint
* KeBugCheckEx
* IoCreateSymbolicLink
* IoDeleteSymbolicLink
* HalTranslateBusAddress

{{< /details >}}
#### ExportedFunctions
{{< details "Expand" >}}

{{< /details >}}


[*source*](https://github.com/magicsword-io/LOLDrivers/tree/main/yaml/winio64.yaml)

*last_updated:* 2023-04-19








{{< /column >}}
{{< /block >}}
