+++

description = ""
title = "EneTechIo64.sys"
weight = 10

+++


{{< block "grid-1" >}}
{{< column "mt-2 pt-1">}}


# EneTechIo64.sys ![:inline](/images/twitter_verified.png) 


### Description

EneTechIo64.sys is a vulnerable driver and more information will be added as found.

- **Created**: 2023-01-09
- **Author**: Michael Haag
- **Acknowledgement**:  | [](https://twitter.com/)


{{< button "https://github.com/magicsword-io/LOLDrivers/raw/main/drivers/0ae30291c6cbfa7be39320badd6e8de0.bin" "Download" >}}

{{< tip "warning" >}}
This download link contains the malcious driver!
{{< /tip >}}

### Commands

```
sc.exe create EneTechIo64.sys binPath=C:\windows\temp\EneTechIo64.sys     type=kernel type=kernel &amp;&amp; sc.exe start EneTechIo64.sys
```

| Use Case | Privileges | Operating System | 
|:---- | ---- | ---- |
| Elevate privileges | kernel | Windows 10 |

### Resources
<br>
<li><a href=" https://gist.github.com/k4nfr3/af970e7facb09195e56f2112e1c9549c"> https://gist.github.com/k4nfr3/af970e7facb09195e56f2112e1c9549c</a></li>
<li><a href="https://github.com/hfiref0x/KDU/releases/tag/v1.2.0">https://github.com/hfiref0x/KDU/releases/tag/v1.2.0</a></li>
<li><a href="https://gist.github.com/k4nfr3/af970e7facb09195e56f2112e1c9549c">https://gist.github.com/k4nfr3/af970e7facb09195e56f2112e1c9549c</a></li>
<br>

### Known Vulnerable Samples

| Filename | EneTechIo64.sys |
|:---- | ---- | 
| MD5 | <a href="https://www.virustotal.com/gui/file/d6e9f6c67d9b3d790d592557a7d57c3c">d6e9f6c67d9b3d790d592557a7d57c3c</a> |
| SHA1 | <a href="https://www.virustotal.com/gui/file/a87d6eac2d70a3fbc04e59412326b28001c179de">a87d6eac2d70a3fbc04e59412326b28001c179de</a> |
| SHA256 | <a href="https://www.virustotal.com/gui/file/06bda5a1594f7121acd2efe38ccb617fbc078bb9a70b665a5f5efd70e3013f50">06bda5a1594f7121acd2efe38ccb617fbc078bb9a70b665a5f5efd70e3013f50</a> |
| Authentihash MD5 | <a href="https://www.virustotal.com/gui/search/authentihash%0765c07a666231285972c3487acfc7b2">0765c07a666231285972c3487acfc7b2</a> || Authentihash SHA1 | <a href="https://www.virustotal.com/gui/search/authentihash%6b60825564b2dccff3a4f904b71541bfe94136c9">6b60825564b2dccff3a4f904b71541bfe94136c9</a> || Authentihash SHA256 | <a href="https://www.virustotal.com/gui/search/authentihash%865e4bc7290fc3b380e266ccd98c2d4e965beb711d7efd090d052e8326accdd2">865e4bc7290fc3b380e266ccd98c2d4e965beb711d7efd090d052e8326accdd2</a> || Signature | Microsoft Windows Hardware Compatibility Publisher, Microsoft Windows Third Party Component CA 2014, Microsoft Root Certificate Authority 2010   |
#### Imports
{{< details "Expand" >}}* ntoskrnl.exe
* HAL.dll
{{< /details >}}
#### ImportedFunctions
{{< details "Expand" >}}* IoCreateDevice
* IoCreateSymbolicLink
* IoDeleteDevice
* IoDeleteSymbolicLink
* ObReferenceObjectByHandle
* IofCompleteRequest
* ZwClose
* ZwOpenSection
* ZwMapViewOfSection
* ZwUnmapViewOfSection
* RtlTimeToSecondsSince1970
* KeBugCheckEx
* ObfDereferenceObject
* RtlInitUnicodeString
* HalTranslateBusAddress
{{< /details >}}
#### ExportedFunctions
{{< details "Expand" >}}{{< /details >}}



[*source*](https://github.com/magicsword-io/LOLDrivers/tree/main/yaml/enetechio64.yaml)

*last_updated:* 2023-04-15








{{< /column >}}
{{< /block >}}
