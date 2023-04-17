+++

description = ""
title = "AsIO64.sys"
weight = 10

+++


{{< block "grid-1" >}}
{{< column "mt-2 pt-1">}}


# AsIO64.sys ![:inline](/images/twitter_verified.png) 


### Description

AsIO64.sys is a vulnerable driver and more information will be added as found.

- **Created**: 2023-01-09
- **Author**: Michael Haag
- **Acknowledgement**:  | [](https://twitter.com/)

{{< button "https://github.com/magicsword-io/LOLDrivers/raw/main/drivers/8065a7659562005127673ac52898675f.bin" "Download" >}}
{{< tip "warning" >}}
This download link contains the malcious driver!
{{< /tip >}}

### Commands

```
sc.exe create AsIO64.sys binPath=C:\windows\temp\AsIO64.sys type=kernel &amp;&amp; sc.exe start AsIO64.sys
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

| Filename | AsIO64.sys |
|:---- | ---- | 
| MD5 | <a href="https://www.virustotal.com/gui/file/8065a7659562005127673ac52898675f">8065a7659562005127673ac52898675f</a> |
| SHA1 | <a href="https://www.virustotal.com/gui/file/fcde5275ee1913509927ce5f0f85e6681064c9d2">fcde5275ee1913509927ce5f0f85e6681064c9d2</a> |
| SHA256 | <a href="https://www.virustotal.com/gui/file/b48a309ee0960da3caaaaf1e794e8c409993aeb3a2b64809f36b97aac8a1e62a">b48a309ee0960da3caaaaf1e794e8c409993aeb3a2b64809f36b97aac8a1e62a</a> |
| Authentihash MD5 | <a href="https://www.virustotal.com/gui/search/authentihash%253Ad593aec08f96fe410f7a6b53e49551a0">d593aec08f96fe410f7a6b53e49551a0</a> || Authentihash SHA1 | <a href="https://www.virustotal.com/gui/search/authentihash%253A2ea631bfe3fd765e3a03b3165790faf8fdd8286b">2ea631bfe3fd765e3a03b3165790faf8fdd8286b</a> || Authentihash SHA256 | <a href="https://www.virustotal.com/gui/search/authentihash%253A906d8412b357379db9512e3f584fcda1f788acc1337e5b4d4eff5e6fa59324a6">906d8412b357379db9512e3f584fcda1f788acc1337e5b4d4eff5e6fa59324a6</a> || Publisher | ASUSTeK Computer Inc. || Signature | ASUSTeK Computer Inc., VeriSign Class 3 Code Signing 2004 CA, VeriSign Class 3 Public Primary CA   |
#### Imports
{{< details "Expand" >}}* ntoskrnl.exe
* HAL.dll
{{< /details >}}
#### ImportedFunctions
{{< details "Expand" >}}* ZwClose
* ZwMapViewOfSection
* ObReferenceObjectByHandle
* ZwOpenSection
* RtlInitUnicodeString
* IoDeleteDevice
* KeDelayExecutionThread
* IofCompleteRequest
* ZwUnmapViewOfSection
* IoIs32bitProcess
* IoCreateSymbolicLink
* IoCreateDevice
* IoDeleteSymbolicLink
* DbgPrint
* HalTranslateBusAddress
{{< /details >}}
#### ExportedFunctions
{{< details "Expand" >}}{{< /details >}}



[*source*](https://github.com/magicsword-io/LOLDrivers/tree/main/yaml/asio64.yaml)

*last_updated:* 2023-04-17








{{< /column >}}
{{< /block >}}
