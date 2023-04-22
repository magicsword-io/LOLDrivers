+++

description = ""
title = "Se64a.sys"
weight = 10

+++


{{< block "grid-1" >}}
{{< column "mt-2 pt-1">}}


# Se64a.sys ![:inline](/images/twitter_verified.png) 


### Description

Se64a.sys is a vulnerable driver and more information will be added as found.

- **Created**: 2023-01-09
- **Author**: Michael Haag
- **Acknowledgement**:  | [](https://twitter.com/)

{{< button "https://github.com/magicsword-io/LOLDrivers/raw/main/drivers/0a6a1c9a7f80a2a5dcced5c4c0473765.bin" "Download" >}}
{{< tip "warning" >}}
This download link contains the vulnerable driver!

{{< /tip >}}

### Commands

```
sc.exe create Se64a.sys binPath=C:\windows\temp\Se64a.sys type=kernel &amp;&amp; sc.exe start Se64a.sys
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
| Filename           | Se64a.sys |
| MD5                | [0a6a1c9a7f80a2a5dcced5c4c0473765](https://www.virustotal.com/gui/file/0a6a1c9a7f80a2a5dcced5c4c0473765) |
| SHA1               | [33285b2e97a0aeb317166cce91f6733cf9c1ad53](https://www.virustotal.com/gui/file/33285b2e97a0aeb317166cce91f6733cf9c1ad53) |
| SHA256             | [6cb51ae871fbd5d07c5aad6ff8eea43d34063089528603ca9ceb8b4f52f68ddc](https://www.virustotal.com/gui/file/6cb51ae871fbd5d07c5aad6ff8eea43d34063089528603ca9ceb8b4f52f68ddc) |
| Authentihash MD5   | [46f46abcb9e3ba747c2a2904babe38c0](https://www.virustotal.com/gui/search/authentihash%253A46f46abcb9e3ba747c2a2904babe38c0) |
| Authentihash SHA1  | [a4e8e3268569acc0a0b3f6eada713c0fa8825463](https://www.virustotal.com/gui/search/authentihash%253Aa4e8e3268569acc0a0b3f6eada713c0fa8825463) |
| Authentihash SHA256| [04cfb452e1ac73fb2f3b8a80d9f27e19a344a6bf0f74c7f9cae3ae82d3770195](https://www.virustotal.com/gui/search/authentihash%253A04cfb452e1ac73fb2f3b8a80d9f27e19a344a6bf0f74c7f9cae3ae82d3770195) |
| Signature         | EnTech Taiwan, GlobalSign ObjectSign CA, GlobalSign Primary Object Publishing CA, GlobalSign Root CA - R1   |
| Company           | EnTech Taiwan |
| Description       | EnTech softEngine x64 kernel-mode driver |
| Product           | softEngine-x64 |
| OriginalFilename  | se64a.sys |


#### Imports
{{< details "Expand" >}}
* ntoskrnl.exe
* HAL.dll

{{< /details >}}
#### ImportedFunctions
{{< details "Expand" >}}
* ZwOpenSection
* RtlInitUnicodeString
* DbgPrint
* IofCompleteRequest
* ZwUnmapViewOfSection
* RtlCopyMemory
* ObReferenceObjectByHandle
* KeEnterCriticalRegion
* IoDeleteDevice
* IoDeleteSymbolicLink
* IoCreateSymbolicLink
* IoCreateDevice
* ZwMapViewOfSection
* KeLeaveCriticalRegion
* ZwClose
* HalTranslateBusAddress
* HalGetBusDataByOffset

{{< /details >}}
#### ExportedFunctions
{{< details "Expand" >}}

{{< /details >}}
-----



[*source*](https://github.com/magicsword-io/LOLDrivers/tree/main/yaml/se64a.yaml)

*last_updated:* 2023-04-22








{{< /column >}}
{{< /block >}}
