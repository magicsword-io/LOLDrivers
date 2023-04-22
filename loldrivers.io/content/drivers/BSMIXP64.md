+++

description = ""
title = "BSMIXP64.sys"
weight = 10

+++


{{< block "grid-1" >}}
{{< column "mt-2 pt-1">}}


# BSMIXP64.sys ![:inline](/images/twitter_verified.png) 


### Description

BSMIXP64.sys is a vulnerable driver and more information will be added as found.

- **Created**: 2023-01-09
- **Author**: Michael Haag
- **Acknowledgement**:  | [](https://twitter.com/)

{{< button "https://github.com/magicsword-io/LOLDrivers/raw/main/drivers/fac8eb49e2fd541b81fcbdeb98a199cb.bin" "Download" >}}
{{< tip "warning" >}}
This download link contains the vulnerable driver!

{{< /tip >}}

### Commands

```
sc.exe create BSMIXP64.sys binPath=C:\windows\temp\BSMIXP64.sys type=kernel &amp;&amp; sc.exe start BSMIXP64.sys
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

| Property           | Value |
|:-------------------|:------|
| Filename           | BSMIXP64.sys |
| MD5                | [fac8eb49e2fd541b81fcbdeb98a199cb](https://www.virustotal.com/gui/file/fac8eb49e2fd541b81fcbdeb98a199cb) |
| SHA1               | [9a35ae9a1f95ce4be64adc604c80079173e4a676](https://www.virustotal.com/gui/file/9a35ae9a1f95ce4be64adc604c80079173e4a676) |
| SHA256             | [59626cac380d8fe0b80a6d4c4406d62ba0683a2f0f68d50ad506ca1b1cf25347](https://www.virustotal.com/gui/file/59626cac380d8fe0b80a6d4c4406d62ba0683a2f0f68d50ad506ca1b1cf25347) |
| Authentihash MD5   | [0dea670f26bf6bf65701c4aa0dd89079](https://www.virustotal.com/gui/search/authentihash%253A0dea670f26bf6bf65701c4aa0dd89079) |
| Authentihash SHA1  | [cc071f9cc1cb577b22824d401b63508f61cd76c0](https://www.virustotal.com/gui/search/authentihash%253Acc071f9cc1cb577b22824d401b63508f61cd76c0) |
| Authentihash SHA256| [df82f155376b4e95a3f497b7362ba6039c04d2ae78926f626dbe1a459bc626d7](https://www.virustotal.com/gui/search/authentihash%253Adf82f155376b4e95a3f497b7362ba6039c04d2ae78926f626dbe1a459bc626d7) |
| Signature         | BIOSTAR MICROTECH INT&#39;L CORP, VeriSign Class 3 Code Signing 2009-2 CA, VeriSign Class 3 Public Primary CA   |
| Description       | SMI Driver |
| OriginalFilename  | BSMI.sys |


#### Imports
{{< details "Expand" >}}
* ntoskrnl.exe

{{< /details >}}
#### ImportedFunctions
{{< details "Expand" >}}
* IoDeleteSymbolicLink
* RtlInitUnicodeString
* IoDeleteDevice
* MmUnmapIoSpace
* MmGetPhysicalAddress
* MmMapIoSpace
* IofCompleteRequest
* IoCreateSymbolicLink
* IoCreateDevice
* RtlAssert
* DbgPrint
* KeBugCheckEx

{{< /details >}}
#### ExportedFunctions
{{< details "Expand" >}}

{{< /details >}}
-----



[*source*](https://github.com/magicsword-io/LOLDrivers/tree/main/yaml/bsmixp64.yaml)

*last_updated:* 2023-04-22








{{< /column >}}
{{< /block >}}
