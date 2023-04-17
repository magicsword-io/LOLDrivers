+++

description = ""
title = "nvflsh64.sys"
weight = 10

+++


{{< block "grid-1" >}}
{{< column "mt-2 pt-1">}}


# nvflsh64.sys ![:inline](/images/twitter_verified.png) 


### Description

nvflsh64.sys is a vulnerable driver and more information will be added as found.

- **Created**: 2023-01-09
- **Author**: Michael Haag
- **Acknowledgement**:  | [](https://twitter.com/)

{{< button "https://github.com/magicsword-io/LOLDrivers/raw/main/drivers/d3e40644a91327da2b1a7241606fe559.bin" "Download" >}}
{{< tip "warning" >}}
This download link contains the malcious driver!
{{< /tip >}}

### Commands

```
sc.exe create nvflsh64.sys binPath=C:\windows\temp \n \n \n  vflsh64.sys type=kernel &amp;&amp; sc.exe start nvflsh64.sys
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

| Filename | nvflsh64.sys |
|:---- | ---- | 
| MD5 | <a href="https://www.virustotal.com/gui/file/d3e40644a91327da2b1a7241606fe559">d3e40644a91327da2b1a7241606fe559</a> |
| SHA1 | <a href="https://www.virustotal.com/gui/file/7667b72471689151e176baeba4e1cd9cd006a09a">7667b72471689151e176baeba4e1cd9cd006a09a</a> |
| SHA256 | <a href="https://www.virustotal.com/gui/file/a899b659b08fbae30b182443be8ffb6a6471c1d0497b52293061754886a937a3">a899b659b08fbae30b182443be8ffb6a6471c1d0497b52293061754886a937a3</a> |
| Authentihash MD5 | <a href="https://www.virustotal.com/gui/search/authentihash%253Ac3a003ae7b48dcd1dac8bced7cf93f28">c3a003ae7b48dcd1dac8bced7cf93f28</a> || Authentihash SHA1 | <a href="https://www.virustotal.com/gui/search/authentihash%253A118cbd8cae88dc0dfb0d6a24df9161c90b916b90">118cbd8cae88dc0dfb0d6a24df9161c90b916b90</a> || Authentihash SHA256 | <a href="https://www.virustotal.com/gui/search/authentihash%253A372c6118541efaa800bcba6e0c1780f9beb8cab6f2176bcc5fe3664ea19379e4">372c6118541efaa800bcba6e0c1780f9beb8cab6f2176bcc5fe3664ea19379e4</a> || Signature | NVIDIA Corporation, VeriSign Class 3 Code Signing 2010 CA, VeriSign   |
#### Imports
{{< details "Expand" >}}* ntoskrnl.exe
* HAL.dll
{{< /details >}}
#### ImportedFunctions
{{< details "Expand" >}}* ZwMapViewOfSection
* ObReferenceObjectByHandle
* ZwOpenSection
* RtlInitUnicodeString
* ZwUnmapViewOfSection
* IofCompleteRequest
* ObfDereferenceObject
* IoDeleteSymbolicLink
* ExFreePoolWithTag
* IoCreateSymbolicLink
* IoCreateDevice
* ExAllocatePoolWithTag
* KeBugCheckEx
* IoDeleteDevice
* ZwClose
* HalTranslateBusAddress
{{< /details >}}
#### ExportedFunctions
{{< details "Expand" >}}{{< /details >}}



[*source*](https://github.com/magicsword-io/LOLDrivers/tree/main/yaml/nvflsh64.yaml)

*last_updated:* 2023-04-16








{{< /column >}}
{{< /block >}}
