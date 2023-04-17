+++

description = ""
title = "AsrDrv102.sys"
weight = 10

+++


{{< block "grid-1" >}}
{{< column "mt-2 pt-1">}}


# AsrDrv102.sys ![:inline](/images/twitter_verified.png) 


### Description

AsrDrv102.sys is a vulnerable driver and more information will be added as found.

- **Created**: 2023-01-09
- **Author**: Michael Haag
- **Acknowledgement**:  | [](https://twitter.com/)

{{< button "https://github.com/magicsword-io/LOLDrivers/raw/main/drivers/76bb1a4332666222a8e3e1339e267179.bin" "Download" >}}
{{< tip "warning" >}}
This download link contains the malcious driver!
{{< /tip >}}

### Commands

```
sc.exe create AsrDrv102.sys binPath=C:\windows\temp\AsrDrv102.sys type=kernel &amp;&amp; sc.exe start AsrDrv102.sys
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

| Filename | AsrDrv102.sys |
|:---- | ---- | 
| MD5 | <a href="https://www.virustotal.com/gui/file/76bb1a4332666222a8e3e1339e267179">76bb1a4332666222a8e3e1339e267179</a> |
| SHA1 | <a href="https://www.virustotal.com/gui/file/9923c8f1e565a05b3c738d283cf5c0ed61a0b90f">9923c8f1e565a05b3c738d283cf5c0ed61a0b90f</a> |
| SHA256 | <a href="https://www.virustotal.com/gui/file/a7c2e7910942dd5e43e2f4eb159bcd2b4e71366e34a68109548b9fb12ac0f7cc">a7c2e7910942dd5e43e2f4eb159bcd2b4e71366e34a68109548b9fb12ac0f7cc</a> |
| Authentihash MD5 | <a href="https://www.virustotal.com/gui/search/authentihash%253Ac36c748b4297cedfdc5f38de22a40b5a">c36c748b4297cedfdc5f38de22a40b5a</a> || Authentihash SHA1 | <a href="https://www.virustotal.com/gui/search/authentihash%253A5f9c7d3552ffa98c9dcf9a9b7ad1263d2ab24a2f">5f9c7d3552ffa98c9dcf9a9b7ad1263d2ab24a2f</a> || Authentihash SHA256 | <a href="https://www.virustotal.com/gui/search/authentihash%253A11eecf9e6e2447856ed4cf86ee1cb779cfe0672c808bbd5934cf2f09a62d6170">11eecf9e6e2447856ed4cf86ee1cb779cfe0672c808bbd5934cf2f09a62d6170</a> || Signature | ASROCK Incorporation, VeriSign Class 3 Code Signing 2010 CA, VeriSign   || Company | ASRock Incorporation || Description | ASRock IO Driver || Product | ASRock IO Driver || OriginalFilename | AsrDrv.sys |
#### Imports
{{< details "Expand" >}}* ntoskrnl.exe
* HAL.dll
{{< /details >}}
#### ImportedFunctions
{{< details "Expand" >}}* IoDeleteSymbolicLink
* ExFreePoolWithTag
* MmFreeContiguousMemorySpecifyCache
* RtlInitUnicodeString
* IoDeleteDevice
* RtlQueryRegistryValues
* MmUnmapIoSpace
* IoFreeMdl
* MmGetPhysicalAddress
* IoBuildAsynchronousFsdRequest
* MmMapIoSpace
* IofCompleteRequest
* IoFreeIrp
* RtlCompareMemory
* MmUnlockPages
* IoCreateSymbolicLink
* IoCreateDevice
* MmAllocateContiguousMemorySpecifyCache
* IofCallDriver
* KeBugCheckEx
* ExAllocatePoolWithTag
* KeStallExecutionProcessor
{{< /details >}}
#### ExportedFunctions
{{< details "Expand" >}}{{< /details >}}



[*source*](https://github.com/magicsword-io/LOLDrivers/tree/main/yaml/asrdrv102.yaml)

*last_updated:* 2023-04-17








{{< /column >}}
{{< /block >}}
