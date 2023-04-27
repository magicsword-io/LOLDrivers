+++

description = ""
title = "IOMap64.sys"
weight = 10

+++


{{< block "grid-1" >}}
{{< column "mt-2 pt-1">}}


# IOMap64.sys ![:inline](/images/twitter_verified.png) 


### Description

IOMap64.sys is a vulnerable driver and more information will be added as found.

- **Created**: 2023-01-09
- **Author**: Michael Haag
- **Acknowledgement**:  | [](https://twitter.com/)

{{< button "https://github.com/magicsword-io/LOLDrivers/raw/main/drivers/a01c412699b6f21645b2885c2bae4454.bin" "Download" >}}
{{< tip "warning" >}}
This download link contains the vulnerable driver!

{{< /tip >}}

### Commands

```
sc.exe create IOMap64.sys binPath=C:\windows\temp\IOMap64.sys type=kernel &amp;&amp; sc.exe start IOMap64.sys
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
| Filename           | IOMap64.sys |
| MD5                | [a01c412699b6f21645b2885c2bae4454](https://www.virustotal.com/gui/file/a01c412699b6f21645b2885c2bae4454) |
| SHA1               | [2fc6845047abcf2a918fce89ab99e4955d08e72c](https://www.virustotal.com/gui/file/2fc6845047abcf2a918fce89ab99e4955d08e72c) |
| SHA256             | [ea85bbe63d6f66f7efee7007e770af820d57f914c7f179c5fee3ef2845f19c41](https://www.virustotal.com/gui/file/ea85bbe63d6f66f7efee7007e770af820d57f914c7f179c5fee3ef2845f19c41) |
| Authentihash MD5   | [3d840e2458fef30b0871bf1c13b060ff](https://www.virustotal.com/gui/search/authentihash%253A3d840e2458fef30b0871bf1c13b060ff) |
| Authentihash SHA1  | [63b773c3c8308ddfa783b318d0ea67724fa1dc2f](https://www.virustotal.com/gui/search/authentihash%253A63b773c3c8308ddfa783b318d0ea67724fa1dc2f) |
| Authentihash SHA256| [34b3acdeac5002880071f73b70aa3abd3a6facb9e281b5c93cc82a7a8a6d5cc1](https://www.virustotal.com/gui/search/authentihash%253A34b3acdeac5002880071f73b70aa3abd3a6facb9e281b5c93cc82a7a8a6d5cc1) |
| Signature         | ASUSTeK Computer Inc., VeriSign Class 3 Code Signing 2009-2 CA, VeriSign Class 3 Public Primary CA   |
| Company           | ASUSTeK Computer Inc. |
| Description       | ASUS Kernel Mode Driver for NT  |
| Product           | ASUS Kernel Mode Driver for NT  |
| OriginalFilename  | IOMap.sys |


#### Imports
{{< details "Expand" >}}
* ntoskrnl.exe
* HAL.dll

{{< /details >}}
#### ImportedFunctions
{{< details "Expand" >}}
* KeInitializeMutex
* RtlInitUnicodeString
* IoDeleteDevice
* MmUnmapIoSpace
* MmMapIoSpace
* PoStartNextPowerIrp
* IofCompleteRequest
* ExFreePoolWithTag
* IoCreateSymbolicLink
* IoCreateDevice
* IofCallDriver
* KeReleaseMutex
* KeWaitForSingleObject
* KeBugCheckEx
* IoDeleteSymbolicLink
* PoCallDriver
* ExAllocatePoolWithTag
* HalTranslateBusAddress
* KeStallExecutionProcessor

{{< /details >}}
#### ExportedFunctions
{{< details "Expand" >}}

{{< /details >}}
-----



[*source*](https://github.com/magicsword-io/LOLDrivers/tree/main/yaml/iomap64.yaml)

*last_updated:* 2023-04-27








{{< /column >}}
{{< /block >}}
