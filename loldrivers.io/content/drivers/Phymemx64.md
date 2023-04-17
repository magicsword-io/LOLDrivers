+++

description = ""
title = "Phymemx64.sys"
weight = 10

+++


{{< block "grid-1" >}}
{{< column "mt-2 pt-1">}}


# Phymemx64.sys ![:inline](/images/twitter_verified.png) 


### Description

Phymemx64.sys is a vulnerable driver and more information will be added as found.

- **Created**: 2023-01-09
- **Author**: Michael Haag
- **Acknowledgement**:  | [](https://twitter.com/)

{{< button "https://github.com/magicsword-io/LOLDrivers/raw/main/drivers/715572dfe6fb10b16f980bfa242f3fa5.bin" "Download" >}}
{{< tip "warning" >}}
This download link contains the malcious driver!
{{< /tip >}}

### Commands

```
sc.exe create Phymemx64.sys binPath=C:\windows\temp\Phymemx64.sys type=kernel &amp;&amp; sc.exe start Phymemx64.sys
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

| Filename | Phymemx64.sys |
|:---- | ---- | 
| MD5 | <a href="https://www.virustotal.com/gui/file/715572dfe6fb10b16f980bfa242f3fa5">715572dfe6fb10b16f980bfa242f3fa5</a> |
| SHA1 | <a href="https://www.virustotal.com/gui/file/f42f28d164205d9f6dab9317c9fecad54c38d5d2">f42f28d164205d9f6dab9317c9fecad54c38d5d2</a> |
| SHA256 | <a href="https://www.virustotal.com/gui/file/19a212e6fc324f4cb9ee5eba60f5c1fc0191799a4432265cbeaa3307c76a7fc0">19a212e6fc324f4cb9ee5eba60f5c1fc0191799a4432265cbeaa3307c76a7fc0</a> |
| Authentihash MD5 | <a href="https://www.virustotal.com/gui/search/authentihash%253A4325af5c85aa7bb0339389cf54d78817">4325af5c85aa7bb0339389cf54d78817</a> || Authentihash SHA1 | <a href="https://www.virustotal.com/gui/search/authentihash%253A3c9f40ac72b0202cb40627fdeb7298079187193a">3c9f40ac72b0202cb40627fdeb7298079187193a</a> || Authentihash SHA256 | <a href="https://www.virustotal.com/gui/search/authentihash%253Aa6ae7364fd188c10d6b5a729a7ff58a3eb11e7feb0d107d18f9133655c11fb66">a6ae7364fd188c10d6b5a729a7ff58a3eb11e7feb0d107d18f9133655c11fb66</a> || Signature | Huawei Technologies Co.,Ltd., VeriSign Class 3 Code Signing 2010 CA, VeriSign   |
#### Imports
{{< details "Expand" >}}* ntoskrnl.exe
* HAL.dll
* WDFLDR.SYS
{{< /details >}}
#### ImportedFunctions
{{< details "Expand" >}}* ObfDereferenceObject
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
{{< details "Expand" >}}{{< /details >}}



[*source*](https://github.com/magicsword-io/LOLDrivers/tree/main/yaml/phymemx64.yaml)

*last_updated:* 2023-04-16








{{< /column >}}
{{< /block >}}
