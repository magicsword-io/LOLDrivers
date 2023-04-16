+++

description = ""
title = "NTIOLib_X64.sys"
weight = 10

+++


{{< block "grid-1" >}}
{{< column "mt-2 pt-1">}}


# NTIOLib_X64.sys ![:inline](/images/twitter_verified.png) 


### Description

NTIOLib_X64.sys is a vulnerable driver and more information will be added as found.

- **Created**: 2023-01-09
- **Author**: Michael Haag
- **Acknowledgement**:  | [](https://twitter.com/)


{{< button "https://github.com/magicsword-io/LOLDrivers/raw/main/drivers/0ae30291c6cbfa7be39320badd6e8de0.bin" "Download" >}}

{{< tip "warning" >}}
This download link contains the malcious driver!
{{< /tip >}}

### Commands

```
sc.exe create NTIOLib_X64.sys binPath=C:\windows\temp\NTIOLib_X64.sys     type=kernel type=kernel &amp;&amp; sc.exe start NTIOLib_X64.sys
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

| Filename | NTIOLib_X64.sys |
|:---- | ---- | 
| MD5 | <a href="https://www.virustotal.com/gui/file/c02f70960fa934b8defa16a03d7f6556">c02f70960fa934b8defa16a03d7f6556</a> |
| SHA1 | <a href="https://www.virustotal.com/gui/file/3805e4e08ad342d224973ecdade8b00c40ed31be">3805e4e08ad342d224973ecdade8b00c40ed31be</a> |
| SHA256 | <a href="https://www.virustotal.com/gui/file/d8b58f6a89a7618558e37afc360cd772b6731e3ba367f8d58734ecee2244a530">d8b58f6a89a7618558e37afc360cd772b6731e3ba367f8d58734ecee2244a530</a> |
| Authentihash MD5 | <a href="https://www.virustotal.com/gui/search/authentihash%c6830e904e56ea951005ea7639eedd35">c6830e904e56ea951005ea7639eedd35</a> || Authentihash SHA1 | <a href="https://www.virustotal.com/gui/search/authentihash%c57c0dd18135bca5fdb094858a70033c006cd281">c57c0dd18135bca5fdb094858a70033c006cd281</a> || Authentihash SHA256 | <a href="https://www.virustotal.com/gui/search/authentihash%4a05ad47cd63932b3df2d0f1f42617321729772211bec651fe061140d3e75957">4a05ad47cd63932b3df2d0f1f42617321729772211bec651fe061140d3e75957</a> || Signature | Micro-Star Int&#39;l Co. Ltd., GlobalSign ObjectSign CA, GlobalSign Primary Object Publishing CA, GlobalSign Root CA - R1   || Company | MSI || Description | NTIOLib || Product | NTIOLib || OriginalFilename | NTIOLib.sys |
#### Imports
{{< details "Expand" >}}* ntoskrnl.exe
* HAL.dll
{{< /details >}}
#### ImportedFunctions
{{< details "Expand" >}}* MmUnmapIoSpace
* MmMapIoSpace
* IofCompleteRequest
* IoDeleteDevice
* IoCreateDevice
* KeBugCheckEx
* RtlInitUnicodeString
* IoCreateSymbolicLink
* IoDeleteSymbolicLink
* __C_specific_handler
* HalSetBusDataByOffset
* HalGetBusDataByOffset
{{< /details >}}
#### ExportedFunctions
{{< details "Expand" >}}{{< /details >}}



[*source*](https://github.com/magicsword-io/LOLDrivers/tree/main/yaml/ntiolib_x64.yaml)

*last_updated:* 2023-04-15








{{< /column >}}
{{< /block >}}
