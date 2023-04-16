+++

description = ""
title = "atillk64.sys"
weight = 10

+++


{{< block "grid-1" >}}
{{< column "mt-2 pt-1">}}


# atillk64.sys ![:inline](/images/twitter_verified.png) 


### Description

atillk64.sys is a vulnerable driver and more information will be added as found.

- **Created**: 2023-01-09
- **Author**: Michael Haag
- **Acknowledgement**:  | [](https://twitter.com/)


{{< button "https://github.com/magicsword-io/LOLDrivers/raw/main/drivers/0ae30291c6cbfa7be39320badd6e8de0.bin" "Download" >}}

{{< tip "warning" >}}
This download link contains the malcious driver!
{{< /tip >}}

### Commands

```
sc.exe create atillk64.sys binPath=C:\windows\temp\atillk64.sys type=kernel &amp;&amp; sc.exe start atillk64.sys
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

| Filename | atillk64.sys |
|:---- | ---- | 
| MD5 | <a href="https://www.virustotal.com/gui/file/62f02339fe267dc7438f603bfb5431a1">62f02339fe267dc7438f603bfb5431a1</a> |
| SHA1 | <a href="https://www.virustotal.com/gui/file/c52cef5b9e1d4a78431b7af56a6fdb6aa1bcad65">c52cef5b9e1d4a78431b7af56a6fdb6aa1bcad65</a> |
| SHA256 | <a href="https://www.virustotal.com/gui/file/5c04c274a708c9a7d993e33be3ea9e6119dc29527a767410dbaf93996f87369a">5c04c274a708c9a7d993e33be3ea9e6119dc29527a767410dbaf93996f87369a</a> |
| Authentihash MD5 | <a href="https://www.virustotal.com/gui/search/authentihash%281880f5f33d1aab062ceccd237ef992">281880f5f33d1aab062ceccd237ef992</a> || Authentihash SHA1 | <a href="https://www.virustotal.com/gui/search/authentihash%e8e533d9e8df018648ccbafbd6081507f5c0f41a">e8e533d9e8df018648ccbafbd6081507f5c0f41a</a> || Authentihash SHA256 | <a href="https://www.virustotal.com/gui/search/authentihash%126719d008d106b7100ae47ed47666c1334701bd7ddb32d5b8e84048f258700f">126719d008d106b7100ae47ed47666c1334701bd7ddb32d5b8e84048f258700f</a> || Publisher | &#34;ATI Technologies, Inc&#34; || Signature | ATI Technologies, Inc, VeriSign Class 3 Code Signing 2004 CA, VeriSign Class 3 Public Primary CA   || Company | ATI Technologies Inc. || Description | ATI Diagnostics Hardware Abstraction Sys || Product | ATI Diagnostics || OriginalFilename | atillk64.sys |
#### Imports
{{< details "Expand" >}}* ntoskrnl.exe
* HAL.dll
{{< /details >}}
#### ImportedFunctions
{{< details "Expand" >}}* IoDeleteDevice
* MmUnmapIoSpace
* MmBuildMdlForNonPagedPool
* IoFreeMdl
* MmMapIoSpace
* IofCompleteRequest
* RtlInitUnicodeString
* IoCreateDevice
* IoAllocateMdl
* KeBugCheckEx
* MmMapLockedPages
* IoCreateSymbolicLink
* IoDeleteSymbolicLink
* HalSetBusDataByOffset
* HalGetBusDataByOffset
{{< /details >}}
#### ExportedFunctions
{{< details "Expand" >}}{{< /details >}}



[*source*](https://github.com/magicsword-io/LOLDrivers/tree/main/yaml/atillk64.yaml)

*last_updated:* 2023-04-15








{{< /column >}}
{{< /block >}}
