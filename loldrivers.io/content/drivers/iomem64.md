+++

description = ""
title = "iomem64.sys"
weight = 10

+++


{{< block "grid-1" >}}
{{< column "mt-2 pt-1">}}


# iomem64.sys ![:inline](/images/twitter_verified.png) 


### Description

iomem64.sys is a vulnerable driver and more information will be added as found.

- **Created**: 2023-01-09
- **Author**: Michael Haag
- **Acknowledgement**:  | [](https://twitter.com/)

{{< button "https://github.com/magicsword-io/LOLDrivers/raw/main/drivers/0898af0888d8f7a9544ef56e5e16354e.bin" "Download" >}}
{{< tip "warning" >}}
This download link contains the vulnerable driver!

{{< /tip >}}

### Commands

```
sc.exe create iomem64.sys binPath=C:\windows\temp\iomem64.sys type=kernel &amp;&amp; sc.exe start iomem64.sys
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
| Filename           | iomem64.sys |
| MD5                | [0898af0888d8f7a9544ef56e5e16354e](https://www.virustotal.com/gui/file/0898af0888d8f7a9544ef56e5e16354e) |
| SHA1               | [4b009e91bae8d27b160dc195f10c095f8a2441e1](https://www.virustotal.com/gui/file/4b009e91bae8d27b160dc195f10c095f8a2441e1) |
| SHA256             | [3d23bdbaf9905259d858df5bf991eb23d2dc9f4ecda7f9f77839691acef1b8c4](https://www.virustotal.com/gui/file/3d23bdbaf9905259d858df5bf991eb23d2dc9f4ecda7f9f77839691acef1b8c4) |
| Authentihash MD5   | [9b6609bd5d9d8de37273fe2d355ae349](https://www.virustotal.com/gui/search/authentihash%253A9b6609bd5d9d8de37273fe2d355ae349) |
| Authentihash SHA1  | [4bf9ce7ffca224020572af6c13e866d8d41ad5bf](https://www.virustotal.com/gui/search/authentihash%253A4bf9ce7ffca224020572af6c13e866d8d41ad5bf) |
| Authentihash SHA256| [46ffe559f5a8f6bd611ac5a9264edf92d8449d8d31b2ddf6b2add5971e309c56](https://www.virustotal.com/gui/search/authentihash%253A46ffe559f5a8f6bd611ac5a9264edf92d8449d8d31b2ddf6b2add5971e309c56) |
| Signature         | DT RESEARCH, INC. TAIWAN BRANCH, VeriSign Class 3 Code Signing 2010 CA, VeriSign   |
| Company           | DT Research, Inc. |
| Description       | DTR Kernel mode driver |
| Product           | iomem.sys |
| OriginalFilename  | iomem.sys |


#### Imports
{{< details "Expand" >}}
* ntoskrnl.exe
* HAL.dll

{{< /details >}}
#### ImportedFunctions
{{< details "Expand" >}}
* IoDeleteDevice
* MmUnmapIoSpace
* KeEnterCriticalRegion
* MmFreeNonCachedMemory
* MmMapIoSpace
* RtlInitUnicodeString
* IoCreateSymbolicLink
* MmAllocateNonCachedMemory
* IoCreateDevice
* KeBugCheckEx
* KeLeaveCriticalRegion
* IofCompleteRequest
* IoDeleteSymbolicLink
* HalSetBusDataByOffset
* HalGetBusDataByOffset

{{< /details >}}
#### ExportedFunctions
{{< details "Expand" >}}

{{< /details >}}| Property           | Value |
|:-------------------|:------|
| Filename           | iomem64.sys |
| MD5                | [f1e054333cc40f79cfa78e5fbf3b54c2](https://www.virustotal.com/gui/file/f1e054333cc40f79cfa78e5fbf3b54c2) |
| SHA1               | [6003184788cd3d2fc624ca801df291ccc4e225ee](https://www.virustotal.com/gui/file/6003184788cd3d2fc624ca801df291ccc4e225ee) |
| SHA256             | [dd4a1253d47de14ef83f1bc8b40816a86ccf90d1e624c5adf9203ae9d51d4097](https://www.virustotal.com/gui/file/dd4a1253d47de14ef83f1bc8b40816a86ccf90d1e624c5adf9203ae9d51d4097) |
| Authentihash MD5   | [91896c53af5ab967f7f131285354e4ac](https://www.virustotal.com/gui/search/authentihash%253A91896c53af5ab967f7f131285354e4ac) |
| Authentihash SHA1  | [7eec42b3027252dea4c777bbdbd47560bc179986](https://www.virustotal.com/gui/search/authentihash%253A7eec42b3027252dea4c777bbdbd47560bc179986) |
| Authentihash SHA256| [57d36936fbf8785380536b03e5d9be172e5dd5c3bf435e19875a80aa96f97e1f](https://www.virustotal.com/gui/search/authentihash%253A57d36936fbf8785380536b03e5d9be172e5dd5c3bf435e19875a80aa96f97e1f) |
| Signature         | DT RESEARCH, INC. TAIWAN BRANCH, VeriSign Class 3 Code Signing 2010 CA, VeriSign   |
| Company           | DT Research, Inc. |
| Description       | DTR Kernel mode driver |
| Product           | iomem.sys |
| OriginalFilename  | iomem.sys |


#### Imports
{{< details "Expand" >}}
* ntoskrnl.exe
* HAL.dll

{{< /details >}}
#### ImportedFunctions
{{< details "Expand" >}}
* IoDeleteDevice
* MmUnmapIoSpace
* KeEnterCriticalRegion
* MmFreeNonCachedMemory
* MmMapIoSpace
* RtlInitUnicodeString
* IoCreateSymbolicLink
* MmAllocateNonCachedMemory
* IoCreateDevice
* KeBugCheckEx
* KeLeaveCriticalRegion
* IofCompleteRequest
* IoDeleteSymbolicLink
* HalSetBusDataByOffset
* HalGetBusDataByOffset

{{< /details >}}
#### ExportedFunctions
{{< details "Expand" >}}

{{< /details >}}


[*source*](https://github.com/magicsword-io/LOLDrivers/tree/main/yaml/iomem64.yaml)

*last_updated:* 2023-04-19








{{< /column >}}
{{< /block >}}
