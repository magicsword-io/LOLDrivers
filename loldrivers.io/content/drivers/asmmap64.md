+++

description = ""
title = "asmmap64.sys"
weight = 10

+++


{{< block "grid-1" >}}
{{< column "mt-2 pt-1">}}


# asmmap64.sys ![:inline](/images/twitter_verified.png) 


### Description

asmmap64.sys is a vulnerable driver and more information will be added as found.

- **Created**: 2023-01-09
- **Author**: Michael Haag
- **Acknowledgement**:  | [](https://twitter.com/)


{{< button "https://github.com/magicsword-io/LOLDrivers/raw/main/drivers/0ae30291c6cbfa7be39320badd6e8de0.bin" "Download" >}}

{{< tip "warning" >}}
This download link contains the malcious driver!
{{< /tip >}}

### Commands

```
sc.exe create asmmap64.sys binPath=C:\windows\temp\asmmap64.sys type=kernel &amp;&amp; sc.exe start asmmap64.sys
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

| Filename | asmmap64.sys |
|:---- | ---- | 
| MD5 | <a href="https://www.virustotal.com/gui/file/4c016fd76ed5c05e84ca8cab77993961">4c016fd76ed5c05e84ca8cab77993961</a> |
| SHA1 | <a href="https://www.virustotal.com/gui/file/00a442a4305c62cefa8105c0b4c4a9a5f4d1e93b">00a442a4305c62cefa8105c0b4c4a9a5f4d1e93b</a> |
| SHA256 | <a href="https://www.virustotal.com/gui/file/025e7be9fcefd6a83f4471bba0c11f1c11bd5047047d26626da24ee9a419cdc4">025e7be9fcefd6a83f4471bba0c11f1c11bd5047047d26626da24ee9a419cdc4</a> |
| Authentihash MD5 | <a href="https://www.virustotal.com/gui/search/authentihash%882ef4da71bcb67204bdec731afe1c94">882ef4da71bcb67204bdec731afe1c94</a> || Authentihash SHA1 | <a href="https://www.virustotal.com/gui/search/authentihash%734f215383ef61350c2da97dea53589ede21a3d2">734f215383ef61350c2da97dea53589ede21a3d2</a> || Authentihash SHA256 | <a href="https://www.virustotal.com/gui/search/authentihash%ab300e7e0d5d540900dbe11495b8d6788039d1cffb22e2dc2304b730a71eec97">ab300e7e0d5d540900dbe11495b8d6788039d1cffb22e2dc2304b730a71eec97</a> || Publisher | ASUSTeK Computer Inc. || Signature | ASUSTeK Computer Inc., VeriSign Class 3 Code Signing 2004 CA, VeriSign Class 3 Public Primary CA   || Company | ASUS || Description | Memory mapping Driver || Product | ATK Generic Function Service || OriginalFilename | asmmap.sys |
#### Imports
{{< details "Expand" >}}* ntoskrnl.exe
* HAL.dll
{{< /details >}}
#### ImportedFunctions
{{< details "Expand" >}}* MmMapLockedPages
* ZwMapViewOfSection
* RtlInitUnicodeString
* IoDeleteDevice
* MmFreeContiguousMemory
* MmBuildMdlForNonPagedPool
* IoFreeMdl
* MmGetPhysicalAddress
* ZwUnmapViewOfSection
* IoDeleteSymbolicLink
* IofCompleteRequest
* ObReferenceObjectByHandle
* IoCreateSymbolicLink
* IoCreateDevice
* ZwOpenSection
* DbgPrint
* IoAllocateMdl
* MmAllocateContiguousMemory
* KeBugCheckEx
* ZwClose
* MmUnmapLockedPages
* __C_specific_handler
* HalTranslateBusAddress
{{< /details >}}
#### ExportedFunctions
{{< details "Expand" >}}{{< /details >}}



[*source*](https://github.com/magicsword-io/LOLDrivers/tree/main/yaml/asmmap64.yaml)

*last_updated:* 2023-04-15








{{< /column >}}
{{< /block >}}
