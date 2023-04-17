+++

description = ""
title = "BS_Def64.sys"
weight = 10

+++


{{< block "grid-1" >}}
{{< column "mt-2 pt-1">}}


# BS_Def64.sys ![:inline](/images/twitter_verified.png) 


### Description

BS_Def64.sys is a vulnerable driver and more information will be added as found.

- **Created**: 2023-01-09
- **Author**: Michael Haag
- **Acknowledgement**:  | [](https://twitter.com/)

{{< button "https://github.com/magicsword-io/LOLDrivers/raw/main/drivers/8abbb12e61045984eda19e2dc77b235e.bin" "Download" >}}
{{< tip "warning" >}}
This download link contains the malcious driver!
{{< /tip >}}

### Commands

```
sc.exe create BS_Def64.sys binPath=C:\windows\temp\BS_Def64.sys type=kernel &amp;&amp; sc.exe start BS_Def64.sys
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

| Filename | BS_Def64.sys |
|:---- | ---- | 
| MD5 | <a href="https://www.virustotal.com/gui/file/8abbb12e61045984eda19e2dc77b235e">8abbb12e61045984eda19e2dc77b235e</a> |
| SHA1 | <a href="https://www.virustotal.com/gui/file/609fa1efcf61e26d64a5ceb13b044175ab2b3a13">609fa1efcf61e26d64a5ceb13b044175ab2b3a13</a> |
| SHA256 | <a href="https://www.virustotal.com/gui/file/0040153302b88bee27eb4f1eca6855039e1a057370f5e8c615724fa5215bada3">0040153302b88bee27eb4f1eca6855039e1a057370f5e8c615724fa5215bada3</a> |
| Authentihash MD5 | <a href="https://www.virustotal.com/gui/search/authentihash%253A5c40712c0a854396aa9e8776763f3340">5c40712c0a854396aa9e8776763f3340</a> || Authentihash SHA1 | <a href="https://www.virustotal.com/gui/search/authentihash%253A45cae96b31928bc5f93381edf6b978534fa24f59">45cae96b31928bc5f93381edf6b978534fa24f59</a> || Authentihash SHA256 | <a href="https://www.virustotal.com/gui/search/authentihash%253A57e9de67e908186b3cb8180caa2e5c5d7b6bb31969557b8bd5710d79089e8868">57e9de67e908186b3cb8180caa2e5c5d7b6bb31969557b8bd5710d79089e8868</a> || Publisher | ASUSTeK Computer Inc. || Signature | ASUSTeK Computer Inc., VeriSign Class 3 Code Signing 2004 CA, VeriSign Class 3 Public Primary CA   || Company | AsusTek Computer Inc. || Description | Default BIOS Flash Driver || Product | Support SST39SF020,SST29EE020,AT49F002T,AT29C020,AM29F002NT,AM29F002NB,V29C51002T,V29C51002B,M29F002T,W29C020. || OriginalFilename | Bs_Def64.sys |
#### Imports
{{< details "Expand" >}}* ntoskrnl.exe
* HAL.dll
{{< /details >}}
#### ImportedFunctions
{{< details "Expand" >}}* MmBuildMdlForNonPagedPool
* IoAllocateMdl
* MmGetPhysicalAddress
* MmAllocateContiguousMemory
* IoFreeMdl
* MmUnmapLockedPages
* KeDelayExecutionThread
* MmUnmapIoSpace
* MmMapIoSpace
* RtlZeroMemory
* IoDeleteDevice
* IoCreateSymbolicLink
* IoCreateDevice
* MmMapLockedPages
* IofCompleteRequest
* IoDeleteSymbolicLink
* ZwClose
* ZwMapViewOfSection
* ObReferenceObjectByHandle
* ZwOpenSection
* ZwUnmapViewOfSection
* strncpy
* KeLeaveCriticalRegion
* KeEnterCriticalRegion
* IoIs32bitProcess
* strstr
* strncmp
* RtlInitUnicodeString
* MmFreeContiguousMemory
* HalTranslateBusAddress
{{< /details >}}
#### ExportedFunctions
{{< details "Expand" >}}{{< /details >}}
| Filename | BS_Def64.sys |
|:---- | ---- | 
| MD5 | <a href="https://www.virustotal.com/gui/file/c9a293762319d73c8ee84bcaaf81b7b3">c9a293762319d73c8ee84bcaaf81b7b3</a> |
| SHA1 | <a href="https://www.virustotal.com/gui/file/7d7c03e22049a725ace2a9812c72b53a66c2548b">7d7c03e22049a725ace2a9812c72b53a66c2548b</a> |
| SHA256 | <a href="https://www.virustotal.com/gui/file/3326e2d32bbabd69feb6024809afc56c7e39241ebe70a53728c77e80995422a5">3326e2d32bbabd69feb6024809afc56c7e39241ebe70a53728c77e80995422a5</a> |
| Authentihash MD5 | <a href="https://www.virustotal.com/gui/search/authentihash%253A7aa4c54af2ef8f71eb5c7976ab741fa3">7aa4c54af2ef8f71eb5c7976ab741fa3</a> || Authentihash SHA1 | <a href="https://www.virustotal.com/gui/search/authentihash%253Ac95b6a13289b6538c7f4b68f791758bda1036cbe">c95b6a13289b6538c7f4b68f791758bda1036cbe</a> || Authentihash SHA256 | <a href="https://www.virustotal.com/gui/search/authentihash%253A3171d7af852e8b6be4651c415ea9490568475c45ecaa02a33dda9babb1643b07">3171d7af852e8b6be4651c415ea9490568475c45ecaa02a33dda9babb1643b07</a> || Publisher | ASUSTeK Computer Inc. || Signature | ASUSTeK Computer Inc., VeriSign Class 3 Code Signing 2004 CA, VeriSign Class 3 Public Primary CA   || Company | AsusTek Computer Inc. || Description | Default BIOS Flash Driver || Product | Support SST39SF020,SST29EE020,AT49F002T,AT29C020,AM29F002NT,AM29F002NB,V29C51002T,V29C51002B,M29F002T,W29C020. || OriginalFilename | Bs_Def64.sys |
#### Imports
{{< details "Expand" >}}* ntoskrnl.exe
* HAL.dll
{{< /details >}}
#### ImportedFunctions
{{< details "Expand" >}}* MmBuildMdlForNonPagedPool
* IoAllocateMdl
* MmGetPhysicalAddress
* MmAllocateContiguousMemory
* IoFreeMdl
* MmUnmapLockedPages
* KeDelayExecutionThread
* MmUnmapIoSpace
* MmMapIoSpace
* RtlZeroMemory
* IoDeleteDevice
* IoCreateSymbolicLink
* IoCreateDevice
* MmMapLockedPages
* IofCompleteRequest
* IoDeleteSymbolicLink
* ZwClose
* ZwMapViewOfSection
* ObReferenceObjectByHandle
* ZwOpenSection
* ZwUnmapViewOfSection
* strncpy
* KeLeaveCriticalRegion
* KeEnterCriticalRegion
* IoIs32bitProcess
* strstr
* strncmp
* RtlInitUnicodeString
* MmFreeContiguousMemory
* HalTranslateBusAddress
{{< /details >}}
#### ExportedFunctions
{{< details "Expand" >}}{{< /details >}}
| Filename | BS_Def64.sys |
|:---- | ---- | 
| MD5 | <a href="https://www.virustotal.com/gui/file/120b5bbb9d2eb35ff4f62d79507ea63a">120b5bbb9d2eb35ff4f62d79507ea63a</a> |
| SHA1 | <a href="https://www.virustotal.com/gui/file/f9519d033d75e1ab6b82b2e156eafe9607edbcfb">f9519d033d75e1ab6b82b2e156eafe9607edbcfb</a> |
| SHA256 | <a href="https://www.virustotal.com/gui/file/36b9e31240ab0341873c7092b63e2e0f2cab2962ebf9b25271c3a1216b7669eb">36b9e31240ab0341873c7092b63e2e0f2cab2962ebf9b25271c3a1216b7669eb</a> |
| Authentihash MD5 | <a href="https://www.virustotal.com/gui/search/authentihash%253A034aa8df77d5a2815c8f4cf9f1399fd3">034aa8df77d5a2815c8f4cf9f1399fd3</a> || Authentihash SHA1 | <a href="https://www.virustotal.com/gui/search/authentihash%253Ae62d0712ddfd9fbaf9014cf43e49e2087a3f1ed2">e62d0712ddfd9fbaf9014cf43e49e2087a3f1ed2</a> || Authentihash SHA256 | <a href="https://www.virustotal.com/gui/search/authentihash%253Aeb11a4270a6980a97ea8775422dacbd1e763b7e5898f0a80c71c91449fff7ab4">eb11a4270a6980a97ea8775422dacbd1e763b7e5898f0a80c71c91449fff7ab4</a> || Publisher | ASUSTeK Computer Inc. || Signature | ASUSTeK Computer Inc., VeriSign Class 3 Code Signing 2004 CA, VeriSign Class 3 Public Primary CA   || Company | AsusTek Computer Inc. || Description | Default BIOS Flash Driver || Product | Support SST39SF020,SST29EE020,AT49F002T,AT29C020,AM29F002NT,AM29F002NB,V29C51002T,V29C51002B,M29F002T,W29C020. || OriginalFilename | Bs_Def64.sys |
#### Imports
{{< details "Expand" >}}* ntoskrnl.exe
* HAL.dll
{{< /details >}}
#### ImportedFunctions
{{< details "Expand" >}}* MmBuildMdlForNonPagedPool
* IoAllocateMdl
* MmGetPhysicalAddress
* MmAllocateContiguousMemory
* IoFreeMdl
* MmUnmapLockedPages
* KeDelayExecutionThread
* MmUnmapIoSpace
* MmMapIoSpace
* RtlZeroMemory
* IoDeleteDevice
* IoCreateSymbolicLink
* IoCreateDevice
* MmMapLockedPages
* IofCompleteRequest
* IoDeleteSymbolicLink
* ZwClose
* ZwMapViewOfSection
* ObReferenceObjectByHandle
* ZwOpenSection
* ZwUnmapViewOfSection
* strncpy
* KeLeaveCriticalRegion
* KeEnterCriticalRegion
* IoIs32bitProcess
* strstr
* strncmp
* RtlInitUnicodeString
* MmFreeContiguousMemory
* HalTranslateBusAddress
{{< /details >}}
#### ExportedFunctions
{{< details "Expand" >}}{{< /details >}}



[*source*](https://github.com/magicsword-io/LOLDrivers/tree/main/yaml/bs_def64.yaml)

*last_updated:* 2023-04-16








{{< /column >}}
{{< /block >}}
