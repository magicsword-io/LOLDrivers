+++

description = ""
title = "CITMDRV_AMD64.sys"
weight = 10

+++


{{< block "grid-1" >}}
{{< column "mt-2 pt-1">}}


# CITMDRV_AMD64.sys ![:inline](/images/twitter_verified.png) 


### Description

CITMDRV_AMD64.sys is a vulnerable driver and more information will be added as found.

- **Created**: 2023-01-09
- **Author**: Michael Haag
- **Acknowledgement**:  | [](https://twitter.com/)


{{< button "https://github.com/magicsword-io/LOLDrivers/raw/main/drivers/0ae30291c6cbfa7be39320badd6e8de0.bin" "Download" >}}

{{< tip "warning" >}}
This download link contains the malcious driver!
{{< /tip >}}

### Commands

```
sc.exe create CITMDRV_AMD64.sys binPath=C:\windows\temp\CITMDRV_AMD64.sys     type=kernel type=kernel &amp;&amp; sc.exe start CITMDRV_AMD64.sys
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

| Filename | CITMDRV_AMD64.sys |
|:---- | ---- | 
| MD5 | <a href="https://www.virustotal.com/gui/file/e076dadf37dd43a6b36aeed957abee9e">e076dadf37dd43a6b36aeed957abee9e</a> |
| SHA1 | <a href="https://www.virustotal.com/gui/file/468e2e5505a3d924b14fedee4ddf240d09393776">468e2e5505a3d924b14fedee4ddf240d09393776</a> |
| SHA256 | <a href="https://www.virustotal.com/gui/file/29e0062a017a93b2f2f5207a608a96df4d554c5de976bd0276c2590a03bd3e94">29e0062a017a93b2f2f5207a608a96df4d554c5de976bd0276c2590a03bd3e94</a> |
| Authentihash MD5 | <a href="https://www.virustotal.com/gui/search/authentihash%6df250bd96e46a522bd7536100737f13">6df250bd96e46a522bd7536100737f13</a> || Authentihash SHA1 | <a href="https://www.virustotal.com/gui/search/authentihash%d917e8e8aee2cb3d01d1ba123098654cf370689f">d917e8e8aee2cb3d01d1ba123098654cf370689f</a> || Authentihash SHA256 | <a href="https://www.virustotal.com/gui/search/authentihash%5be61901f41d55e6fbd0994869015448f8eb0450ae38f67b75ddb594c3325aac">5be61901f41d55e6fbd0994869015448f8eb0450ae38f67b75ddb594c3325aac</a> || Publisher | IBM Polska Sp. z o.o. || Signature | IBM Polska Sp. z o.o., VeriSign Class 3 Code Signing 2009-2 CA, VeriSign Class 3 Public Primary CA   |
#### Imports
{{< details "Expand" >}}* ntoskrnl.exe
{{< /details >}}
#### ImportedFunctions
{{< details "Expand" >}}* ZwClose
* ZwOpenFile
* RtlInitUnicodeString
* ZwWriteFile
* DbgPrint
* ZwCreateFile
* vsprintf
* IoDeleteDevice
* IoDeleteSymbolicLink
* ZwMapViewOfSection
* ZwUnmapViewOfSection
* __C_specific_handler
* IoFreeMdl
* MmUnlockPages
* ZwOpenSection
* MmProbeAndLockPages
* IoAllocateMdl
* IofCompleteRequest
* IoCreateSymbolicLink
* IoCreateDevice
* KeBugCheckEx
{{< /details >}}
#### ExportedFunctions
{{< details "Expand" >}}{{< /details >}}
| Filename | CITMDRV_AMD64.sys |
|:---- | ---- | 
| MD5 | <a href="https://www.virustotal.com/gui/file/aa1ed3917928f04d97d8a217fe9b5cb1">aa1ed3917928f04d97d8a217fe9b5cb1</a> |
| SHA1 | <a href="https://www.virustotal.com/gui/file/2e3de9bff43d7712707ef8a0b10f7e4ad8427fd8">2e3de9bff43d7712707ef8a0b10f7e4ad8427fd8</a> |
| SHA256 | <a href="https://www.virustotal.com/gui/file/45abdbcd4c0916b7d9faaf1cd08543a3a5178871074628e0126a6eda890d26e0">45abdbcd4c0916b7d9faaf1cd08543a3a5178871074628e0126a6eda890d26e0</a> |
| Authentihash MD5 | <a href="https://www.virustotal.com/gui/search/authentihash%6df250bd96e46a522bd7536100737f13">6df250bd96e46a522bd7536100737f13</a> || Authentihash SHA1 | <a href="https://www.virustotal.com/gui/search/authentihash%d917e8e8aee2cb3d01d1ba123098654cf370689f">d917e8e8aee2cb3d01d1ba123098654cf370689f</a> || Authentihash SHA256 | <a href="https://www.virustotal.com/gui/search/authentihash%5be61901f41d55e6fbd0994869015448f8eb0450ae38f67b75ddb594c3325aac">5be61901f41d55e6fbd0994869015448f8eb0450ae38f67b75ddb594c3325aac</a> || Publisher | IBM Polska Sp. z o.o. || Signature | IBM Polska Sp. z o.o., VeriSign Class 3 Code Signing 2010 CA, VeriSign   |
#### Imports
{{< details "Expand" >}}* ntoskrnl.exe
{{< /details >}}
#### ImportedFunctions
{{< details "Expand" >}}* ZwClose
* ZwOpenFile
* RtlInitUnicodeString
* ZwWriteFile
* DbgPrint
* ZwCreateFile
* vsprintf
* IoDeleteDevice
* IoDeleteSymbolicLink
* ZwMapViewOfSection
* ZwUnmapViewOfSection
* __C_specific_handler
* IoFreeMdl
* MmUnlockPages
* ZwOpenSection
* MmProbeAndLockPages
* IoAllocateMdl
* IofCompleteRequest
* IoCreateSymbolicLink
* IoCreateDevice
* KeBugCheckEx
{{< /details >}}
#### ExportedFunctions
{{< details "Expand" >}}{{< /details >}}
| Filename | CITMDRV_AMD64.sys |
|:---- | ---- | 
| MD5 | <a href="https://www.virustotal.com/gui/file/dd39a86852b498b891672ffbcd071c03">dd39a86852b498b891672ffbcd071c03</a> |
| SHA1 | <a href="https://www.virustotal.com/gui/file/c9cbfdd0be7b35751a017ec59ff7237ffdc4df1f">c9cbfdd0be7b35751a017ec59ff7237ffdc4df1f</a> |
| SHA256 | <a href="https://www.virustotal.com/gui/file/50db5480d0392a7dd6ab5df98389dc24d1ed1e9c98c9c35964b19dabcd6dc67f">50db5480d0392a7dd6ab5df98389dc24d1ed1e9c98c9c35964b19dabcd6dc67f</a> |
| Authentihash MD5 | <a href="https://www.virustotal.com/gui/search/authentihash%6df250bd96e46a522bd7536100737f13">6df250bd96e46a522bd7536100737f13</a> || Authentihash SHA1 | <a href="https://www.virustotal.com/gui/search/authentihash%d917e8e8aee2cb3d01d1ba123098654cf370689f">d917e8e8aee2cb3d01d1ba123098654cf370689f</a> || Authentihash SHA256 | <a href="https://www.virustotal.com/gui/search/authentihash%5be61901f41d55e6fbd0994869015448f8eb0450ae38f67b75ddb594c3325aac">5be61901f41d55e6fbd0994869015448f8eb0450ae38f67b75ddb594c3325aac</a> || Publisher | IBM Polska Sp. z o.o. || Signature | IBM Polska Sp. z o.o., VeriSign Class 3 Code Signing 2010 CA, VeriSign   |
#### Imports
{{< details "Expand" >}}* ntoskrnl.exe
{{< /details >}}
#### ImportedFunctions
{{< details "Expand" >}}* ZwClose
* ZwOpenFile
* RtlInitUnicodeString
* ZwWriteFile
* DbgPrint
* ZwCreateFile
* vsprintf
* IoDeleteDevice
* IoDeleteSymbolicLink
* ZwMapViewOfSection
* ZwUnmapViewOfSection
* __C_specific_handler
* IoFreeMdl
* MmUnlockPages
* ZwOpenSection
* MmProbeAndLockPages
* IoAllocateMdl
* IofCompleteRequest
* IoCreateSymbolicLink
* IoCreateDevice
* KeBugCheckEx
{{< /details >}}
#### ExportedFunctions
{{< details "Expand" >}}{{< /details >}}
| Filename | CITMDRV_AMD64.sys |
|:---- | ---- | 
| MD5 | <a href="https://www.virustotal.com/gui/file/708ac9f7b12b6ca4553fd8d0c7299296">708ac9f7b12b6ca4553fd8d0c7299296</a> |
| SHA1 | <a href="https://www.virustotal.com/gui/file/078ae07dec258db4376d5a2a05b9b508d68c0123">078ae07dec258db4376d5a2a05b9b508d68c0123</a> |
| SHA256 | <a href="https://www.virustotal.com/gui/file/607dc4c75ac7aef82ae0616a453866b3b358c6cf5c8f9d29e4d37f844306b97c">607dc4c75ac7aef82ae0616a453866b3b358c6cf5c8f9d29e4d37f844306b97c</a> |
| Authentihash MD5 | <a href="https://www.virustotal.com/gui/search/authentihash%6df250bd96e46a522bd7536100737f13">6df250bd96e46a522bd7536100737f13</a> || Authentihash SHA1 | <a href="https://www.virustotal.com/gui/search/authentihash%d917e8e8aee2cb3d01d1ba123098654cf370689f">d917e8e8aee2cb3d01d1ba123098654cf370689f</a> || Authentihash SHA256 | <a href="https://www.virustotal.com/gui/search/authentihash%5be61901f41d55e6fbd0994869015448f8eb0450ae38f67b75ddb594c3325aac">5be61901f41d55e6fbd0994869015448f8eb0450ae38f67b75ddb594c3325aac</a> || Publisher | IBM Polska Sp. z o.o. || Signature | IBM Polska Sp. z o.o., VeriSign Class 3 Code Signing 2010 CA, VeriSign   |
#### Imports
{{< details "Expand" >}}* ntoskrnl.exe
{{< /details >}}
#### ImportedFunctions
{{< details "Expand" >}}* ZwClose
* ZwOpenFile
* RtlInitUnicodeString
* ZwWriteFile
* DbgPrint
* ZwCreateFile
* vsprintf
* IoDeleteDevice
* IoDeleteSymbolicLink
* ZwMapViewOfSection
* ZwUnmapViewOfSection
* __C_specific_handler
* IoFreeMdl
* MmUnlockPages
* ZwOpenSection
* MmProbeAndLockPages
* IoAllocateMdl
* IofCompleteRequest
* IoCreateSymbolicLink
* IoCreateDevice
* KeBugCheckEx
{{< /details >}}
#### ExportedFunctions
{{< details "Expand" >}}{{< /details >}}
| Filename | CITMDRV_AMD64.sys |
|:---- | ---- | 
| MD5 | <a href="https://www.virustotal.com/gui/file/7a16fca3d56c6038c692ec75b2bfee15">7a16fca3d56c6038c692ec75b2bfee15</a> |
| SHA1 | <a href="https://www.virustotal.com/gui/file/623cd2abef6c92255f79cbbd3309cb59176771da">623cd2abef6c92255f79cbbd3309cb59176771da</a> |
| SHA256 | <a href="https://www.virustotal.com/gui/file/61d6e40601fa368800980801a662a5b3b36e3c23296e8ae1c85726a56ef18cc8">61d6e40601fa368800980801a662a5b3b36e3c23296e8ae1c85726a56ef18cc8</a> |
| Authentihash MD5 | <a href="https://www.virustotal.com/gui/search/authentihash%6df250bd96e46a522bd7536100737f13">6df250bd96e46a522bd7536100737f13</a> || Authentihash SHA1 | <a href="https://www.virustotal.com/gui/search/authentihash%d917e8e8aee2cb3d01d1ba123098654cf370689f">d917e8e8aee2cb3d01d1ba123098654cf370689f</a> || Authentihash SHA256 | <a href="https://www.virustotal.com/gui/search/authentihash%5be61901f41d55e6fbd0994869015448f8eb0450ae38f67b75ddb594c3325aac">5be61901f41d55e6fbd0994869015448f8eb0450ae38f67b75ddb594c3325aac</a> || Publisher | IBM Polska Sp. z o.o. || Signature | IBM Polska Sp. z o.o., VeriSign Class 3 Code Signing 2010 CA, VeriSign   |
#### Imports
{{< details "Expand" >}}* ntoskrnl.exe
{{< /details >}}
#### ImportedFunctions
{{< details "Expand" >}}* ZwClose
* ZwOpenFile
* RtlInitUnicodeString
* ZwWriteFile
* DbgPrint
* ZwCreateFile
* vsprintf
* IoDeleteDevice
* IoDeleteSymbolicLink
* ZwMapViewOfSection
* ZwUnmapViewOfSection
* __C_specific_handler
* IoFreeMdl
* MmUnlockPages
* ZwOpenSection
* MmProbeAndLockPages
* IoAllocateMdl
* IofCompleteRequest
* IoCreateSymbolicLink
* IoCreateDevice
* KeBugCheckEx
{{< /details >}}
#### ExportedFunctions
{{< details "Expand" >}}{{< /details >}}
| Filename | CITMDRV_AMD64.sys |
|:---- | ---- | 
| MD5 | <a href="https://www.virustotal.com/gui/file/5970e8de1b337ca665114511b9d10806">5970e8de1b337ca665114511b9d10806</a> |
| SHA1 | <a href="https://www.virustotal.com/gui/file/1f3a9265963b660392c4053329eb9436deeed339">1f3a9265963b660392c4053329eb9436deeed339</a> |
| SHA256 | <a href="https://www.virustotal.com/gui/file/74a846c61adc53692d3040aff4c1916f32987ad72b07fe226e9e7dbeff1036c4">74a846c61adc53692d3040aff4c1916f32987ad72b07fe226e9e7dbeff1036c4</a> |
| Authentihash MD5 | <a href="https://www.virustotal.com/gui/search/authentihash%6df250bd96e46a522bd7536100737f13">6df250bd96e46a522bd7536100737f13</a> || Authentihash SHA1 | <a href="https://www.virustotal.com/gui/search/authentihash%d917e8e8aee2cb3d01d1ba123098654cf370689f">d917e8e8aee2cb3d01d1ba123098654cf370689f</a> || Authentihash SHA256 | <a href="https://www.virustotal.com/gui/search/authentihash%5be61901f41d55e6fbd0994869015448f8eb0450ae38f67b75ddb594c3325aac">5be61901f41d55e6fbd0994869015448f8eb0450ae38f67b75ddb594c3325aac</a> || Publisher | IBM Polska Sp. z o.o. || Signature | IBM Polska Sp. z o.o., VeriSign Class 3 Code Signing 2009-2 CA, VeriSign Class 3 Public Primary CA   |
#### Imports
{{< details "Expand" >}}* ntoskrnl.exe
{{< /details >}}
#### ImportedFunctions
{{< details "Expand" >}}* ZwClose
* ZwOpenFile
* RtlInitUnicodeString
* ZwWriteFile
* DbgPrint
* ZwCreateFile
* vsprintf
* IoDeleteDevice
* IoDeleteSymbolicLink
* ZwMapViewOfSection
* ZwUnmapViewOfSection
* __C_specific_handler
* IoFreeMdl
* MmUnlockPages
* ZwOpenSection
* MmProbeAndLockPages
* IoAllocateMdl
* IofCompleteRequest
* IoCreateSymbolicLink
* IoCreateDevice
* KeBugCheckEx
{{< /details >}}
#### ExportedFunctions
{{< details "Expand" >}}{{< /details >}}
| Filename | CITMDRV_AMD64.sys |
|:---- | ---- | 
| MD5 | <a href="https://www.virustotal.com/gui/file/2509a71a02296aa65a3428ddfac22180">2509a71a02296aa65a3428ddfac22180</a> |
| SHA1 | <a href="https://www.virustotal.com/gui/file/4a235f0b84ff615e2879fa9e0ec0d745fcfdaa5c">4a235f0b84ff615e2879fa9e0ec0d745fcfdaa5c</a> |
| SHA256 | <a href="https://www.virustotal.com/gui/file/76fb4deaee57ef30e56c382c92abffe2cf616d08dbecb3368c8ee6b02e59f303">76fb4deaee57ef30e56c382c92abffe2cf616d08dbecb3368c8ee6b02e59f303</a> |
| Authentihash MD5 | <a href="https://www.virustotal.com/gui/search/authentihash%6df250bd96e46a522bd7536100737f13">6df250bd96e46a522bd7536100737f13</a> || Authentihash SHA1 | <a href="https://www.virustotal.com/gui/search/authentihash%d917e8e8aee2cb3d01d1ba123098654cf370689f">d917e8e8aee2cb3d01d1ba123098654cf370689f</a> || Authentihash SHA256 | <a href="https://www.virustotal.com/gui/search/authentihash%5be61901f41d55e6fbd0994869015448f8eb0450ae38f67b75ddb594c3325aac">5be61901f41d55e6fbd0994869015448f8eb0450ae38f67b75ddb594c3325aac</a> || Publisher | IBM Polska Sp. z o.o. || Signature | IBM Polska Sp. z o.o., VeriSign Class 3 Code Signing 2010 CA, VeriSign   |
#### Imports
{{< details "Expand" >}}* ntoskrnl.exe
{{< /details >}}
#### ImportedFunctions
{{< details "Expand" >}}* ZwClose
* ZwOpenFile
* RtlInitUnicodeString
* ZwWriteFile
* DbgPrint
* ZwCreateFile
* vsprintf
* IoDeleteDevice
* IoDeleteSymbolicLink
* ZwMapViewOfSection
* ZwUnmapViewOfSection
* __C_specific_handler
* IoFreeMdl
* MmUnlockPages
* ZwOpenSection
* MmProbeAndLockPages
* IoAllocateMdl
* IofCompleteRequest
* IoCreateSymbolicLink
* IoCreateDevice
* KeBugCheckEx
{{< /details >}}
#### ExportedFunctions
{{< details "Expand" >}}{{< /details >}}
| Filename | CITMDRV_AMD64.sys |
|:---- | ---- | 
| MD5 | <a href="https://www.virustotal.com/gui/file/296bde4d0ed32c6069eb90c502187d0d">296bde4d0ed32c6069eb90c502187d0d</a> |
| SHA1 | <a href="https://www.virustotal.com/gui/file/ace6b9e34e3e2e73fe584f3bbdb4e4ec106e0a7d">ace6b9e34e3e2e73fe584f3bbdb4e4ec106e0a7d</a> |
| SHA256 | <a href="https://www.virustotal.com/gui/file/81939e5c12bd627ff268e9887d6fb57e95e6049f28921f3437898757e7f21469">81939e5c12bd627ff268e9887d6fb57e95e6049f28921f3437898757e7f21469</a> |
| Authentihash MD5 | <a href="https://www.virustotal.com/gui/search/authentihash%6df250bd96e46a522bd7536100737f13">6df250bd96e46a522bd7536100737f13</a> || Authentihash SHA1 | <a href="https://www.virustotal.com/gui/search/authentihash%d917e8e8aee2cb3d01d1ba123098654cf370689f">d917e8e8aee2cb3d01d1ba123098654cf370689f</a> || Authentihash SHA256 | <a href="https://www.virustotal.com/gui/search/authentihash%5be61901f41d55e6fbd0994869015448f8eb0450ae38f67b75ddb594c3325aac">5be61901f41d55e6fbd0994869015448f8eb0450ae38f67b75ddb594c3325aac</a> || Publisher | IBM Polska Sp. z o.o. || Signature | IBM Polska Sp. z o.o., VeriSign Class 3 Code Signing 2010 CA, VeriSign   |
#### Imports
{{< details "Expand" >}}* ntoskrnl.exe
{{< /details >}}
#### ImportedFunctions
{{< details "Expand" >}}* ZwClose
* ZwOpenFile
* RtlInitUnicodeString
* ZwWriteFile
* DbgPrint
* ZwCreateFile
* vsprintf
* IoDeleteDevice
* IoDeleteSymbolicLink
* ZwMapViewOfSection
* ZwUnmapViewOfSection
* __C_specific_handler
* IoFreeMdl
* MmUnlockPages
* ZwOpenSection
* MmProbeAndLockPages
* IoAllocateMdl
* IofCompleteRequest
* IoCreateSymbolicLink
* IoCreateDevice
* KeBugCheckEx
{{< /details >}}
#### ExportedFunctions
{{< details "Expand" >}}{{< /details >}}
| Filename | CITMDRV_AMD64.sys |
|:---- | ---- | 
| MD5 | <a href="https://www.virustotal.com/gui/file/d1bac75205c389d6d5d6418f0457c29b">d1bac75205c389d6d5d6418f0457c29b</a> |
| SHA1 | <a href="https://www.virustotal.com/gui/file/4268f30b79ce125a81d0d588bef0d4e2ad409bbb">4268f30b79ce125a81d0d588bef0d4e2ad409bbb</a> |
| SHA256 | <a href="https://www.virustotal.com/gui/file/9790a7b9d624b2b18768bb655dda4a05a9929633cef0b1521e79e40d7de0a05b">9790a7b9d624b2b18768bb655dda4a05a9929633cef0b1521e79e40d7de0a05b</a> |
| Authentihash MD5 | <a href="https://www.virustotal.com/gui/search/authentihash%6df250bd96e46a522bd7536100737f13">6df250bd96e46a522bd7536100737f13</a> || Authentihash SHA1 | <a href="https://www.virustotal.com/gui/search/authentihash%d917e8e8aee2cb3d01d1ba123098654cf370689f">d917e8e8aee2cb3d01d1ba123098654cf370689f</a> || Authentihash SHA256 | <a href="https://www.virustotal.com/gui/search/authentihash%5be61901f41d55e6fbd0994869015448f8eb0450ae38f67b75ddb594c3325aac">5be61901f41d55e6fbd0994869015448f8eb0450ae38f67b75ddb594c3325aac</a> || Publisher | IBM Polska Sp. z o.o. || Signature | IBM Polska Sp. z o.o., VeriSign Class 3 Code Signing 2009-2 CA, VeriSign Class 3 Public Primary CA   |
#### Imports
{{< details "Expand" >}}* ntoskrnl.exe
{{< /details >}}
#### ImportedFunctions
{{< details "Expand" >}}* ZwClose
* ZwOpenFile
* RtlInitUnicodeString
* ZwWriteFile
* DbgPrint
* ZwCreateFile
* vsprintf
* IoDeleteDevice
* IoDeleteSymbolicLink
* ZwMapViewOfSection
* ZwUnmapViewOfSection
* __C_specific_handler
* IoFreeMdl
* MmUnlockPages
* ZwOpenSection
* MmProbeAndLockPages
* IoAllocateMdl
* IofCompleteRequest
* IoCreateSymbolicLink
* IoCreateDevice
* KeBugCheckEx
{{< /details >}}
#### ExportedFunctions
{{< details "Expand" >}}{{< /details >}}
| Filename | CITMDRV_AMD64.sys |
|:---- | ---- | 
| MD5 | <a href="https://www.virustotal.com/gui/file/b2a9ac0600b12ec9819e049d7a6a0b75">b2a9ac0600b12ec9819e049d7a6a0b75</a> |
| SHA1 | <a href="https://www.virustotal.com/gui/file/c834c4931b074665d56ccab437dfcc326649d612">c834c4931b074665d56ccab437dfcc326649d612</a> |
| SHA256 | <a href="https://www.virustotal.com/gui/file/9a1d66036b0868bbb1b2823209fedea61a301d5dd245f8e7d390bd31e52d663e">9a1d66036b0868bbb1b2823209fedea61a301d5dd245f8e7d390bd31e52d663e</a> |
| Authentihash MD5 | <a href="https://www.virustotal.com/gui/search/authentihash%6df250bd96e46a522bd7536100737f13">6df250bd96e46a522bd7536100737f13</a> || Authentihash SHA1 | <a href="https://www.virustotal.com/gui/search/authentihash%d917e8e8aee2cb3d01d1ba123098654cf370689f">d917e8e8aee2cb3d01d1ba123098654cf370689f</a> || Authentihash SHA256 | <a href="https://www.virustotal.com/gui/search/authentihash%5be61901f41d55e6fbd0994869015448f8eb0450ae38f67b75ddb594c3325aac">5be61901f41d55e6fbd0994869015448f8eb0450ae38f67b75ddb594c3325aac</a> || Publisher | IBM Polska Sp. z o.o. || Signature | IBM Polska Sp. z o.o., Symantec Class 3 SHA256 Code Signing CA, VeriSign   |
#### Imports
{{< details "Expand" >}}* ntoskrnl.exe
{{< /details >}}
#### ImportedFunctions
{{< details "Expand" >}}* ZwClose
* ZwOpenFile
* RtlInitUnicodeString
* ZwWriteFile
* DbgPrint
* ZwCreateFile
* vsprintf
* IoDeleteDevice
* IoDeleteSymbolicLink
* ZwMapViewOfSection
* ZwUnmapViewOfSection
* __C_specific_handler
* IoFreeMdl
* MmUnlockPages
* ZwOpenSection
* MmProbeAndLockPages
* IoAllocateMdl
* IofCompleteRequest
* IoCreateSymbolicLink
* IoCreateDevice
* KeBugCheckEx
{{< /details >}}
#### ExportedFunctions
{{< details "Expand" >}}{{< /details >}}
| Filename | CITMDRV_AMD64.sys |
|:---- | ---- | 
| MD5 | <a href="https://www.virustotal.com/gui/file/79f7e6f98a5d3ab6601622be4471027f">79f7e6f98a5d3ab6601622be4471027f</a> |
| SHA1 | <a href="https://www.virustotal.com/gui/file/8f5cd4a56e6e15935491aa40adb1ecad61eafe7c">8f5cd4a56e6e15935491aa40adb1ecad61eafe7c</a> |
| SHA256 | <a href="https://www.virustotal.com/gui/file/aa9ab1195dc866270e984f1bed5e1358d6ef24c515dfdb6c2a92d1e1b94bf608">aa9ab1195dc866270e984f1bed5e1358d6ef24c515dfdb6c2a92d1e1b94bf608</a> |
| Authentihash MD5 | <a href="https://www.virustotal.com/gui/search/authentihash%6df250bd96e46a522bd7536100737f13">6df250bd96e46a522bd7536100737f13</a> || Authentihash SHA1 | <a href="https://www.virustotal.com/gui/search/authentihash%d917e8e8aee2cb3d01d1ba123098654cf370689f">d917e8e8aee2cb3d01d1ba123098654cf370689f</a> || Authentihash SHA256 | <a href="https://www.virustotal.com/gui/search/authentihash%5be61901f41d55e6fbd0994869015448f8eb0450ae38f67b75ddb594c3325aac">5be61901f41d55e6fbd0994869015448f8eb0450ae38f67b75ddb594c3325aac</a> || Publisher | IBM Polska Sp. z o.o. || Signature | IBM Polska Sp. z o.o., VeriSign Class 3 Code Signing 2009-2 CA, VeriSign Class 3 Public Primary Certification Authority (PCA3 G1 SHA1)   |
#### Imports
{{< details "Expand" >}}* ntoskrnl.exe
{{< /details >}}
#### ImportedFunctions
{{< details "Expand" >}}* ZwClose
* ZwOpenFile
* RtlInitUnicodeString
* ZwWriteFile
* DbgPrint
* ZwCreateFile
* vsprintf
* IoDeleteDevice
* IoDeleteSymbolicLink
* ZwMapViewOfSection
* ZwUnmapViewOfSection
* __C_specific_handler
* IoFreeMdl
* MmUnlockPages
* ZwOpenSection
* MmProbeAndLockPages
* IoAllocateMdl
* IofCompleteRequest
* IoCreateSymbolicLink
* IoCreateDevice
* KeBugCheckEx
{{< /details >}}
#### ExportedFunctions
{{< details "Expand" >}}{{< /details >}}
| Filename | CITMDRV_AMD64.sys |
|:---- | ---- | 
| MD5 | <a href="https://www.virustotal.com/gui/file/2d465b4487dc81effaa84f122b71c24f">2d465b4487dc81effaa84f122b71c24f</a> |
| SHA1 | <a href="https://www.virustotal.com/gui/file/51b60eaa228458dee605430aae1bc26f3fc62325">51b60eaa228458dee605430aae1bc26f3fc62325</a> |
| SHA256 | <a href="https://www.virustotal.com/gui/file/af095de15a16255ca1b2c27dad365dff9ac32d2a75e8e288f5a1307680781685">af095de15a16255ca1b2c27dad365dff9ac32d2a75e8e288f5a1307680781685</a> |
| Authentihash MD5 | <a href="https://www.virustotal.com/gui/search/authentihash%6df250bd96e46a522bd7536100737f13">6df250bd96e46a522bd7536100737f13</a> || Authentihash SHA1 | <a href="https://www.virustotal.com/gui/search/authentihash%d917e8e8aee2cb3d01d1ba123098654cf370689f">d917e8e8aee2cb3d01d1ba123098654cf370689f</a> || Authentihash SHA256 | <a href="https://www.virustotal.com/gui/search/authentihash%5be61901f41d55e6fbd0994869015448f8eb0450ae38f67b75ddb594c3325aac">5be61901f41d55e6fbd0994869015448f8eb0450ae38f67b75ddb594c3325aac</a> || Publisher | IBM Polska Sp. z o.o. || Signature | IBM Polska Sp. z o.o., VeriSign Class 3 Code Signing 2009-2 CA, VeriSign Class 3 Public Primary CA   |
#### Imports
{{< details "Expand" >}}* ntoskrnl.exe
{{< /details >}}
#### ImportedFunctions
{{< details "Expand" >}}* ZwClose
* ZwOpenFile
* RtlInitUnicodeString
* ZwWriteFile
* DbgPrint
* ZwCreateFile
* vsprintf
* IoDeleteDevice
* IoDeleteSymbolicLink
* ZwMapViewOfSection
* ZwUnmapViewOfSection
* __C_specific_handler
* IoFreeMdl
* MmUnlockPages
* ZwOpenSection
* MmProbeAndLockPages
* IoAllocateMdl
* IofCompleteRequest
* IoCreateSymbolicLink
* IoCreateDevice
* KeBugCheckEx
{{< /details >}}
#### ExportedFunctions
{{< details "Expand" >}}{{< /details >}}
| Filename | CITMDRV_AMD64.sys |
|:---- | ---- | 
| MD5 | <a href="https://www.virustotal.com/gui/file/4d17b32be70ef39eae5d5edeb5e89877">4d17b32be70ef39eae5d5edeb5e89877</a> |
| SHA1 | <a href="https://www.virustotal.com/gui/file/3270720a066492b046d7180ca6e60602c764cac7">3270720a066492b046d7180ca6e60602c764cac7</a> |
| SHA256 | <a href="https://www.virustotal.com/gui/file/d5586dc1e61796a9ae5e5d1ced397874753056c3df2eb963a8916287e1929a71">d5586dc1e61796a9ae5e5d1ced397874753056c3df2eb963a8916287e1929a71</a> |
| Authentihash MD5 | <a href="https://www.virustotal.com/gui/search/authentihash%6df250bd96e46a522bd7536100737f13">6df250bd96e46a522bd7536100737f13</a> || Authentihash SHA1 | <a href="https://www.virustotal.com/gui/search/authentihash%d917e8e8aee2cb3d01d1ba123098654cf370689f">d917e8e8aee2cb3d01d1ba123098654cf370689f</a> || Authentihash SHA256 | <a href="https://www.virustotal.com/gui/search/authentihash%5be61901f41d55e6fbd0994869015448f8eb0450ae38f67b75ddb594c3325aac">5be61901f41d55e6fbd0994869015448f8eb0450ae38f67b75ddb594c3325aac</a> || Publisher | IBM Polska Sp. z o.o. || Signature | IBM Polska Sp. z o.o., VeriSign Class 3 Code Signing 2009-2 CA, VeriSign Class 3 Public Primary CA   |
#### Imports
{{< details "Expand" >}}* ntoskrnl.exe
{{< /details >}}
#### ImportedFunctions
{{< details "Expand" >}}* ZwClose
* ZwOpenFile
* RtlInitUnicodeString
* ZwWriteFile
* DbgPrint
* ZwCreateFile
* vsprintf
* IoDeleteDevice
* IoDeleteSymbolicLink
* ZwMapViewOfSection
* ZwUnmapViewOfSection
* __C_specific_handler
* IoFreeMdl
* MmUnlockPages
* ZwOpenSection
* MmProbeAndLockPages
* IoAllocateMdl
* IofCompleteRequest
* IoCreateSymbolicLink
* IoCreateDevice
* KeBugCheckEx
{{< /details >}}
#### ExportedFunctions
{{< details "Expand" >}}{{< /details >}}
| Filename | CITMDRV_AMD64.sys |
|:---- | ---- | 
| MD5 | <a href="https://www.virustotal.com/gui/file/c1d3a6bb423739a5e781f7eee04c9cfd">c1d3a6bb423739a5e781f7eee04c9cfd</a> |
| SHA1 | <a href="https://www.virustotal.com/gui/file/2a6e6bd51c7062ad24c02a4d2c1b5e948908d131">2a6e6bd51c7062ad24c02a4d2c1b5e948908d131</a> |
| SHA256 | <a href="https://www.virustotal.com/gui/file/d8459f7d707c635e2c04d6d6d47b63f73ba3f6629702c7a6e0df0462f6478ae2">d8459f7d707c635e2c04d6d6d47b63f73ba3f6629702c7a6e0df0462f6478ae2</a> |
| Authentihash MD5 | <a href="https://www.virustotal.com/gui/search/authentihash%6df250bd96e46a522bd7536100737f13">6df250bd96e46a522bd7536100737f13</a> || Authentihash SHA1 | <a href="https://www.virustotal.com/gui/search/authentihash%d917e8e8aee2cb3d01d1ba123098654cf370689f">d917e8e8aee2cb3d01d1ba123098654cf370689f</a> || Authentihash SHA256 | <a href="https://www.virustotal.com/gui/search/authentihash%5be61901f41d55e6fbd0994869015448f8eb0450ae38f67b75ddb594c3325aac">5be61901f41d55e6fbd0994869015448f8eb0450ae38f67b75ddb594c3325aac</a> || Publisher | IBM Polska Sp. z o.o. || Signature | IBM Polska Sp. z o.o., VeriSign Class 3 Code Signing 2009-2 CA, VeriSign Class 3 Public Primary CA   |
#### Imports
{{< details "Expand" >}}* ntoskrnl.exe
{{< /details >}}
#### ImportedFunctions
{{< details "Expand" >}}* ZwClose
* ZwOpenFile
* RtlInitUnicodeString
* ZwWriteFile
* DbgPrint
* ZwCreateFile
* vsprintf
* IoDeleteDevice
* IoDeleteSymbolicLink
* ZwMapViewOfSection
* ZwUnmapViewOfSection
* __C_specific_handler
* IoFreeMdl
* MmUnlockPages
* ZwOpenSection
* MmProbeAndLockPages
* IoAllocateMdl
* IofCompleteRequest
* IoCreateSymbolicLink
* IoCreateDevice
* KeBugCheckEx
{{< /details >}}
#### ExportedFunctions
{{< details "Expand" >}}{{< /details >}}
| Filename | CITMDRV_AMD64.sys |
|:---- | ---- | 
| MD5 | <a href="https://www.virustotal.com/gui/file/054299e09cea38df2b84e6b29348b418">054299e09cea38df2b84e6b29348b418</a> |
| SHA1 | <a href="https://www.virustotal.com/gui/file/19bd488fe54b011f387e8c5d202a70019a204adf">19bd488fe54b011f387e8c5d202a70019a204adf</a> |
| SHA256 | <a href="https://www.virustotal.com/gui/file/e81230217988f3e7ec6f89a06d231ec66039bdba340fd8ebb2bbb586506e3293">e81230217988f3e7ec6f89a06d231ec66039bdba340fd8ebb2bbb586506e3293</a> |
| Authentihash MD5 | <a href="https://www.virustotal.com/gui/search/authentihash%6df250bd96e46a522bd7536100737f13">6df250bd96e46a522bd7536100737f13</a> || Authentihash SHA1 | <a href="https://www.virustotal.com/gui/search/authentihash%d917e8e8aee2cb3d01d1ba123098654cf370689f">d917e8e8aee2cb3d01d1ba123098654cf370689f</a> || Authentihash SHA256 | <a href="https://www.virustotal.com/gui/search/authentihash%5be61901f41d55e6fbd0994869015448f8eb0450ae38f67b75ddb594c3325aac">5be61901f41d55e6fbd0994869015448f8eb0450ae38f67b75ddb594c3325aac</a> || Publisher | IBM Polska Sp. z o.o. || Signature | IBM Polska Sp. z o.o., Symantec Class 3 SHA256 Code Signing CA, VeriSign   |
#### Imports
{{< details "Expand" >}}* ntoskrnl.exe
{{< /details >}}
#### ImportedFunctions
{{< details "Expand" >}}* ZwClose
* ZwOpenFile
* RtlInitUnicodeString
* ZwWriteFile
* DbgPrint
* ZwCreateFile
* vsprintf
* IoDeleteDevice
* IoDeleteSymbolicLink
* ZwMapViewOfSection
* ZwUnmapViewOfSection
* __C_specific_handler
* IoFreeMdl
* MmUnlockPages
* ZwOpenSection
* MmProbeAndLockPages
* IoAllocateMdl
* IofCompleteRequest
* IoCreateSymbolicLink
* IoCreateDevice
* KeBugCheckEx
{{< /details >}}
#### ExportedFunctions
{{< details "Expand" >}}{{< /details >}}
| Filename | CITMDRV_AMD64.sys |
|:---- | ---- | 
| MD5 | <a href="https://www.virustotal.com/gui/file/0ba6afe0ea182236f98365bd977adfdf">0ba6afe0ea182236f98365bd977adfdf</a> |
| SHA1 | <a href="https://www.virustotal.com/gui/file/a6fe4f30ca7cb94d74bc6d42cdd09a136056952e">a6fe4f30ca7cb94d74bc6d42cdd09a136056952e</a> |
| SHA256 | <a href="https://www.virustotal.com/gui/file/f88ebb633406a086d9cca6bc8b66a4ea940c5476529f9033a9e0463512a23a57">f88ebb633406a086d9cca6bc8b66a4ea940c5476529f9033a9e0463512a23a57</a> |
| Authentihash MD5 | <a href="https://www.virustotal.com/gui/search/authentihash%6df250bd96e46a522bd7536100737f13">6df250bd96e46a522bd7536100737f13</a> || Authentihash SHA1 | <a href="https://www.virustotal.com/gui/search/authentihash%d917e8e8aee2cb3d01d1ba123098654cf370689f">d917e8e8aee2cb3d01d1ba123098654cf370689f</a> || Authentihash SHA256 | <a href="https://www.virustotal.com/gui/search/authentihash%5be61901f41d55e6fbd0994869015448f8eb0450ae38f67b75ddb594c3325aac">5be61901f41d55e6fbd0994869015448f8eb0450ae38f67b75ddb594c3325aac</a> || Publisher | IBM Polska Sp. z o.o. || Signature | IBM Polska Sp. z o.o., Symantec Class 3 SHA256 Code Signing CA, VeriSign   |
#### Imports
{{< details "Expand" >}}* ntoskrnl.exe
{{< /details >}}
#### ImportedFunctions
{{< details "Expand" >}}* ZwClose
* ZwOpenFile
* RtlInitUnicodeString
* ZwWriteFile
* DbgPrint
* ZwCreateFile
* vsprintf
* IoDeleteDevice
* IoDeleteSymbolicLink
* ZwMapViewOfSection
* ZwUnmapViewOfSection
* __C_specific_handler
* IoFreeMdl
* MmUnlockPages
* ZwOpenSection
* MmProbeAndLockPages
* IoAllocateMdl
* IofCompleteRequest
* IoCreateSymbolicLink
* IoCreateDevice
* KeBugCheckEx
{{< /details >}}
#### ExportedFunctions
{{< details "Expand" >}}{{< /details >}}



[*source*](https://github.com/magicsword-io/LOLDrivers/tree/main/yaml/citmdrv_amd64.yaml)

*last_updated:* 2023-04-15








{{< /column >}}
{{< /block >}}
