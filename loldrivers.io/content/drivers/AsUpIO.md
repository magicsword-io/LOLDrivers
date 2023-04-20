+++

description = ""
title = "AsUpIO.sys"
weight = 10

+++


{{< block "grid-1" >}}
{{< column "mt-2 pt-1">}}


# AsUpIO.sys ![:inline](/images/twitter_verified.png) 


### Description

AsUpIO.sys is a vulnerable driver and more information will be added as found.

- **Created**: 2023-01-09
- **Author**: Michael Haag
- **Acknowledgement**:  | [](https://twitter.com/)

{{< button "https://github.com/magicsword-io/LOLDrivers/raw/main/drivers/6d4159694e1754f262e326b52a3b305a.bin" "Download" >}}
{{< tip "warning" >}}
This download link contains the vulnerable driver!

{{< /tip >}}

### Commands

```
sc.exe create AsUpIO.sys binPath=C:\windows\temp\AsUpIO.sys type=kernel &amp;&amp; sc.exe start AsUpIO.sys
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
| Filename           | AsUpIO.sys |
| MD5                | [6d4159694e1754f262e326b52a3b305a](https://www.virustotal.com/gui/file/6d4159694e1754f262e326b52a3b305a) |
| SHA1               | [d5fd9fe10405c4f90235e583526164cd0902ed86](https://www.virustotal.com/gui/file/d5fd9fe10405c4f90235e583526164cd0902ed86) |
| SHA256             | [b9a4e40a5d80fedd1037eaed958f9f9efed41eb01ada73d51b5dcd86e27e0cbf](https://www.virustotal.com/gui/file/b9a4e40a5d80fedd1037eaed958f9f9efed41eb01ada73d51b5dcd86e27e0cbf) |
| Authentihash MD5   | [3e6db96f242c0c3115075add7d7847a0](https://www.virustotal.com/gui/search/authentihash%253A3e6db96f242c0c3115075add7d7847a0) |
| Authentihash SHA1  | [c5da546e0af6119f033a5d4ed79e7f5d90c004ff](https://www.virustotal.com/gui/search/authentihash%253Ac5da546e0af6119f033a5d4ed79e7f5d90c004ff) |
| Authentihash SHA256| [70870e20f563899e4f05be2d0049cb495552b409ca7f4729a335bcbfffc3f47c](https://www.virustotal.com/gui/search/authentihash%253A70870e20f563899e4f05be2d0049cb495552b409ca7f4729a335bcbfffc3f47c) |
| Publisher         | ASUSTeK Computer Inc. |
| Signature         | ASUSTeK Computer Inc., VeriSign Class 3 Code Signing 2009-2 CA, VeriSign Class 3 Public Primary CA   |


#### Imports
{{< details "Expand" >}}
* ntoskrnl.exe
* HAL.dll

{{< /details >}}
#### ImportedFunctions
{{< details "Expand" >}}
* ZwClose
* ObReferenceObjectByHandle
* ZwOpenSection
* RtlInitUnicodeString
* IoDeleteDevice
* IoDeleteSymbolicLink
* ZwMapViewOfSection
* MmGetPhysicalAddress
* MmAllocateContiguousMemory
* ZwUnmapViewOfSection
* IoIs32bitProcess
* IoCreateSymbolicLink
* IoCreateDevice
* IofCompleteRequest
* KeDelayExecutionThread
* HalTranslateBusAddress

{{< /details >}}
#### ExportedFunctions
{{< details "Expand" >}}

{{< /details >}}
-----



[*source*](https://github.com/magicsword-io/LOLDrivers/tree/main/yaml/asupio.yaml)

*last_updated:* 2023-04-20








{{< /column >}}
{{< /block >}}
