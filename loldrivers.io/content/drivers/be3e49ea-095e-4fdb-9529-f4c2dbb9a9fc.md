+++

description = ""
title = "be3e49ea-095e-4fdb-9529-f4c2dbb9a9fc"
weight = 10

+++


{{< block "grid-1" >}}
{{< column "mt-2 pt-1">}}


# PhlashNT.sys ![:inline](/images/twitter_verified.png) 


### Description

be3e49ea-095e-4fdb-9529-f4c2dbb9a9fc is a vulnerable driver and more information will be added as found.
- **UUID**: be3e49ea-095e-4fdb-9529-f4c2dbb9a9fc
- **Created**: 2023-01-09
- **Author**: Michael Haag
- **Acknowledgement**:  | [](https://twitter.com/)

{{< button "https://github.com/magicsword-io/LOLDrivers/raw/main/drivers/e9e786bdba458b8b4f9e93d034f73d00.bin" "Download" >}}
{{< tip "warning" >}}
This download link contains the vulnerable driver!

{{< /tip >}}

### Commands

```
sc.exe create PhlashNT.sys binPath=C:\windows\temp\PhlashNT.sys type=kernel &amp;&amp; sc.exe start PhlashNT.sys
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

| Property           | Value |
|:-------------------|:------|
| Filename           | PhlashNT.sys |
| MD5                | [e9e786bdba458b8b4f9e93d034f73d00](https://www.virustotal.com/gui/file/e9e786bdba458b8b4f9e93d034f73d00) |
| SHA1               | [c6d349823bbb1f5b44bae91357895dba653c5861](https://www.virustotal.com/gui/file/c6d349823bbb1f5b44bae91357895dba653c5861) |
| SHA256             | [65db1b259e305a52042e07e111f4fa4af16542c8bacd33655f753ef642228890](https://www.virustotal.com/gui/file/65db1b259e305a52042e07e111f4fa4af16542c8bacd33655f753ef642228890) |
| Authentihash MD5   | [5cf72ecb15ffea87586783893b02c43d](https://www.virustotal.com/gui/search/authentihash%253A5cf72ecb15ffea87586783893b02c43d) |
| Authentihash SHA1  | [ef2d7210b761f158a0832083a8407b3ec2f99db9](https://www.virustotal.com/gui/search/authentihash%253Aef2d7210b761f158a0832083a8407b3ec2f99db9) |
| Authentihash SHA256| [cde02c7db90626bcfbfbbc1315d4ce18d4f15667fa57c16b9ac2b060507c62ad](https://www.virustotal.com/gui/search/authentihash%253Acde02c7db90626bcfbfbbc1315d4ce18d4f15667fa57c16b9ac2b060507c62ad) |
| Signature         | Phoenix Technology Ltd., VeriSign Class 3 Code Signing 2004 CA, VeriSign Class 3 Public Primary CA   |
| Company           | Phoenix Technologies, Ltd. |
| Description       | SWinFlash Driver for Windows NT |
| Product           | WinPhlash |
| OriginalFilename  | PHLASHNT.SYS |


#### Imports
{{< details "Expand" >}}
* ntoskrnl.exe

{{< /details >}}
#### ImportedFunctions
{{< details "Expand" >}}
* IoDeleteDevice
* IoCreateSymbolicLink
* IoCreateDevice
* RtlInitUnicodeString
* IoDeleteSymbolicLink
* IofCompleteRequest
* MmMapLockedPages
* RtlAssert
* DbgPrint
* MmMapIoSpace
* MmUnmapIoSpace
* ExFreePoolWithTag
* ExAllocatePoolWithTag

{{< /details >}}
#### ExportedFunctions
{{< details "Expand" >}}

{{< /details >}}
-----



[*source*](https://github.com/magicsword-io/LOLDrivers/tree/main/yaml/be3e49ea-095e-4fdb-9529-f4c2dbb9a9fc.yaml)

*last_updated:* 2023-05-07








{{< /column >}}
{{< /block >}}
