+++

description = ""
title = "UCOREW64.SYS"
weight = 10

+++


{{< block "grid-1" >}}
{{< column "mt-2 pt-1">}}


# UCOREW64.SYS ![:inline](/images/twitter_verified.png) 


### Description

UCOREW64.SYS is a vulnerable driver and more information will be added as found.

- **Created**: 2023-01-09
- **Author**: Michael Haag
- **Acknowledgement**:  | [](https://twitter.com/)

{{< button "https://github.com/magicsword-io/LOLDrivers/raw/main/drivers/a17c58c0582ee560c72f60764ed63224.bin" "Download" >}}
{{< tip "warning" >}}
This download link contains the vulnerable driver!

{{< /tip >}}

### Commands

```
sc.exe create UCOREW64.SYS binPath=C:\windows\temp\UCOREW64.SYS type=kernel &amp;&amp; sc.exe start UCOREW64.SYS
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
| Filename           | UCOREW64.SYS |
| MD5                | [a17c58c0582ee560c72f60764ed63224](https://www.virustotal.com/gui/file/a17c58c0582ee560c72f60764ed63224) |
| SHA1               | [bbc0b9fd67c8f4cefa3d76fcb29ff3cef996b825](https://www.virustotal.com/gui/file/bbc0b9fd67c8f4cefa3d76fcb29ff3cef996b825) |
| SHA256             | [a7c8f4faf3cbb088cac7753d81f8ec4c38ccb97cd9da817741f49272e8d01200](https://www.virustotal.com/gui/file/a7c8f4faf3cbb088cac7753d81f8ec4c38ccb97cd9da817741f49272e8d01200) |
| Authentihash MD5   | [6957cb828dd243621e2e67c948171264](https://www.virustotal.com/gui/search/authentihash%253A6957cb828dd243621e2e67c948171264) |
| Authentihash SHA1  | [c55173b926235b8678bddb9b49a1a8b9a92a1ada](https://www.virustotal.com/gui/search/authentihash%253Ac55173b926235b8678bddb9b49a1a8b9a92a1ada) |
| Authentihash SHA256| [f9c290ffc007e94fb61aecff42d267c1e626ec7939025b1a7d7285441d1c490d](https://www.virustotal.com/gui/search/authentihash%253Af9c290ffc007e94fb61aecff42d267c1e626ec7939025b1a7d7285441d1c490d) |
| Signature         | American Megatrends, Inc., VeriSign Class 3 Code Signing 2004 CA, VeriSign Class 3 Public Primary CA   |


#### Imports
{{< details "Expand" >}}
* ntoskrnl.exe
* HAL.dll

{{< /details >}}
#### ImportedFunctions
{{< details "Expand" >}}
* MmMapLockedPages
* MmBuildMdlForNonPagedPool
* IoAllocateMdl
* MmGetPhysicalAddress
* MmIsAddressValid
* MmAllocateContiguousMemory
* DbgPrint
* MmUnmapLockedPages
* MmMapIoSpace
* MmUnmapIoSpace
* IoFreeMdl
* ZwMapViewOfSection
* ObReferenceObjectByHandle
* ZwOpenSection
* RtlInitUnicodeString
* ZwUnmapViewOfSection
* IoDeleteDevice
* IoDeleteSymbolicLink
* IofCompleteRequest
* IoCreateSymbolicLink
* IoCreateDevice
* ZwClose
* MmFreeContiguousMemory
* HalTranslateBusAddress

{{< /details >}}
#### ExportedFunctions
{{< details "Expand" >}}

{{< /details >}}
-----



[*source*](https://github.com/magicsword-io/LOLDrivers/tree/main/yaml/ucorew64.yaml)

*last_updated:* 2023-04-20








{{< /column >}}
{{< /block >}}
