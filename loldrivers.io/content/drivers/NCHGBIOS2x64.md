+++

description = ""
title = "NCHGBIOS2x64.SYS"
weight = 10

+++


{{< block "grid-1" >}}
{{< column "mt-2 pt-1">}}


# NCHGBIOS2x64.SYS ![:inline](/images/twitter_verified.png) 


### Description

NCHGBIOS2x64.SYS is a vulnerable driver and more information will be added as found.

- **Created**: 2023-01-09
- **Author**: Michael Haag
- **Acknowledgement**:  | [](https://twitter.com/)


{{< button "https://github.com/magicsword-io/LOLDrivers/raw/main/drivers/0ae30291c6cbfa7be39320badd6e8de0.bin" "Download" >}}

{{< tip "warning" >}}
This download link contains the malcious driver!
{{< /tip >}}

### Commands

```
sc.exe create NCHGBIOS2x64.SYS binPath=C:\windows\temp\NCHGBIOS2x64.SYS     type=kernel type=kernel &amp;&amp; sc.exe start NCHGBIOS2x64.SYS
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

| Filename | NCHGBIOS2x64.SYS |
|:---- | ---- | 
| MD5 | <a href="https://www.virustotal.com/gui/file/d9ce18960c23f38706ae9c6584d9ac90">d9ce18960c23f38706ae9c6584d9ac90</a> |
| SHA1 | <a href="https://www.virustotal.com/gui/file/d0d39e1061f30946141b6ecfa0957f8cc3ddeb63">d0d39e1061f30946141b6ecfa0957f8cc3ddeb63</a> |
| SHA256 | <a href="https://www.virustotal.com/gui/file/314384b40626800b1cde6fbc51ebc7d13e91398be2688c2a58354aa08d00b073">314384b40626800b1cde6fbc51ebc7d13e91398be2688c2a58354aa08d00b073</a> |
| Authentihash MD5 | <a href="https://www.virustotal.com/gui/search/authentihash%188d9708ba2de146c555d484668decee">188d9708ba2de146c555d484668decee</a> || Authentihash SHA1 | <a href="https://www.virustotal.com/gui/search/authentihash%bb209301f3785febdd7bdeb717cbd66340ad5c65">bb209301f3785febdd7bdeb717cbd66340ad5c65</a> || Authentihash SHA256 | <a href="https://www.virustotal.com/gui/search/authentihash%c4031eb0a40137c4ab6d2dbdd2755135c63ab137a0aeb74a7bbea6617b96f0a7">c4031eb0a40137c4ab6d2dbdd2755135c63ab137a0aeb74a7bbea6617b96f0a7</a> || Signature | TOSHIBA CORPORATION, VeriSign Class 3 Code Signing 2010 CA, VeriSign   || Company | TOSHIBA Corporation || Description | BIOS Update Driver For Windows x64 Edition || Product | TOSHIBA BIOS Package || OriginalFilename | NCHGBIOS2x64.SYS |
#### Imports
{{< details "Expand" >}}* ntoskrnl.exe
* HAL.dll
{{< /details >}}
#### ImportedFunctions
{{< details "Expand" >}}* MmFreeContiguousMemory
* MmUnmapIoSpace
* MmGetPhysicalAddress
* MmMapLockedPagesSpecifyCache
* MmMapIoSpace
* IoDeleteDevice
* RtlCompareMemory
* IoCreateSymbolicLink
* IoCreateDevice
* MmAllocateContiguousMemory
* KeBugCheckEx
* RtlInitUnicodeString
* IofCompleteRequest
* IoDeleteSymbolicLink
* HalGetBusDataByOffset
* HalSetBusDataByOffset
{{< /details >}}
#### ExportedFunctions
{{< details "Expand" >}}{{< /details >}}



[*source*](https://github.com/magicsword-io/LOLDrivers/tree/main/yaml/nchgbios2x64.yaml)

*last_updated:* 2023-04-15








{{< /column >}}
{{< /block >}}
