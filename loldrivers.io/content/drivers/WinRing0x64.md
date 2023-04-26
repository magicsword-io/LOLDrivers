+++

description = ""
title = "WinRing0x64.sys"
weight = 10

+++


{{< block "grid-1" >}}
{{< column "mt-2 pt-1">}}


# WinRing0x64.sys ![:inline](/images/twitter_verified.png) 


### Description

WinRing0x64.sys is a vulnerable driver and more information will be added as found.

- **Created**: 2023-01-09
- **Author**: Michael Haag
- **Acknowledgement**:  | [](https://twitter.com/)

{{< button "https://github.com/magicsword-io/LOLDrivers/raw/main/drivers/0c0195c48b6b8582fa6f6373032118da.bin" "Download" >}}
{{< tip "warning" >}}
This download link contains the vulnerable driver!

{{< /tip >}}

### Commands

```
sc.exe create WinRing0x64.sys binPath=C:\windows\temp\WinRing0x64.sys     type=kernel &amp;&amp; sc.exe start WinRing0x64.sys
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
| Filename           | WinRing0x64.sys |
| MD5                | [0c0195c48b6b8582fa6f6373032118da](https://www.virustotal.com/gui/file/0c0195c48b6b8582fa6f6373032118da) |
| SHA1               | [d25340ae8e92a6d29f599fef426a2bc1b5217299](https://www.virustotal.com/gui/file/d25340ae8e92a6d29f599fef426a2bc1b5217299) |
| SHA256             | [11bd2c9f9e2397c9a16e0990e4ed2cf0679498fe0fd418a3dfdac60b5c160ee5](https://www.virustotal.com/gui/file/11bd2c9f9e2397c9a16e0990e4ed2cf0679498fe0fd418a3dfdac60b5c160ee5) |
| Authentihash MD5   | [2bab314d894a026ac6073efe43c14a3d](https://www.virustotal.com/gui/search/authentihash%253A2bab314d894a026ac6073efe43c14a3d) |
| Authentihash SHA1  | [266821a39174d29f6f8791cf9f44f1a1f3439dda](https://www.virustotal.com/gui/search/authentihash%253A266821a39174d29f6f8791cf9f44f1a1f3439dda) |
| Authentihash SHA256| [1b845e5e43ce9e9b645ac198549e81f45c08197aad69708d96cdb9a719eb0e29](https://www.virustotal.com/gui/search/authentihash%253A1b845e5e43ce9e9b645ac198549e81f45c08197aad69708d96cdb9a719eb0e29) |
| Signature         | Noriyuki MIYAZAKI, GlobalSign ObjectSign CA, GlobalSign Primary Object Publishing CA, GlobalSign Root CA - R1   |
| Company           | OpenLibSys.org |
| Description       | WinRing0 |
| Product           | WinRing0 |
| OriginalFilename  | WinRing0.sys |


#### Imports
{{< details "Expand" >}}
* ntoskrnl.exe
* HAL.dll

{{< /details >}}
#### ImportedFunctions
{{< details "Expand" >}}
* IoDeleteSymbolicLink
* RtlInitUnicodeString
* IoDeleteDevice
* IoCreateDevice
* MmMapIoSpace
* KeBugCheckEx
* IoCreateSymbolicLink
* MmUnmapIoSpace
* IofCompleteRequest
* __C_specific_handler
* HalSetBusDataByOffset
* HalGetBusDataByOffset

{{< /details >}}
#### ExportedFunctions
{{< details "Expand" >}}

{{< /details >}}
-----



[*source*](https://github.com/magicsword-io/LOLDrivers/tree/main/yaml/winring0x64.yaml)

*last_updated:* 2023-04-26








{{< /column >}}
{{< /block >}}
