+++

description = ""
title = "PanIO.sys"
weight = 10

+++


{{< block "grid-1" >}}
{{< column "mt-2 pt-1">}}


# PanIO.sys 


{{< tip "warning" >}}
We were not able to verify the hash of this driver successfully, it has not been confirmed.
{{< /tip >}}


### Description

PanIO.sys is a vulnerable driver and more information will be added as found.

- **Created**: 2023-01-09
- **Author**: Michael Haag
- **Acknowledgement**:  | [](https://twitter.com/)

{{< button "https://github.com/magicsword-io/LOLDrivers/raw/main/drivers/9a9dbf5107848c254381be67a4c1b1dd.bin" "Download" >}}
{{< tip "warning" >}}
This download link contains the vulnerable driver!

{{< /tip >}}

### Commands

```
sc.exe create PanIO.sys binPath=C:\windows\temp\PanIO.sys type=kernel &amp;&amp; sc.exe start PanIO.sys
```

| Use Case | Privileges | Operating System | 
|:---- | ---- | ---- |
| Elevate privileges | kernel | Windows 10 |

### Resources
<br>
<li><a href=" https://learn.microsoft.com/en-us/windows/security/threat-protection/windows-defender-application-control/microsoft-recommended-driver-block-rules"> https://learn.microsoft.com/en-us/windows/security/threat-protection/windows-defender-application-control/microsoft-recommended-driver-block-rules</a></li>
<li><a href="https://learn.microsoft.com/en-us/windows/security/threat-protection/windows-defender-application-control/microsoft-recommended-driver-block-rules">https://learn.microsoft.com/en-us/windows/security/threat-protection/windows-defender-application-control/microsoft-recommended-driver-block-rules</a></li>
<br>

### Known Vulnerable Samples

| Property           | Value |
|:-------------------|:------|
| Filename           | PanIO.sys |
| MD5                | [9a9dbf5107848c254381be67a4c1b1dd](https://www.virustotal.com/gui/file/9a9dbf5107848c254381be67a4c1b1dd) |
| SHA1               | [291b4a88ffd2ac1d6bf812ecaedc2d934dc503cb](https://www.virustotal.com/gui/file/291b4a88ffd2ac1d6bf812ecaedc2d934dc503cb) |
| SHA256             | [f596e64f4c5d7c37a00493728d8756b243cfdc11e3372d6d6dfeffc13c9ab960](https://www.virustotal.com/gui/file/f596e64f4c5d7c37a00493728d8756b243cfdc11e3372d6d6dfeffc13c9ab960) |
| Authentihash MD5   | [5af91c612918020b1dbc829a040d1c88](https://www.virustotal.com/gui/search/authentihash%253A5af91c612918020b1dbc829a040d1c88) |
| Authentihash SHA1  | [b65163db28ef590620b8966f14ec78fe7788ac6c](https://www.virustotal.com/gui/search/authentihash%253Ab65163db28ef590620b8966f14ec78fe7788ac6c) |
| Authentihash SHA256| [f246b9d22b3ffe15f2e97f306d049020f38ed162150c97d7a72e3ae0b22c79ad](https://www.virustotal.com/gui/search/authentihash%253Af246b9d22b3ffe15f2e97f306d049020f38ed162150c97d7a72e3ae0b22c79ad) |
| Signature         | PAN YAZILIM BILISIM TEKNOLOJILERI TICARET LTD. STI., GlobalSign CodeSigning CA - G2, GlobalSign   |
| Company           | Pan Yazilim Bilisim Teknolojileri Tic. Ltd. Sti. |
| Description       | Temperature and system information driver |
| Product           | PanIO Library |
| OriginalFilename  | PanIO.sys |


#### Imports
{{< details "Expand" >}}
* ntoskrnl.exe
* HAL.dll

{{< /details >}}
#### ImportedFunctions
{{< details "Expand" >}}
* IoCreateSymbolicLink
* IofCompleteRequest
* KeTickCount
* MmMapIoSpace
* READ_REGISTER_BUFFER_ULONG
* READ_REGISTER_BUFFER_USHORT
* READ_REGISTER_BUFFER_UCHAR
* MmUnmapIoSpace
* RtlInitUnicodeString
* IoDeleteSymbolicLink
* IoCreateDevice
* IoDeleteDevice
* RtlUnwind
* KeBugCheckEx
* HalGetBusDataByOffset
* WRITE_PORT_ULONG
* WRITE_PORT_USHORT
* WRITE_PORT_UCHAR
* READ_PORT_ULONG
* READ_PORT_USHORT
* READ_PORT_UCHAR
* HalSetBusDataByOffset

{{< /details >}}
#### ExportedFunctions
{{< details "Expand" >}}

{{< /details >}}
-----



[*source*](https://github.com/magicsword-io/LOLDrivers/tree/main/yaml/panio.yaml)

*last_updated:* 2023-04-22








{{< /column >}}
{{< /block >}}
