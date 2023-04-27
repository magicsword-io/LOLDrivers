+++

description = ""
title = "mydrivers.sys"
weight = 10

+++


{{< block "grid-1" >}}
{{< column "mt-2 pt-1">}}


# mydrivers.sys 


{{< tip "warning" >}}
We were not able to verify the hash of this driver successfully, it has not been confirmed.
{{< /tip >}}


### Description

mydrivers.sys is a vulnerable driver and more information will be added as found.

- **Created**: 2023-01-09
- **Author**: Michael Haag
- **Acknowledgement**:  | [](https://twitter.com/)

{{< button "https://github.com/magicsword-io/LOLDrivers/raw/main/drivers/507a649eb585d8d0447eab0532ef0c73.bin" "Download" >}}
{{< tip "warning" >}}
This download link contains the vulnerable driver!

{{< /tip >}}

### Commands

```
sc.exe create mydrivers.sys binPath=C:\windows\temp\mydrivers.sys type=kernel &amp;&amp; sc.exe start mydrivers.sys
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
| Filename           | mydrivers.sys |
| MD5                | [507a649eb585d8d0447eab0532ef0c73](https://www.virustotal.com/gui/file/507a649eb585d8d0447eab0532ef0c73) |
| SHA1               | [7859e75580570e23a1ef7208b9a76f81738043d5](https://www.virustotal.com/gui/file/7859e75580570e23a1ef7208b9a76f81738043d5) |
| SHA256             | [08eb2d2aa25c5f0af4e72a7e0126735536f6c2c05e9c7437282171afe5e322c6](https://www.virustotal.com/gui/file/08eb2d2aa25c5f0af4e72a7e0126735536f6c2c05e9c7437282171afe5e322c6) |
| Authentihash MD5   | [74a1e675b4fd736298bc24d082684b0e](https://www.virustotal.com/gui/search/authentihash%253A74a1e675b4fd736298bc24d082684b0e) |
| Authentihash SHA1  | [c57e38ce02ba45c3ad886faff98fe346560b1f5e](https://www.virustotal.com/gui/search/authentihash%253Ac57e38ce02ba45c3ad886faff98fe346560b1f5e) |
| Authentihash SHA256| [a689804c4e6e9aa07d48f9c99b7a1be6b05cba1c632b1a083b8031f6e1651c28](https://www.virustotal.com/gui/search/authentihash%253Aa689804c4e6e9aa07d48f9c99b7a1be6b05cba1c632b1a083b8031f6e1651c28) |
| Signature         | Beijing Kingsoft Security software Co.,Ltd, VeriSign Class 3 Code Signing 2010 CA, VeriSign   |
| Company           | MyDrivers.com |
| Description       | DriverGenius Hardware monitor |
| Product           | DriverGenius |
| OriginalFilename  | mydrivers.sys |


#### Imports
{{< details "Expand" >}}
* ntoskrnl.exe
* HAL.dll

{{< /details >}}
#### ImportedFunctions
{{< details "Expand" >}}
* WRITE_REGISTER_BUFFER_USHORT
* WRITE_REGISTER_BUFFER_ULONG
* IofCompleteRequest
* WRITE_REGISTER_BUFFER_UCHAR
* IoCreateDevice
* KeTickCount
* MmMapIoSpace
* READ_REGISTER_BUFFER_ULONG
* READ_REGISTER_BUFFER_USHORT
* READ_REGISTER_BUFFER_UCHAR
* MmUnmapIoSpace
* RtlInitUnicodeString
* IoDeleteSymbolicLink
* IoCreateSymbolicLink
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



[*source*](https://github.com/magicsword-io/LOLDrivers/tree/main/yaml/mydrivers.yaml)

*last_updated:* 2023-04-27








{{< /column >}}
{{< /block >}}
