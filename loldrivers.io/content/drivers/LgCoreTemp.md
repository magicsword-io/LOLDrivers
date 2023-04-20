+++

description = ""
title = "LgCoreTemp.sys"
weight = 10

+++


{{< block "grid-1" >}}
{{< column "mt-2 pt-1">}}


# LgCoreTemp.sys ![:inline](/images/twitter_verified.png) 


### Description

LgCoreTemp.sys is a vulnerable driver and more information will be added as found.

- **Created**: 2023-04-15
- **Author**: Nasreddine Bencherchali
- **Acknowledgement**: Paolo Stagno | [Void_Sec](https://twitter.com/Void_Sec)

{{< button "https://github.com/magicsword-io/LOLDrivers/raw/main/drivers/2d7f1c02b94d6f0f3e10107e5ea8e141.bin" "Download" >}}
{{< tip "warning" >}}
This download link contains the vulnerable driver!

{{< /tip >}}

### Commands

```
sc.exe create LgCoreTemp.sys binPath=C:\windows\temp\LgCoreTemp.sys     type=kernel &amp;&amp; sc.exe start LgCoreTemp.sys
```

| Use Case | Privileges | Operating System | 
|:---- | ---- | ---- |
| Denial of Service | kernel | Windows 10 |

### Resources
<br>
<li><a href="https://github.com/VoidSec/Exploit-Development/tree/b82b6d3ac1cce66221101d3e0f4634aa64cb4ca7/windows/x64/kernel/logitech_v.9.02.65_DoS">https://github.com/VoidSec/Exploit-Development/tree/b82b6d3ac1cce66221101d3e0f4634aa64cb4ca7/windows/x64/kernel/logitech_v.9.02.65_DoS</a></li>
<br>

### Known Vulnerable Samples

| Filename | LgCoreTemp.sys |
|:---- | ---- | 
| MD5 | <a href="https://www.virustotal.com/gui/file/2d7f1c02b94d6f0f3e10107e5ea8e141">2d7f1c02b94d6f0f3e10107e5ea8e141</a> |
| SHA1 | <a href="https://www.virustotal.com/gui/file/471ca4b5bb5fe68543264dd52acb99fddd7b3c6d">471ca4b5bb5fe68543264dd52acb99fddd7b3c6d</a> |
| SHA256 | <a href="https://www.virustotal.com/gui/file/93b266f38c3c3eaab475d81597abbd7cc07943035068bb6fd670dbbe15de0131">93b266f38c3c3eaab475d81597abbd7cc07943035068bb6fd670dbbe15de0131</a> |
| Authentihash MD5 | <a href="https://www.virustotal.com/gui/search/authentihash%253Aa4c810e750095e71c0288c1ce6669115">a4c810e750095e71c0288c1ce6669115</a> || Authentihash SHA1 | <a href="https://www.virustotal.com/gui/search/authentihash%253Ae05304325b24fc9f76c106de27ffbef2d7eb3315">e05304325b24fc9f76c106de27ffbef2d7eb3315</a> || Authentihash SHA256 | <a href="https://www.virustotal.com/gui/search/authentihash%253A7f0eef1ed4c1278372348cb52e27dc3aa2f51a8b6a62db39d2af75031e55a8db">7f0eef1ed4c1278372348cb52e27dc3aa2f51a8b6a62db39d2af75031e55a8db</a> || Publisher | N/A || Signature | N, /, A   || Date | N/A || Company | Logitech || Description | CPU Core Temperature Monitor || Product | LgCoreTemp || OriginalFilename | LgCoreTemp.sys |
#### Imports
{{< details "Expand" >}}* ntoskrnl.exe
* HAL.dll
{{< /details >}}
#### ImportedFunctions
{{< details "Expand" >}}* IofCompleteRequest
* IoCreateDevice
* KeSetSystemAffinityThread
* IoDeleteDevice
* IoDeleteSymbolicLink
* __C_specific_handler
* KeRevertToUserAffinityThread
* IoCreateSymbolicLink
* RtlInitUnicodeString
* HalGetBusDataByOffset
{{< /details >}}
#### ExportedFunctions
{{< details "Expand" >}}{{< /details >}}



[*source*](https://github.com/magicsword-io/LOLDrivers/tree/main/yaml/lgcoretemp.yaml)

*last_updated:* 2023-04-19








{{< /column >}}
{{< /block >}}
