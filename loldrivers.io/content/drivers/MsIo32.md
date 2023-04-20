+++

description = ""
title = "MsIo32.sys"
weight = 10

+++


{{< block "grid-1" >}}
{{< column "mt-2 pt-1">}}


# MsIo32.sys ![:inline](/images/twitter_verified.png) 


### Description

The MsIo64.sys and MsIo32.sys drivers in Patriot Viper RGB before 1.1 allow local users (including low integrity processes) to read and write to arbitrary memory locations, and consequently gain NT AUTHORITY\SYSTEM privileges, by mapping \Device\PhysicalMemory into the calling process via ZwOpenSection and ZwMapViewOfSection.

- **Created**: 2023-01-09
- **Author**: Michael Haag
- **Acknowledgement**:  | [](https://twitter.com/)

{{< button "https://github.com/magicsword-io/LOLDrivers/raw/main/drivers/d9e7e5bcc5b01915dbcef7762a7fc329.bin" "Download" >}}
{{< tip "warning" >}}
This download link contains the vulnerable driver!

{{< /tip >}}

### Commands

```
sc.exe create MsIo32.sys binPath=C:\windows\temp\MsIo32.sys type=kernel &amp;&amp; sc.exe start MsIo32.sys
```

| Use Case | Privileges | Operating System | 
|:---- | ---- | ---- |
| Elevate privileges | kernel | Windows 10 |

### Resources
<br>
<li><a href=" https://github.com/elastic/protections-artifacts/search?q=VulnDriver"> https://github.com/elastic/protections-artifacts/search?q=VulnDriver</a></li>
<li><a href="https://www.activecyber.us/activelabs/viper-rgb-driver-local-privilege-escalation-cve-2019-18845">https://www.activecyber.us/activelabs/viper-rgb-driver-local-privilege-escalation-cve-2019-18845</a></li>
<li><a href="http://blog.rewolf.pl/blog/?p=1630">http://blog.rewolf.pl/blog/?p=1630</a></li>
<li><a href="https://github.com/elastic/protections-artifacts/search?q=VulnDriver">https://github.com/elastic/protections-artifacts/search?q=VulnDriver</a></li>
<br>

### Known Vulnerable Samples

| Property           | Value |
|:-------------------|:------|
| Filename           | MsIo32.sys |
| MD5                | [d9e7e5bcc5b01915dbcef7762a7fc329](https://www.virustotal.com/gui/file/d9e7e5bcc5b01915dbcef7762a7fc329) |
| SHA1               | [e6305dddd06490d7f87e3b06d09e9d4c1c643af0](https://www.virustotal.com/gui/file/e6305dddd06490d7f87e3b06d09e9d4c1c643af0) |
| SHA256             | [525d9b51a80ca0cd4c5889a96f857e73f3a80da1ffbae59851e0f51bdfb0b6cd](https://www.virustotal.com/gui/file/525d9b51a80ca0cd4c5889a96f857e73f3a80da1ffbae59851e0f51bdfb0b6cd) |
| Authentihash MD5   | [6491c34f274a0ed6258fadca85bd69fb](https://www.virustotal.com/gui/search/authentihash%253A6491c34f274a0ed6258fadca85bd69fb) |
| Authentihash SHA1  | [7e732acb7cfad9ba043a9350cdeff25d742becb8](https://www.virustotal.com/gui/search/authentihash%253A7e732acb7cfad9ba043a9350cdeff25d742becb8) |
| Authentihash SHA256| [7018d515a6c781ea6097ca71d0f0603ad0d689f7ec99db27fcacd492a9e86027](https://www.virustotal.com/gui/search/authentihash%253A7018d515a6c781ea6097ca71d0f0603ad0d689f7ec99db27fcacd492a9e86027) |
| Signature         | MICSYS Technology Co., Ltd., Symantec Class 3 Extended Validation Code Signing CA - G2, VeriSign   |


#### Imports
{{< details "Expand" >}}
* ntoskrnl.exe
* HAL.dll

{{< /details >}}
#### ImportedFunctions
{{< details "Expand" >}}
* RtlInitUnicodeString
* DbgPrint
* ZwClose
* ZwMapViewOfSection
* ObReferenceObjectByHandle
* ZwOpenSection
* IoDeleteSymbolicLink
* ZwUnmapViewOfSection
* IofCompleteRequest
* IoCreateSymbolicLink
* IoCreateDevice
* ObfDereferenceObject
* IoDeleteDevice
* HalTranslateBusAddress

{{< /details >}}
#### ExportedFunctions
{{< details "Expand" >}}

{{< /details >}}


[*source*](https://github.com/magicsword-io/LOLDrivers/tree/main/yaml/msio32.yaml)

*last_updated:* 2023-04-20








{{< /column >}}
{{< /block >}}
