+++

description = ""
title = "SysInfo.sys"
weight = 10

+++


{{< block "grid-1" >}}
{{< column "mt-2 pt-1">}}


# SysInfo.sys ![:inline](/images/twitter_verified.png) 


### Description

SysInfo.sys is a vulnerable driver and more information will be added as found.

- **Created**: 2023-01-09
- **Author**: Michael Haag
- **Acknowledgement**:  | [](https://twitter.com/)


{{< button "https://github.com/magicsword-io/LOLDrivers/raw/main/drivers/0ae30291c6cbfa7be39320badd6e8de0.bin" "Download" >}}

{{< tip "warning" >}}
This download link contains the malcious driver!
{{< /tip >}}

### Commands

```
sc.exe create SysInfo.sys binPath=C:\windows\temp\SysInfo.sys type=kernel &amp;&amp; sc.exe start SysInfo.sys
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

| Filename | SysInfo.sys |
|:---- | ---- | 
| MD5 | <a href="https://www.virustotal.com/gui/file/5228b7a738dc90a06ae4f4a7412cb1e9">5228b7a738dc90a06ae4f4a7412cb1e9</a> |
| SHA1 | <a href="https://www.virustotal.com/gui/file/f0c463d29a5914b01e4607889094f1b7d95e7aaf">f0c463d29a5914b01e4607889094f1b7d95e7aaf</a> |
| SHA256 | <a href="https://www.virustotal.com/gui/file/7049f3c939efe76a5556c2a2c04386db51daf61d56b679f4868bb0983c996ebb">7049f3c939efe76a5556c2a2c04386db51daf61d56b679f4868bb0983c996ebb</a> |
| Authentihash MD5 | <a href="https://www.virustotal.com/gui/search/authentihash%0f56e9fddae9389425d93099ad609867">0f56e9fddae9389425d93099ad609867</a> || Authentihash SHA1 | <a href="https://www.virustotal.com/gui/search/authentihash%ca88f321631c1552e3e0bcd1f26ad3435cc9f1ae">ca88f321631c1552e3e0bcd1f26ad3435cc9f1ae</a> || Authentihash SHA256 | <a href="https://www.virustotal.com/gui/search/authentihash%a82d08ef67bdfccf0a2cf6d507c9fbb6ac42bd74bf2ade46ec07fe253deb6573">a82d08ef67bdfccf0a2cf6d507c9fbb6ac42bd74bf2ade46ec07fe253deb6573</a> || Signature | Noriyuki MIYAZAKI, GlobalSign ObjectSign CA, GlobalSign Primary Object Publishing CA, GlobalSign Root CA - R1   |
#### Imports
{{< details "Expand" >}}* ntoskrnl.exe
* HAL.dll
{{< /details >}}
#### ImportedFunctions
{{< details "Expand" >}}* RtlInitUnicodeString
* __C_specific_handler
* MmUnmapIoSpace
* MmMapIoSpace
* IoDisconnectInterrupt
* IoConnectInterrupt
* IoCreateDevice
* KeInsertQueueDpc
* ZwClose
* IoDeleteSymbolicLink
* IofCompleteRequest
* KeInitializeDpc
* IoCreateSymbolicLink
* KeClearEvent
* IoDeleteDevice
* HalGetBusDataByOffset
* HalSetBusDataByOffset
{{< /details >}}
#### ExportedFunctions
{{< details "Expand" >}}{{< /details >}}



[*source*](https://github.com/magicsword-io/LOLDrivers/tree/main/yaml/sysinfo.yaml)

*last_updated:* 2023-04-15








{{< /column >}}
{{< /block >}}
