+++

description = ""
title = "rtkio.sys"
weight = 10

+++


{{< block "grid-1" >}}
{{< column "mt-2 pt-1">}}


# rtkio.sys ![:inline](/images/twitter_verified.png) 


### Description

rtkio.sys is a vulnerable driver and more information will be added as found.

- **Created**: 2023-01-09
- **Author**: Michael Haag
- **Acknowledgement**:  | [](https://twitter.com/)

{{< button "https://github.com/magicsword-io/LOLDrivers/raw/main/drivers/daf800da15b33bf1a84ee7afc59f0656.bin" "Download" >}}
{{< tip "warning" >}}
This download link contains the vulnerable driver!

{{< /tip >}}

### Commands

```
sc.exe create rtkio.sys binPath=C:\windows\temp\rtkio.sys type=kernel &amp;&amp; sc.exe start rtkio.sys
```

| Use Case | Privileges | Operating System | 
|:---- | ---- | ---- |
| Elevate privileges | kernel | Windows 10 |

### Resources
<br>
<li><a href=" https://github.com/elastic/protections-artifacts/search?q=VulnDriver"> https://github.com/elastic/protections-artifacts/search?q=VulnDriver</a></li>
<li><a href="https://github.com/elastic/protections-artifacts/search?q=VulnDriver">https://github.com/elastic/protections-artifacts/search?q=VulnDriver</a></li>
<br>

### Known Vulnerable Samples

| Property           | Value |
|:-------------------|:------|
| Filename           | rtkio.sys |
| MD5                | [daf800da15b33bf1a84ee7afc59f0656](https://www.virustotal.com/gui/file/daf800da15b33bf1a84ee7afc59f0656) |
| SHA1               | [166759fd511613414d3213942fe2575b926a6226](https://www.virustotal.com/gui/file/166759fd511613414d3213942fe2575b926a6226) |
| SHA256             | [478917514be37b32d5ccf76e4009f6f952f39f5553953544f1b0688befd95e82](https://www.virustotal.com/gui/file/478917514be37b32d5ccf76e4009f6f952f39f5553953544f1b0688befd95e82) |
| Authentihash MD5   | [d543d754cbb1d404d62b6c574a1aa3cd](https://www.virustotal.com/gui/search/authentihash%253Ad543d754cbb1d404d62b6c574a1aa3cd) |
| Authentihash SHA1  | [daca8d39b72bbe8a5b6d5fa35bbb4ecef198a359](https://www.virustotal.com/gui/search/authentihash%253Adaca8d39b72bbe8a5b6d5fa35bbb4ecef198a359) |
| Authentihash SHA256| [e657e54c341d37881837dbaf553e10bbe31ff2d6ccf9ca939ca5433ec464a73b](https://www.virustotal.com/gui/search/authentihash%253Ae657e54c341d37881837dbaf553e10bbe31ff2d6ccf9ca939ca5433ec464a73b) |
| Signature         | Realtek Semiconductor Corp., DigiCert EV Code Signing CA, DigiCert   |
| Company           | Windows (R) Codename Longhorn DDK provider |
| Description       | Realtek IODriver |
| Product           | Windows (R) Codename Longhorn DDK driver |
| OriginalFilename  | rtkio.sys |


#### Imports
{{< details "Expand" >}}
* ntoskrnl.exe
* HAL.dll

{{< /details >}}
#### ImportedFunctions
{{< details "Expand" >}}
* KeSetSystemAffinityThread
* KeQueryActiveProcessors
* ExAllocatePool
* DbgPrint
* MmMapLockedPagesSpecifyCache
* MmUnmapLockedPages
* IoAllocateMdl
* MmMapIoSpace
* IoCreateSymbolicLink
* IoCreateDevice
* KeTickCount
* IoFreeMdl
* MmUnmapIoSpace
* ExFreePoolWithTag
* RtlInitUnicodeString
* IoDeleteSymbolicLink
* IoDeleteDevice
* MmBuildMdlForNonPagedPool
* IofCompleteRequest
* RtlUnwind
* KeBugCheckEx
* WRITE_PORT_ULONG
* READ_PORT_USHORT
* READ_PORT_ULONG
* READ_PORT_UCHAR
* KeStallExecutionProcessor
* WRITE_PORT_UCHAR
* WRITE_PORT_USHORT

{{< /details >}}
#### ExportedFunctions
{{< details "Expand" >}}

{{< /details >}}
-----



[*source*](https://github.com/magicsword-io/LOLDrivers/tree/main/yaml/rtkio.yaml)

*last_updated:* 2023-04-22








{{< /column >}}
{{< /block >}}
