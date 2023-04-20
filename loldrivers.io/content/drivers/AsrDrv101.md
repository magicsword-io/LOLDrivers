+++

description = ""
title = "AsrDrv101.sys"
weight = 10

+++


{{< block "grid-1" >}}
{{< column "mt-2 pt-1">}}


# AsrDrv101.sys ![:inline](/images/twitter_verified.png) 


### Description

AsrDrv101.sys is a vulnerable driver and more information will be added as found.

- **Created**: 2023-01-09
- **Author**: Michael Haag
- **Acknowledgement**:  | [](https://twitter.com/)

{{< button "https://github.com/magicsword-io/LOLDrivers/raw/main/drivers/1a234f4643f5658bab07bfa611282267.bin" "Download" >}}
{{< tip "warning" >}}
This download link contains the vulnerable driver!

{{< /tip >}}

### Commands

```
sc.exe create AsrDrv101.sys binPath=C:\windows\temp\AsrDrv101.sys type=kernel &amp;&amp; sc.exe start AsrDrv101.sys
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

| Property           | Value |
|:-------------------|:------|
| Filename           | AsrDrv101.sys |
| MD5                | [1a234f4643f5658bab07bfa611282267](https://www.virustotal.com/gui/file/1a234f4643f5658bab07bfa611282267) |
| SHA1               | [57511ef5ff8162a9d793071b5bf7ebe8371759de](https://www.virustotal.com/gui/file/57511ef5ff8162a9d793071b5bf7ebe8371759de) |
| SHA256             | [f40435488389b4fb3b945ca21a8325a51e1b5f80f045ab019748d0ec66056a8b](https://www.virustotal.com/gui/file/f40435488389b4fb3b945ca21a8325a51e1b5f80f045ab019748d0ec66056a8b) |
| Authentihash MD5   | [236e9dd83b6d3ae6d23a57590b68fb5e](https://www.virustotal.com/gui/search/authentihash%253A236e9dd83b6d3ae6d23a57590b68fb5e) |
| Authentihash SHA1  | [d0580bfc31faefb7e017798121c5b8a4e68155f9](https://www.virustotal.com/gui/search/authentihash%253Ad0580bfc31faefb7e017798121c5b8a4e68155f9) |
| Authentihash SHA256| [fee4560f2160a951d83344857eb4587ab10c1cfd8c5cfc23b6f06bef8ebcd984](https://www.virustotal.com/gui/search/authentihash%253Afee4560f2160a951d83344857eb4587ab10c1cfd8c5cfc23b6f06bef8ebcd984) |
| Publisher         | ASROCK Incorporation |
| Signature         | ASROCK Incorporation, VeriSign Class 3 Code Signing 2010 CA, VeriSign   |
| Company           | ASRock Incorporation |
| Description       | ASRock IO Driver |
| Product           | ASRock IO Driver |
| OriginalFilename  | AsrDrv.sys |


#### Imports
{{< details "Expand" >}}
* ntoskrnl.exe
* HAL.dll

{{< /details >}}
#### ImportedFunctions
{{< details "Expand" >}}
* IoDeleteSymbolicLink
* ExFreePoolWithTag
* MmFreeContiguousMemorySpecifyCache
* RtlInitUnicodeString
* IoDeleteDevice
* RtlQueryRegistryValues
* MmUnmapIoSpace
* IoFreeMdl
* MmGetPhysicalAddress
* IoBuildAsynchronousFsdRequest
* MmMapIoSpace
* IofCompleteRequest
* IoFreeIrp
* RtlCompareMemory
* MmUnlockPages
* IoCreateSymbolicLink
* IoCreateDevice
* MmAllocateContiguousMemorySpecifyCache
* IofCallDriver
* KeBugCheckEx
* ExAllocatePoolWithTag
* KeStallExecutionProcessor

{{< /details >}}
#### ExportedFunctions
{{< details "Expand" >}}

{{< /details >}}


[*source*](https://github.com/magicsword-io/LOLDrivers/tree/main/yaml/asrdrv101.yaml)

*last_updated:* 2023-04-20








{{< /column >}}
{{< /block >}}
