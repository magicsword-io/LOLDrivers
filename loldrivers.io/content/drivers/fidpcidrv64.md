+++

description = ""
title = "fidpcidrv64.sys"
weight = 10

+++


{{< block "grid-1" >}}
{{< column "mt-2 pt-1">}}


# fidpcidrv64.sys ![:inline](/images/twitter_verified.png) 


### Description

fidpcidrv64.sys is a vulnerable driver and more information will be added as found.

- **Created**: 2023-01-09
- **Author**: Michael Haag
- **Acknowledgement**:  | [](https://twitter.com/)

{{< button "https://github.com/magicsword-io/LOLDrivers/raw/main/drivers/2fed983ec44d1e7cffb0d516407746f2.bin" "Download" >}}
{{< tip "warning" >}}
This download link contains the vulnerable driver!

{{< /tip >}}

### Commands

```
sc.exe create fidpcidrv64.sys binPath=C:\windows\temp\fidpcidrv64.sys     type=kernel &amp;&amp; sc.exe start fidpcidrv64.sys
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
| Filename           | fidpcidrv64.sys |
| MD5                | [2fed983ec44d1e7cffb0d516407746f2](https://www.virustotal.com/gui/file/2fed983ec44d1e7cffb0d516407746f2) |
| SHA1               | [eb93d2f564fea9b3dc350f386b45de2cd9a3e001](https://www.virustotal.com/gui/file/eb93d2f564fea9b3dc350f386b45de2cd9a3e001) |
| SHA256             | [3ac5e01689a3d745e60925bc7faca8d4306ae693e803b5e19c94906dc30add46](https://www.virustotal.com/gui/file/3ac5e01689a3d745e60925bc7faca8d4306ae693e803b5e19c94906dc30add46) |
| Authentihash MD5   | [66e3da88d9b3b4637474d0da27a523a6](https://www.virustotal.com/gui/search/authentihash%253A66e3da88d9b3b4637474d0da27a523a6) |
| Authentihash SHA1  | [4789b910023a667bee70ff1f1a8f369cffb10fe8](https://www.virustotal.com/gui/search/authentihash%253A4789b910023a667bee70ff1f1a8f369cffb10fe8) |
| Authentihash SHA256| [7fb0f6fc5bdd22d53f8532cb19da666a77a66ffb1cf3919a2e22b66c13b415b7](https://www.virustotal.com/gui/search/authentihash%253A7fb0f6fc5bdd22d53f8532cb19da666a77a66ffb1cf3919a2e22b66c13b415b7) |
| Signature         | Intel(R) Processor Identification Utility, Intel External Basic Issuing CA 3A, Intel External Basic Policy CA, GeoTrust   |


#### Imports
{{< details "Expand" >}}
* ntoskrnl.exe
* HAL.dll

{{< /details >}}
#### ImportedFunctions
{{< details "Expand" >}}
* MmGetSystemRoutineAddress
* IoGetDeviceAttachmentBaseRef
* KeInitializeEvent
* KeWaitForSingleObject
* IoFreeIrp
* ExAllocatePoolWithTag
* RtlCompareUnicodeString
* ObfReferenceObject
* IoDeleteSymbolicLink
* IoCreateSymbolicLink
* ExFreePoolWithTag
* IofCompleteRequest
* ObReferenceObjectByName
* IoCreateDevice
* IoDriverObjectType
* IoEnumerateDeviceObjectList
* IoBuildSynchronousFsdRequest
* IoGetDeviceProperty
* DbgPrint
* IofCallDriver
* KeBugCheckEx
* IoDeleteDevice
* ObfDereferenceObject
* RtlInitUnicodeString
* HalGetBusData
* HalGetBusDataByOffset

{{< /details >}}
#### ExportedFunctions
{{< details "Expand" >}}

{{< /details >}}
-----



[*source*](https://github.com/magicsword-io/LOLDrivers/tree/main/yaml/fidpcidrv64.yaml)

*last_updated:* 2023-04-26








{{< /column >}}
{{< /block >}}
