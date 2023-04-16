+++

description = ""
title = "piddrv64.sys"
weight = 10

+++


{{< block "grid-1" >}}
{{< column "mt-2 pt-1">}}


# piddrv64.sys ![:inline](/images/twitter_verified.png) 


### Description

piddrv64.sys is a vulnerable driver and more information will be added as found.

- **Created**: 2023-01-09
- **Author**: Michael Haag
- **Acknowledgement**:  | [](https://twitter.com/)


{{< button "https://github.com/magicsword-io/LOLDrivers/raw/main/drivers/0ae30291c6cbfa7be39320badd6e8de0.bin" "Download" >}}

{{< tip "warning" >}}
This download link contains the malcious driver!
{{< /tip >}}

### Commands

```
sc.exe create piddrv64.sys binPath=C:\windows\temp\piddrv64.sys type=kernel &amp;&amp; sc.exe start piddrv64.sys
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

| Filename | piddrv64.sys |
|:---- | ---- | 
| MD5 | <a href="https://www.virustotal.com/gui/file/fd7de498a72b2daf89f321d23948c3c4">fd7de498a72b2daf89f321d23948c3c4</a> |
| SHA1 | <a href="https://www.virustotal.com/gui/file/c4ed28fdfba7b8a8dfe39e591006f25d39990f07">c4ed28fdfba7b8a8dfe39e591006f25d39990f07</a> |
| SHA256 | <a href="https://www.virustotal.com/gui/file/b03f26009de2e8eabfcf6152f49b02a55c5e5d0f73e01d48f5a745f93ce93a29">b03f26009de2e8eabfcf6152f49b02a55c5e5d0f73e01d48f5a745f93ce93a29</a> |
| Authentihash MD5 | <a href="https://www.virustotal.com/gui/search/authentihash%a6200c0995103391120e3561971560a6">a6200c0995103391120e3561971560a6</a> || Authentihash SHA1 | <a href="https://www.virustotal.com/gui/search/authentihash%0c2599d738d01a82ec91725f499acebbcfb47cc9">0c2599d738d01a82ec91725f499acebbcfb47cc9</a> || Authentihash SHA256 | <a href="https://www.virustotal.com/gui/search/authentihash%b97f870c501714fa453cf18ae8a30c87d08ff1e6d784afdbb0121aea3da2dc28">b97f870c501714fa453cf18ae8a30c87d08ff1e6d784afdbb0121aea3da2dc28</a> || Signature | Microsoft Windows Hardware Compatibility Publisher, Microsoft Windows Third Party Component CA 2012, Microsoft Root Certificate Authority 2010   |
#### Imports
{{< details "Expand" >}}* ntoskrnl.exe
* HAL.dll
* WDFLDR.SYS
{{< /details >}}
#### ImportedFunctions
{{< details "Expand" >}}* MmGetSystemRoutineAddress
* IoBuildSynchronousFsdRequest
* IofCallDriver
* IofCompleteRequest
* IoCreateDevice
* IoCreateSymbolicLink
* IoDeleteDevice
* IoDeleteSymbolicLink
* IoFreeIrp
* IoGetDeviceProperty
* ExFreePoolWithTag
* ObfDereferenceObject
* ObReferenceObjectByName
* IoEnumerateDeviceObjectList
* IoGetDeviceAttachmentBaseRef
* IoDriverObjectType
* KeBugCheckEx
* __C_specific_handler
* ExAllocatePoolWithTag
* KeWaitForSingleObject
* KeInitializeEvent
* RtlCopyUnicodeString
* DbgPrint
* RtlCompareUnicodeString
* RtlInitUnicodeString
* ObfReferenceObject
* memcpy_s
* HalGetBusData
* HalGetBusDataByOffset
* WdfVersionUnbind
* WdfVersionBind
* WdfVersionBindClass
* WdfVersionUnbindClass
{{< /details >}}
#### ExportedFunctions
{{< details "Expand" >}}{{< /details >}}



[*source*](https://github.com/magicsword-io/LOLDrivers/tree/main/yaml/piddrv64.yaml)

*last_updated:* 2023-04-15








{{< /column >}}
{{< /block >}}
