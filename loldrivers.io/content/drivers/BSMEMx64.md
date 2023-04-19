+++

description = ""
title = "BSMEMx64.sys"
weight = 10

+++


{{< block "grid-1" >}}
{{< column "mt-2 pt-1">}}


# BSMEMx64.sys ![:inline](/images/twitter_verified.png) 


### Description

BSMEMx64.sys is a vulnerable driver and more information will be added as found.

- **Created**: 2023-01-09
- **Author**: Michael Haag
- **Acknowledgement**:  | [](https://twitter.com/)

{{< button "https://github.com/magicsword-io/LOLDrivers/raw/main/drivers/49fe3d1f3d5c2e50a0df0f6e8436d778.bin" "Download" >}}
{{< tip "warning" >}}
This download link contains the vulnerable driver!

{{< /tip >}}

### Commands

```
sc.exe create BSMEMx64.sys binPath=C:\windows\temp\BSMEMx64.sys type=kernel &amp;&amp; sc.exe start BSMEMx64.sys
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

| Filename | BSMEMx64.sys |
|:---- | ---- | 
| MD5 | <a href="https://www.virustotal.com/gui/file/49fe3d1f3d5c2e50a0df0f6e8436d778">49fe3d1f3d5c2e50a0df0f6e8436d778</a> |
| SHA1 | <a href="https://www.virustotal.com/gui/file/9d07df024ec457168bf0be7e0009619f6ac4f13c">9d07df024ec457168bf0be7e0009619f6ac4f13c</a> |
| SHA256 | <a href="https://www.virustotal.com/gui/file/f929bead59e9424ab90427b379dcdd63fbfe0c4fb5e1792e3a1685541cd5ec65">f929bead59e9424ab90427b379dcdd63fbfe0c4fb5e1792e3a1685541cd5ec65</a> |
| Authentihash MD5 | <a href="https://www.virustotal.com/gui/search/authentihash%253A464c033940c536ca2b627ba616f33fd0">464c033940c536ca2b627ba616f33fd0</a> || Authentihash SHA1 | <a href="https://www.virustotal.com/gui/search/authentihash%253A59e1a1abd37be9c1e33dd7d47526394d6ecb9c49">59e1a1abd37be9c1e33dd7d47526394d6ecb9c49</a> || Authentihash SHA256 | <a href="https://www.virustotal.com/gui/search/authentihash%253A20c87381f8f0bf953cb109a5d50a2184c0104cc8ab30e2f94dfba89a5d19b9d8">20c87381f8f0bf953cb109a5d50a2184c0104cc8ab30e2f94dfba89a5d19b9d8</a> || Signature | BIOSTAR MICROTECH INT&#39;L CORP, VeriSign Class 3 Code Signing 2009-2 CA, VeriSign Class 3 Public Primary CA   || Company | BIOSTAR Group || Description | I/O Interface driver file || Product | BIOSTAR I/O driver fle || OriginalFilename | BS_I2cIo.sys |
#### Imports
{{< details "Expand" >}}* ntoskrnl.exe
* HAL.dll
{{< /details >}}
#### ImportedFunctions
{{< details "Expand" >}}* KeInitializeEvent
* ExAllocatePoolWithTag
* ExFreePoolWithTag
* ObfDereferenceObject
* KeWaitForSingleObject
* ExInterlockedInsertTailList
* RtlTimeToTimeFields
* PsTerminateSystemThread
* ZwWriteFile
* ExInterlockedRemoveHeadList
* KeSetPriorityThread
* ZwCreateFile
* RtlInitUnicodeString
* PsCreateSystemThread
* IoCreateSymbolicLink
* IoCreateDevice
* IoDeleteSymbolicLink
* IoStartNextPacket
* IoReleaseCancelSpinLock
* IoAcquireCancelSpinLock
* MmUnmapIoSpace
* MmMapIoSpace
* KeRemoveEntryDeviceQueue
* IoStartPacket
* IofCompleteRequest
* ObReferenceObjectByHandle
* ZwClose
* IoDeleteDevice
* KeSetEvent
* HalSetBusDataByOffset
* HalTranslateBusAddress
* HalGetBusDataByOffset
{{< /details >}}
#### ExportedFunctions
{{< details "Expand" >}}{{< /details >}}



[*source*](https://github.com/magicsword-io/LOLDrivers/tree/main/yaml/bsmemx64.yaml)

*last_updated:* 2023-04-19








{{< /column >}}
{{< /block >}}
