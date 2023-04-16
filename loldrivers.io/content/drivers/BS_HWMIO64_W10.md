+++

description = ""
title = "BS_HWMIO64_W10.sys"
weight = 10

+++


{{< block "grid-1" >}}
{{< column "mt-2 pt-1">}}


# BS_HWMIO64_W10.sys ![:inline](/images/twitter_verified.png) 


### Description

BS_HWMIO64_W10.sys is a vulnerable driver and more information will be added as found.

- **Created**: 2023-01-09
- **Author**: Michael Haag
- **Acknowledgement**:  | [](https://twitter.com/)


{{< button "https://github.com/magicsword-io/LOLDrivers/raw/main/drivers/0ae30291c6cbfa7be39320badd6e8de0.bin" "Download" >}}

{{< tip "warning" >}}
This download link contains the malcious driver!
{{< /tip >}}

### Commands

```
sc.exe create BS_HWMIO64_W10.sys binPath=C:\windows\temp\BS_HWMIO64_W10.sys     type=kernel type=kernel &amp;&amp; sc.exe start BS_HWMIO64_W10.sys
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

| Filename | BS_HWMIO64_W10.sys |
|:---- | ---- | 
| MD5 | <a href="https://www.virustotal.com/gui/file/d2588631d8aae2a3e54410eaf54f0679">d2588631d8aae2a3e54410eaf54f0679</a> |
| SHA1 | <a href="https://www.virustotal.com/gui/file/cb3de54667548a5c9abf5d8fa47db4097fcee9f1">cb3de54667548a5c9abf5d8fa47db4097fcee9f1</a> |
| SHA256 | <a href="https://www.virustotal.com/gui/file/1d0397c263d51e9fc95bcc8baf98d1a853e1c0401cd0e27c7bf5da3fba1c93a8">1d0397c263d51e9fc95bcc8baf98d1a853e1c0401cd0e27c7bf5da3fba1c93a8</a> |
| Authentihash MD5 | <a href="https://www.virustotal.com/gui/search/authentihash%88704eaf268ad2d72eb099de209873c6">88704eaf268ad2d72eb099de209873c6</a> || Authentihash SHA1 | <a href="https://www.virustotal.com/gui/search/authentihash%2d8499e9b45d7ae198cab59c7435bc83cd4162a0">2d8499e9b45d7ae198cab59c7435bc83cd4162a0</a> || Authentihash SHA256 | <a href="https://www.virustotal.com/gui/search/authentihash%c3fa4872fd2c286904a0cf37a392ef89fb6ba2a84fc9e1b66c70e0cb5ae28efa">c3fa4872fd2c286904a0cf37a392ef89fb6ba2a84fc9e1b66c70e0cb5ae28efa</a> || Signature | Microsoft Windows Hardware Compatibility Publisher, Microsoft Windows Third Party Component CA 2014, Microsoft Root Certificate Authority 2010   || Company | BIOSTAR Group || Description | I/O Interface driver file || Product | BIOSTAR I/O driver || OriginalFilename | BS_HWMIO64_W10.sys |
#### Imports
{{< details "Expand" >}}* ntoskrnl.exe
* HAL.dll
{{< /details >}}
#### ImportedFunctions
{{< details "Expand" >}}* KeInitializeSemaphore
* IoCreateSymbolicLink
* IoCreateDevice
* KeSetEvent
* MmUnmapIoSpace
* KeDelayExecutionThread
* PsCreateSystemThread
* IoStartNextPacket
* PsTerminateSystemThread
* ExEventObjectType
* MmMapIoSpace
* IoDeleteDevice
* ObReferenceObjectByHandle
* KeWaitForSingleObject
* KeReleaseSemaphore
* ObfDereferenceObject
* IoReleaseCancelSpinLock
* IoAcquireCancelSpinLock
* IoStartPacket
* IofCompleteRequest
* KeRemoveEntryDeviceQueue
* KeBugCheckEx
* RtlInitUnicodeString
* ZwClose
* IoDeleteSymbolicLink
* HalSetBusDataByOffset
* HalGetBusDataByOffset
{{< /details >}}
#### ExportedFunctions
{{< details "Expand" >}}{{< /details >}}



[*source*](https://github.com/magicsword-io/LOLDrivers/tree/main/yaml/bs_hwmio64_w10.yaml)

*last_updated:* 2023-04-15








{{< /column >}}
{{< /block >}}
