+++

description = ""
title = "BS_HWMIo64.sys"
weight = 10

+++


{{< block "grid-1" >}}
{{< column "mt-2 pt-1">}}


# BS_HWMIo64.sys ![:inline](/images/twitter_verified.png) 


### Description

BS_HWMIo64.sys is a vulnerable driver and more information will be added as found.

- **Created**: 2023-01-09
- **Author**: Michael Haag
- **Acknowledgement**:  | [](https://twitter.com/)


{{< button "https://github.com/magicsword-io/LOLDrivers/raw/main/drivers/0ae30291c6cbfa7be39320badd6e8de0.bin" "Download" >}}

{{< tip "warning" >}}
This download link contains the malcious driver!
{{< /tip >}}

### Commands

```
sc.exe create BS_HWMIo64.sys binPath=C:\windows\temp\BS_HWMIo64.sys type=kernel &amp;&amp; sc.exe start BS_HWMIo64.sys
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

| Filename | BS_HWMIo64.sys |
|:---- | ---- | 
| MD5 | <a href="https://www.virustotal.com/gui/file/338a98e1c27bc76f09331fcd7ae413a5">338a98e1c27bc76f09331fcd7ae413a5</a> |
| SHA1 | <a href="https://www.virustotal.com/gui/file/9c24dd75e4074041dbe03bf21f050c77d748b8e9">9c24dd75e4074041dbe03bf21f050c77d748b8e9</a> |
| SHA256 | <a href="https://www.virustotal.com/gui/file/60c6f4f34c7319cb3f9ca682e59d92711a05a2688badbae4891b1303cd384813">60c6f4f34c7319cb3f9ca682e59d92711a05a2688badbae4891b1303cd384813</a> |
| Authentihash MD5 | <a href="https://www.virustotal.com/gui/search/authentihash%d6f9dc5cd435d1c210cd4053886b9f36">d6f9dc5cd435d1c210cd4053886b9f36</a> || Authentihash SHA1 | <a href="https://www.virustotal.com/gui/search/authentihash%3281135748c9c7a9ddace55c648c720af810475f">3281135748c9c7a9ddace55c648c720af810475f</a> || Authentihash SHA256 | <a href="https://www.virustotal.com/gui/search/authentihash%3de51a3102db7297d96b4de5b60aca5f3a07e8577bbbed7f755f1de9a9c38e75">3de51a3102db7297d96b4de5b60aca5f3a07e8577bbbed7f755f1de9a9c38e75</a> || Signature | BIOSTAR MICROTECH INT&#39;L CORP, VeriSign Class 3 Code Signing 2010 CA, VeriSign   |
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



[*source*](https://github.com/magicsword-io/LOLDrivers/tree/main/yaml/bs_hwmio64.yaml)

*last_updated:* 2023-04-15








{{< /column >}}
{{< /block >}}
