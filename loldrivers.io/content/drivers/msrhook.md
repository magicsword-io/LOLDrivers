+++

description = ""
title = "msrhook.sys"
weight = 10

+++


{{< block "grid-1" >}}
{{< column "mt-2 pt-1">}}


# msrhook.sys ![:inline](/images/twitter_verified.png) 


### Description

msrhook.sys is a vulnerable driver and more information will be added as found.

- **Created**: 2023-01-09
- **Author**: Michael Haag
- **Acknowledgement**:  | [](https://twitter.com/)

{{< button "https://github.com/magicsword-io/LOLDrivers/raw/main/drivers/c49a1956a6a25ffc25ad97d6762b0989.bin" "Download" >}}
{{< tip "warning" >}}
This download link contains the vulnerable driver!

{{< /tip >}}

### Commands

```
sc.exe create msrhook.sys binPath=C:\windows\temp\msrhook.sys type=kernel &amp;&amp; sc.exe start msrhook.sys
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
| Filename           | msrhook.sys |
| MD5                | [c49a1956a6a25ffc25ad97d6762b0989](https://www.virustotal.com/gui/file/c49a1956a6a25ffc25ad97d6762b0989) |
| SHA1               | [89909fa481ff67d7449ee90d24c167b17b0612f1](https://www.virustotal.com/gui/file/89909fa481ff67d7449ee90d24c167b17b0612f1) |
| SHA256             | [6de84caa2ca18673e01b91af58220c60aecd5cccf269725ec3c7f226b2167492](https://www.virustotal.com/gui/file/6de84caa2ca18673e01b91af58220c60aecd5cccf269725ec3c7f226b2167492) |
| Authentihash MD5   | [172df59ed493cc10ccca27239ff3b4e3](https://www.virustotal.com/gui/search/authentihash%253A172df59ed493cc10ccca27239ff3b4e3) |
| Authentihash SHA1  | [ccce82f52142229c88746b06b198ea5c5e058961](https://www.virustotal.com/gui/search/authentihash%253Accce82f52142229c88746b06b198ea5c5e058961) |
| Authentihash SHA256| [37e33b54de1bbe4cf86fa58aeec39084afb35e0cbe5f69c763ecaec1d352daa0](https://www.virustotal.com/gui/search/authentihash%253A37e33b54de1bbe4cf86fa58aeec39084afb35e0cbe5f69c763ecaec1d352daa0) |
| Signature         | ID TECH, VeriSign Class 3 Code Signing 2010 CA, VeriSign   |


#### Imports
{{< details "Expand" >}}
* ntoskrnl.exe
* HAL.dll

{{< /details >}}
#### ImportedFunctions
{{< details "Expand" >}}
* KeInitializeEvent
* KeDelayExecutionThread
* KeSetPriorityThread
* KeInitializeSpinLock
* KeAcquireSpinLockRaiseToDpc
* KeReleaseSpinLock
* KeQueryTimeIncrement
* PsCreateSystemThread
* PsTerminateSystemThread
* IoAttachDeviceToDeviceStack
* IofCallDriver
* IofCompleteRequest
* DbgPrint
* IoCreateSymbolicLink
* IoDeleteDevice
* IoDeleteSymbolicLink
* IoDetachDevice
* PoCallDriver
* PoStartNextPowerIrp
* ObfDereferenceObject
* ZwClose
* ObReferenceObjectByName
* __C_specific_handler
* IoDriverObjectType
* IoCreateDevice
* RtlInitUnicodeString
* KeStallExecutionProcessor

{{< /details >}}
#### ExportedFunctions
{{< details "Expand" >}}

{{< /details >}}
-----



[*source*](https://github.com/magicsword-io/LOLDrivers/tree/main/yaml/msrhook.yaml)

*last_updated:* 2023-05-06








{{< /column >}}
{{< /block >}}
