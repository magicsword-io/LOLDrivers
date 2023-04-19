+++

description = ""
title = "vmdrv.sys"
weight = 10

+++


{{< block "grid-1" >}}
{{< column "mt-2 pt-1">}}


# vmdrv.sys ![:inline](/images/twitter_verified.png) 


### Description

vmdrv.sys is a vulnerable driver and more information will be added as found.

- **Created**: 2023-01-09
- **Author**: Michael Haag
- **Acknowledgement**:  | [](https://twitter.com/)

{{< button "https://github.com/magicsword-io/LOLDrivers/raw/main/drivers/d5db81974ffda566fa821400419f59be.bin" "Download" >}}
{{< tip "warning" >}}
This download link contains the vulnerable driver!

{{< /tip >}}

### Commands

```
sc.exe create vmdrv.sys binPath=C:\windows\temp\vmdrv.sys type=kernel &amp;&amp; sc.exe start vmdrv.sys
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

| Filename | vmdrv.sys |
|:---- | ---- | 
| MD5 | <a href="https://www.virustotal.com/gui/file/d5db81974ffda566fa821400419f59be">d5db81974ffda566fa821400419f59be</a> |
| SHA1 | <a href="https://www.virustotal.com/gui/file/4c18754dca481f107f0923fb8ef5e149d128525d">4c18754dca481f107f0923fb8ef5e149d128525d</a> |
| SHA256 | <a href="https://www.virustotal.com/gui/file/32cccc4f249499061c0afa18f534c825d01034a1f6815f5506bf4c4ff55d1351">32cccc4f249499061c0afa18f534c825d01034a1f6815f5506bf4c4ff55d1351</a> |
| Authentihash MD5 | <a href="https://www.virustotal.com/gui/search/authentihash%253A681bb8e9713477839a1ee8d87b498630">681bb8e9713477839a1ee8d87b498630</a> || Authentihash SHA1 | <a href="https://www.virustotal.com/gui/search/authentihash%253A68cdcd073e57f650c5d6173cd79af3a3526052f6">68cdcd073e57f650c5d6173cd79af3a3526052f6</a> || Authentihash SHA256 | <a href="https://www.virustotal.com/gui/search/authentihash%253A99ddeba6bcdc79e52e3ff8afc63dbe4b299161cf0f5558a2d7630c2a18daf2c6">99ddeba6bcdc79e52e3ff8afc63dbe4b299161cf0f5558a2d7630c2a18daf2c6</a> || Signature | Voicemod Sociedad Limitada, DigiCert Global G3 Code Signing ECC SHA384 2021 CA1, DigiCert Global Root G3   || Company | Windows (R) Win 7 DDK provider || Description | Voicemod Virtual Audio Device (WDM) || Product | Windows (R) Win 7 DDK driver || OriginalFilename | vmdrv.sys |
#### Imports
{{< details "Expand" >}}* ntoskrnl.exe
* portcls.sys
{{< /details >}}
#### ImportedFunctions
{{< details "Expand" >}}* RtlInitUnicodeString
* KeClearEvent
* KeSetEvent
* ExFreePool
* IofCompleteRequest
* IoCreateDevice
* IoCreateSymbolicLink
* IoDeleteDevice
* IoDeleteSymbolicLink
* ObReferenceObjectByHandle
* ObfDereferenceObject
* ExEventObjectType
* ExAllocatePoolWithTag
* ExFreePoolWithTag
* ExSystemTimeToLocalTime
* _purecall
* KeInitializeDpc
* KeFlushQueuedDpcs
* KeInitializeMutex
* KeReleaseMutex
* KeInitializeTimerEx
* KeCancelTimer
* KeSetTimerEx
* KeWaitForSingleObject
* KeInitializeSpinLock
* KeAcquireSpinLockRaiseToDpc
* KeReleaseSpinLock
* IoAllocateWorkItem
* IoFreeWorkItem
* IoQueueWorkItem
* RtlIsNtDdiVersionAvailable
* PcInitializeAdapterDriver
* PcDispatchIrp
* PcAddAdapterDevice
* PcRegisterAdapterPowerManagement
* PcNewServiceGroup
* PcRegisterSubdevice
* PcRegisterPhysicalConnection
* PcNewPort
{{< /details >}}
#### ExportedFunctions
{{< details "Expand" >}}{{< /details >}}



[*source*](https://github.com/magicsword-io/LOLDrivers/tree/main/yaml/vmdrv.yaml)

*last_updated:* 2023-04-19








{{< /column >}}
{{< /block >}}
