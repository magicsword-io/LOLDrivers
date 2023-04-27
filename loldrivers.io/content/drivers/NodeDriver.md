+++

description = ""
title = "NodeDriver.sys"
weight = 10

+++


{{< block "grid-1" >}}
{{< column "mt-2 pt-1">}}


# NodeDriver.sys ![:inline](/images/twitter_verified.png) 


### Description

Driver categorized as POORTRY by Mandiant.

- **Created**: 2023-03-02
- **Author**: Michael Haag
- **Acknowledgement**:  | [](https://twitter.com/)

{{< button "https://github.com/magicsword-io/LOLDrivers/raw/main/drivers/ee6b1a79cb6641aa44c762ee90786fe0.bin" "Download" >}}
{{< tip "warning" >}}
This download link contains the malicious driver!

{{< /tip >}}

### Commands

```
sc.exe create NodeDriver.sys binPath=C:\windows\temp\NodeDriver.sys type=kernel &amp;&amp; sc.exe start NodeDriver.sys
```

| Use Case | Privileges | Operating System | 
|:---- | ---- | ---- |
| Elevate privileges | kernel | Windows 10 |

### Resources
<br>
<li><a href="https://www.mandiant.com/resources/blog/hunting-attestation-signed-malware">https://www.mandiant.com/resources/blog/hunting-attestation-signed-malware</a></li>
<li><a href=""></a></li>
<br>

### Known Vulnerable Samples

| Property           | Value |
|:-------------------|:------|
| Filename           | NodeDriver.sys |
| MD5                | [ee6b1a79cb6641aa44c762ee90786fe0](https://www.virustotal.com/gui/file/ee6b1a79cb6641aa44c762ee90786fe0) |
| SHA1               | [3ef30c95e40a854cc4ded94fc503d0c3dc3e620e](https://www.virustotal.com/gui/file/3ef30c95e40a854cc4ded94fc503d0c3dc3e620e) |
| SHA256             | [05b146a48a69dd62a02759487e769bd30d39f16374bc76c86453b4ae59e7ffa4](https://www.virustotal.com/gui/file/05b146a48a69dd62a02759487e769bd30d39f16374bc76c86453b4ae59e7ffa4) |
| Authentihash MD5   | [cb01e86f3c5a26629d53856c5e4990ec](https://www.virustotal.com/gui/search/authentihash%253Acb01e86f3c5a26629d53856c5e4990ec) |
| Authentihash SHA1  | [fbbb429de5458a274b4a4ab44ed6785139f4a7e4](https://www.virustotal.com/gui/search/authentihash%253Afbbb429de5458a274b4a4ab44ed6785139f4a7e4) |
| Authentihash SHA256| [43374fd68dc06c8491b16d177156444ee44f497bbceafd0165f40ba48bf6802f](https://www.virustotal.com/gui/search/authentihash%253A43374fd68dc06c8491b16d177156444ee44f497bbceafd0165f40ba48bf6802f) |
| Signature         | Microsoft Windows Hardware Compatibility Publisher, Microsoft Windows Third Party Component CA 2014, Microsoft Root Certificate Authority 2010   |


#### Imports
{{< details "Expand" >}}
* NETIO.SYS
* ntoskrnl.exe
* ntoskrnl.exe
* HAL.dll

{{< /details >}}
#### ImportedFunctions
{{< details "Expand" >}}
* WskCaptureProviderNPI
* ExAllocatePoolWithTag
* ExAllocatePool
* NtQuerySystemInformation
* ExFreePoolWithTag
* IoAllocateMdl
* MmProbeAndLockPages
* MmMapLockedPagesSpecifyCache
* MmUnlockPages
* IoFreeMdl
* KeQueryActiveProcessors
* KeSetSystemAffinityThread
* KeRevertToUserAffinityThread
* DbgPrint
* KeQueryPerformanceCounter

{{< /details >}}
#### ExportedFunctions
{{< details "Expand" >}}

{{< /details >}}
-----



[*source*](https://github.com/magicsword-io/LOLDrivers/tree/main/yaml/nodedriver.yaml)

*last_updated:* 2023-04-27








{{< /column >}}
{{< /block >}}
