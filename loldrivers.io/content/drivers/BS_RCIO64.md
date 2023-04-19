+++

description = ""
title = "BS_RCIO64.sys"
weight = 10

+++


{{< block "grid-1" >}}
{{< column "mt-2 pt-1">}}


# BS_RCIO64.sys ![:inline](/images/twitter_verified.png) 


### Description

BS_RCIO64.sys is a vulnerable driver and more information will be added as found.

- **Created**: 2023-01-09
- **Author**: Michael Haag
- **Acknowledgement**:  | [](https://twitter.com/)

{{< button "https://github.com/magicsword-io/LOLDrivers/raw/main/drivers/b10b210c5944965d0dc85e70a0b19a42.bin" "Download" >}}
{{< tip "warning" >}}
{% if driver.Category == "vulnerable driver" %}
This download link contains the vulnerable driver!
{% elif driver.Category == "malicious" %}
This download link contains the malicious driver!
{% endif %}
{{< /tip >}}

### Commands

```
sc.exe create BS_RCIO64.sys binPath=C:\windows\temp\BS_RCIO64.sys type=kernel &amp;&amp; sc.exe start BS_RCIO64.sys
```

| Use Case | Privileges | Operating System | 
|:---- | ---- | ---- |
| Elevate privileges | kernel | Windows 10 |

### Resources
<br>
<li><a href=" https://github.com/jbaines-r7/dellicious"> https://github.com/jbaines-r7/dellicious</a></li>
<li><a href=" https://www.rapid7.com/blog/post/2021/12/13/driver-based-attacks-past-and-present/"> https://www.rapid7.com/blog/post/2021/12/13/driver-based-attacks-past-and-present/</a></li>
<li><a href="https://github.com/elastic/protections-artifacts/blob/932baf346cc8a743f1963ad3d4565b42ed17bebe/yara/rules/Windows_VulnDriver_Biostar.yar#L54">https://github.com/elastic/protections-artifacts/blob/932baf346cc8a743f1963ad3d4565b42ed17bebe/yara/rules/Windows_VulnDriver_Biostar.yar#L54</a></li>
<li><a href="https://github.com/jbaines-r7/dellicious and https://www.rapid7.com/blog/post/2021/12/13/driver-based-attacks-past-and-present/">https://github.com/jbaines-r7/dellicious and https://www.rapid7.com/blog/post/2021/12/13/driver-based-attacks-past-and-present/</a></li>
<br>

### Known Vulnerable Samples

| Filename | BS_RCIO64.sys |
|:---- | ---- | 
| MD5 | <a href="https://www.virustotal.com/gui/file/b10b210c5944965d0dc85e70a0b19a42">b10b210c5944965d0dc85e70a0b19a42</a> |
| SHA1 | <a href="https://www.virustotal.com/gui/file/5db61d00a001fd493591dc919f69b14713889fc5">5db61d00a001fd493591dc919f69b14713889fc5</a> |
| SHA256 | <a href="https://www.virustotal.com/gui/file/d205286bffdf09bc033c09e95c519c1c267b40c2ee8bab703c6a2d86741ccd3e">d205286bffdf09bc033c09e95c519c1c267b40c2ee8bab703c6a2d86741ccd3e</a> |
| Authentihash MD5 | <a href="https://www.virustotal.com/gui/search/authentihash%253A380a4fd97d795fec244add19a9c21fd6">380a4fd97d795fec244add19a9c21fd6</a> || Authentihash SHA1 | <a href="https://www.virustotal.com/gui/search/authentihash%253A6832acd68bcf08f8ced63023b5f7da36824cc596">6832acd68bcf08f8ced63023b5f7da36824cc596</a> || Authentihash SHA256 | <a href="https://www.virustotal.com/gui/search/authentihash%253A6991be9952aa08c0d2ac9fa728410ebdb44988b496ed01b8b7f478785ebb30c4">6991be9952aa08c0d2ac9fa728410ebdb44988b496ed01b8b7f478785ebb30c4</a> || Signature | Microsoft Windows Hardware Compatibility Publisher, Microsoft Windows Third Party Component CA 2014, Microsoft Root Certificate Authority 2010   || Company | BIOSTAR Group || Description | I/O Interface driver file || Product | BIOSTAR I/O driver || OriginalFilename | BS_RCIO64.sys |
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



[*source*](https://github.com/magicsword-io/LOLDrivers/tree/main/yaml/bs_rcio64.yaml)

*last_updated:* 2023-04-19








{{< /column >}}
{{< /block >}}
