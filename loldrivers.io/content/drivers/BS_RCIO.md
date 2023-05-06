+++

description = ""
title = "BS_RCIO.sys"
weight = 10

+++


{{< block "grid-1" >}}
{{< column "mt-2 pt-1">}}


# BS_RCIO.sys 


{{< tip "warning" >}}
We were not able to verify the hash of this driver successfully, it has not been confirmed.
{{< /tip >}}


### Description

BS_RCIO.sys is a vulnerable driver and more information will be added as found.

- **Created**: 2023-01-09
- **Author**: Michael Haag
- **Acknowledgement**:  | [](https://twitter.com/)

{{< button "https://github.com/magicsword-io/LOLDrivers/raw/main/drivers/ab53d07f18a9697139ddc825b466f696.bin" "Download" >}}
{{< tip "warning" >}}
This download link contains the vulnerable driver!

{{< /tip >}}

### Commands

```
sc.exe create BS_RCIO.sys binPath=C:\windows\temp\BS_RCIO.sys type=kernel &amp;&amp; sc.exe start BS_RCIO.sys
```

| Use Case | Privileges | Operating System | 
|:---- | ---- | ---- |
| Elevate privileges | kernel | Windows 10 |

### Resources
<br>
<li><a href=" https://learn.microsoft.com/en-us/windows/security/threat-protection/windows-defender-application-control/microsoft-recommended-driver-block-rules"> https://learn.microsoft.com/en-us/windows/security/threat-protection/windows-defender-application-control/microsoft-recommended-driver-block-rules</a></li>
<li><a href="https://learn.microsoft.com/en-us/windows/security/threat-protection/windows-defender-application-control/microsoft-recommended-driver-block-rules">https://learn.microsoft.com/en-us/windows/security/threat-protection/windows-defender-application-control/microsoft-recommended-driver-block-rules</a></li>
<br>

### Known Vulnerable Samples

| Property           | Value |
|:-------------------|:------|
| Filename           | BS_RCIO.sys |
| MD5                | [ab53d07f18a9697139ddc825b466f696](https://www.virustotal.com/gui/file/ab53d07f18a9697139ddc825b466f696) |
| SHA1               | [213ba055863d4226da26a759e8a254062ea77814](https://www.virustotal.com/gui/file/213ba055863d4226da26a759e8a254062ea77814) |
| SHA256             | [362c4f3dadc9c393682664a139d65d80e32caa2a97b6e0361dfd713a73267ecc](https://www.virustotal.com/gui/file/362c4f3dadc9c393682664a139d65d80e32caa2a97b6e0361dfd713a73267ecc) |
| Authentihash MD5   | [8284660345377a69dd99b25fdf397314](https://www.virustotal.com/gui/search/authentihash%253A8284660345377a69dd99b25fdf397314) |
| Authentihash SHA1  | [3311e4e94e8a6dd81859719fbe0fcbf187f0bd8a](https://www.virustotal.com/gui/search/authentihash%253A3311e4e94e8a6dd81859719fbe0fcbf187f0bd8a) |
| Authentihash SHA256| [f67e60228084151fdcb84e94a48693db864cf606b65faef5a1d829175380dbfa](https://www.virustotal.com/gui/search/authentihash%253Af67e60228084151fdcb84e94a48693db864cf606b65faef5a1d829175380dbfa) |
| Signature         | Biostar Microtech Int&#39;l Corp, DigiCert EV Code Signing CA, DigiCert   |


#### Imports
{{< details "Expand" >}}
* ntoskrnl.exe
* HAL.dll

{{< /details >}}
#### ImportedFunctions
{{< details "Expand" >}}
* KeWaitForSingleObject
* memcpy
* KeDelayExecutionThread
* PsTerminateSystemThread
* KeSetEvent
* IoStartNextPacket
* IoReleaseCancelSpinLock
* IoAcquireCancelSpinLock
* ZwClose
* MmMapIoSpace
* ObfDereferenceObject
* ObReferenceObjectByHandle
* ExEventObjectType
* IofCompleteRequest
* KeRemoveEntryDeviceQueue
* IoStartPacket
* KeTickCount
* KeBugCheckEx
* READ_REGISTER_BUFFER_UCHAR
* MmUnmapIoSpace
* KeReleaseSemaphore
* KeInitializeSemaphore
* IoDeleteSymbolicLink
* RtlInitUnicodeString
* IoCreateDevice
* IoCreateSymbolicLink
* PsCreateSystemThread
* IoDeleteDevice
* HalSetBusDataByOffset
* HalGetBusDataByOffset
* WRITE_PORT_UCHAR
* WRITE_PORT_USHORT
* WRITE_PORT_ULONG
* READ_PORT_UCHAR
* READ_PORT_USHORT
* READ_PORT_ULONG
* KfLowerIrql

{{< /details >}}
#### ExportedFunctions
{{< details "Expand" >}}

{{< /details >}}
-----



[*source*](https://github.com/magicsword-io/LOLDrivers/tree/main/yaml/bs_rcio.yaml)

*last_updated:* 2023-05-06








{{< /column >}}
{{< /block >}}
