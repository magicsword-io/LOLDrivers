+++

description = ""
title = "ALSysIO64.sys"
weight = 10

+++


{{< block "grid-1" >}}
{{< column "mt-2 pt-1">}}


# ALSysIO64.sys ![:inline](/images/twitter_verified.png) 


### Description

ALSysIO64.sys is a vulnerable driver and more information will be added as found.

- **Created**: 2023-01-09
- **Author**: Michael Haag
- **Acknowledgement**:  | [](https://twitter.com/)

{{< button "https://github.com/magicsword-io/LOLDrivers/raw/main/drivers/13dda15ef67eb265869fc371c72d6ef0.bin" "Download" >}}
{{< tip "warning" >}}
This download link contains the malcious driver!
{{< /tip >}}

### Commands

```
sc.exe create ALSysIO64.sys binPath=C:\windows\temp\ALSysIO64.sys type=kernel &amp;&amp; sc.exe start ALSysIO64.sys
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

| Filename | ALSysIO64.sys |
|:---- | ---- | 
| MD5 | <a href="https://www.virustotal.com/gui/file/13dda15ef67eb265869fc371c72d6ef0">13dda15ef67eb265869fc371c72d6ef0</a> |
| SHA1 | <a href="https://www.virustotal.com/gui/file/2f991435a6f58e25c103a657d24ed892b99690b8">2f991435a6f58e25c103a657d24ed892b99690b8</a> |
| SHA256 | <a href="https://www.virustotal.com/gui/file/7196187fb1ef8d108b380d37b2af8efdeb3ca1f6eefd37b5dc114c609147216d">7196187fb1ef8d108b380d37b2af8efdeb3ca1f6eefd37b5dc114c609147216d</a> |
| Authentihash MD5 | <a href="https://www.virustotal.com/gui/search/authentihash%253A86be5dbedcfcd517b9b602436cd985eb">86be5dbedcfcd517b9b602436cd985eb</a> || Authentihash SHA1 | <a href="https://www.virustotal.com/gui/search/authentihash%253A7a9981f1bca18e2f624fe806c753a14dfd970c4e">7a9981f1bca18e2f624fe806c753a14dfd970c4e</a> || Authentihash SHA256 | <a href="https://www.virustotal.com/gui/search/authentihash%253Aca829178d01990c8d1d6a681dee074a53f0dd873fd8eef6f6161c682449ec8c5">ca829178d01990c8d1d6a681dee074a53f0dd873fd8eef6f6161c682449ec8c5</a> || Publisher | Artur Liberman || Signature | Artur Liberman, GlobalSign CodeSigning CA - G2, GlobalSign Root CA - R1   || Company | Arthur Liberman || Description | ALSysIO || Product | ALSysIO || OriginalFilename | ALSysIO.sys |
#### Imports
{{< details "Expand" >}}* ntoskrnl.exe
* HAL.dll
{{< /details >}}
#### ImportedFunctions
{{< details "Expand" >}}* IoDeleteDevice
* ZwClose
* IofCompleteRequest
* IoCreateSymbolicLink
* IoCreateDevice
* IoBuildDeviceIoControlRequest
* RtlAnsiStringToUnicodeString
* MmGetSystemRoutineAddress
* KeInitializeEvent
* RtlInitAnsiString
* RtlFreeUnicodeString
* RtlInitUnicodeString
* KeWaitForSingleObject
* MmIsAddressValid
* ObfDereferenceObject
* DbgPrint
* IofCallDriver
* ExAllocatePoolWithTag
* ExFreePoolWithTag
* strstr
* MmUnmapIoSpace
* MmMapIoSpace
* KeBugCheckEx
* IoGetDeviceObjectPointer
* IoDeleteSymbolicLink
* RtlUnwindEx
* HalGetBusDataByOffset
{{< /details >}}
#### ExportedFunctions
{{< details "Expand" >}}{{< /details >}}
| Filename | ALSysIO64.sys |
|:---- | ---- | 
| MD5 | <a href="https://www.virustotal.com/gui/file/ba5f0f6347780c2ed911bbf888e75bef">ba5f0f6347780c2ed911bbf888e75bef</a> |
| SHA1 | <a href="https://www.virustotal.com/gui/file/f02af84393e9627ba808d4159841854a6601cf80">f02af84393e9627ba808d4159841854a6601cf80</a> |
| SHA256 | <a href="https://www.virustotal.com/gui/file/7f375639a0df7fe51e5518cf87c3f513c55bc117db47d28da8c615642eb18bfa">7f375639a0df7fe51e5518cf87c3f513c55bc117db47d28da8c615642eb18bfa</a> |
| Authentihash MD5 | <a href="https://www.virustotal.com/gui/search/authentihash%253A966e1c16e1aa07044b733c5589f40fd7">966e1c16e1aa07044b733c5589f40fd7</a> || Authentihash SHA1 | <a href="https://www.virustotal.com/gui/search/authentihash%253A7027b399daf84a7c24dd010c2806bf6048a230bd">7027b399daf84a7c24dd010c2806bf6048a230bd</a> || Authentihash SHA256 | <a href="https://www.virustotal.com/gui/search/authentihash%253Aac22a7cce3795e58c974056a86a06444e831d52185f9f37db88c65e14cd5bb75">ac22a7cce3795e58c974056a86a06444e831d52185f9f37db88c65e14cd5bb75</a> || Publisher | Artur Liberman || Signature | Artur Liberman, GlobalSign CodeSigning CA - G2, GlobalSign Root CA - R1   || Company | Arthur Liberman || Description | ALSysIO || Product | ALSysIO || OriginalFilename | ALSysIO.sys |
#### Imports
{{< details "Expand" >}}* ntoskrnl.exe
* HAL.dll
{{< /details >}}
#### ImportedFunctions
{{< details "Expand" >}}* IoDeleteDevice
* ZwClose
* IofCompleteRequest
* IoCreateSymbolicLink
* IoCreateDevice
* IoBuildDeviceIoControlRequest
* RtlAnsiStringToUnicodeString
* MmGetSystemRoutineAddress
* KeInitializeEvent
* RtlInitAnsiString
* RtlFreeUnicodeString
* RtlInitUnicodeString
* KeWaitForSingleObject
* MmIsAddressValid
* ObfDereferenceObject
* DbgPrint
* IofCallDriver
* ExAllocatePoolWithTag
* ExFreePoolWithTag
* strstr
* MmUnmapIoSpace
* MmMapIoSpace
* KeBugCheckEx
* IoGetDeviceObjectPointer
* IoDeleteSymbolicLink
* RtlUnwindEx
* HalGetBusDataByOffset
{{< /details >}}
#### ExportedFunctions
{{< details "Expand" >}}{{< /details >}}



[*source*](https://github.com/magicsword-io/LOLDrivers/tree/main/yaml/alsysio64.yaml)

*last_updated:* 2023-04-17








{{< /column >}}
{{< /block >}}
