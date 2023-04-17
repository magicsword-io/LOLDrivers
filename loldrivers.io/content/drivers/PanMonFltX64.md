+++

description = ""
title = "PanMonFltX64.sys"
weight = 10

+++


{{< block "grid-1" >}}
{{< column "mt-2 pt-1">}}


# PanMonFltX64.sys 


{{< tip "warning" >}}
We were not able to verify the hash of this driver successfully, it has not been confirmed.
{{< /tip >}}


### Description

PanMonFltX64.sys is a vulnerable driver and more information will be added as found.

- **Created**: 2023-01-09
- **Author**: Michael Haag
- **Acknowledgement**:  | [](https://twitter.com/)

{{< button "https://github.com/magicsword-io/LOLDrivers/raw/main/drivers/0067c788e1cb174f008c325ebde56c22.bin" "Download" >}}
{{< tip "warning" >}}
This download link contains the malcious driver!
{{< /tip >}}

### Commands

```
sc.exe create PanMonFltX64.sys binPath=C:\windows\temp\PanMonFltX64.sys     type=kernel type=kernel &amp;&amp; sc.exe start PanMonFltX64.sys
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

| Filename | PanMonFltX64.sys |
|:---- | ---- | 
| MD5 | <a href="https://www.virustotal.com/gui/file/0067c788e1cb174f008c325ebde56c22">0067c788e1cb174f008c325ebde56c22</a> |
| SHA1 | <a href="https://www.virustotal.com/gui/file/12d38abbc5391369a4c14f3431715b5b76ac5a2a">12d38abbc5391369a4c14f3431715b5b76ac5a2a</a> |
| SHA256 | <a href="https://www.virustotal.com/gui/file/06508aacb4ed0a1398a2b0da5fa2dbf7da435b56da76fd83c759a50a51c75caf">06508aacb4ed0a1398a2b0da5fa2dbf7da435b56da76fd83c759a50a51c75caf</a> |
| Authentihash MD5 | <a href="https://www.virustotal.com/gui/search/authentihash%253Afb2c77030c99606abb5d78bd51d6637d">fb2c77030c99606abb5d78bd51d6637d</a> || Authentihash SHA1 | <a href="https://www.virustotal.com/gui/search/authentihash%253Acc0f86949ee6261f8c3de046112b99595db14c00">cc0f86949ee6261f8c3de046112b99595db14c00</a> || Authentihash SHA256 | <a href="https://www.virustotal.com/gui/search/authentihash%253A9544fbc011638cbc168f6ea4740cc6ed6fd331769e191fd64bdf9113eb64fde1">9544fbc011638cbc168f6ea4740cc6ed6fd331769e191fd64bdf9113eb64fde1</a> || Signature | PAN YAZILIM BILISIM TEKNOLOJILERI TICARET LTD. STI., GlobalSign CodeSigning CA - G2, GlobalSign   || Company | Pan Yazilim Bilisim Teknolojileri Tic. Ltd. Sti. || Description | PanCafe Manager File Monitor || Product | PanCafe Manager || OriginalFilename | PanMonFltX64.sys |
#### Imports
{{< details "Expand" >}}* ntoskrnl.exe
* FLTMGR.SYS
{{< /details >}}
#### ImportedFunctions
{{< details "Expand" >}}* KeBugCheckEx
* KeAcquireSpinLockRaiseToDpc
* ExInterlockedRemoveHeadList
* ExInterlockedInsertTailList
* RtlEqualUnicodeString
* KeReleaseSpinLock
* IoQueryFileDosDeviceName
* RtlAppendUnicodeStringToString
* IoVolumeDeviceToDosName
* RtlAppendUnicodeToString
* DbgPrint
* RtlCopyUnicodeString
* PsGetCurrentThreadId
* RtlInitUnicodeString
* ExFreePoolWithTag
* ExAllocatePoolWithTag
* __C_specific_handler
* FltSendMessage
* FltQueryInformationFile
* FltStartFiltering
* FltParseFileName
* FltRegisterFilter
* FltBuildDefaultSecurityDescriptor
* FltCloseCommunicationPort
* FltUnregisterFilter
* FltAllocateContext
* FltReleaseContext
* FltIsDirectory
* FltFreeSecurityDescriptor
* FltSetInformationFile
* FltCreateCommunicationPort
* FltDeleteContext
* FltCloseClientPort
* FltSetStreamHandleContext
* FltGetStreamHandleContext
{{< /details >}}
#### ExportedFunctions
{{< details "Expand" >}}{{< /details >}}



[*source*](https://github.com/magicsword-io/LOLDrivers/tree/main/yaml/panmonfltx64.yaml)

*last_updated:* 2023-04-17








{{< /column >}}
{{< /block >}}
