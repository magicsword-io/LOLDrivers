+++

description = ""
title = "PanMonFlt.sys"
weight = 10

+++


{{< block "grid-1" >}}
{{< column "mt-2 pt-1">}}


# PanMonFlt.sys 


{{< tip "warning" >}}
We were not able to verify the hash of this driver successfully, it has not been confirmed.
{{< /tip >}}


### Description

PanMonFlt.sys is a vulnerable driver and more information will be added as found.

- **Created**: 2023-01-09
- **Author**: Michael Haag
- **Acknowledgement**:  | [](https://twitter.com/)

{{< button "https://github.com/magicsword-io/LOLDrivers/raw/main/drivers/2850608430dd089f24386f3336c84729.bin" "Download" >}}
{{< tip "warning" >}}
{% if driver.Category == "vulnerable driver" %}
This download link contains the vulnerable driver!
{% elif driver.Category == "malicious" %}
This download link contains the malicious driver!
{% endif %}
{{< /tip >}}

### Commands

```
sc.exe create PanMonFlt.sys binPath=C:\windows\temp\PanMonFlt.sys type=kernel &amp;&amp; sc.exe start PanMonFlt.sys
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

| Filename | PanMonFlt.sys |
|:---- | ---- | 
| MD5 | <a href="https://www.virustotal.com/gui/file/2850608430dd089f24386f3336c84729">2850608430dd089f24386f3336c84729</a> |
| SHA1 | <a href="https://www.virustotal.com/gui/file/a6816949cd469b6e5c35858d19273936fab1bef6">a6816949cd469b6e5c35858d19273936fab1bef6</a> |
| SHA256 | <a href="https://www.virustotal.com/gui/file/7e0124fcc7c95fdc34408cf154cb41e654dade8b898c71ad587b2090b1da30d7">7e0124fcc7c95fdc34408cf154cb41e654dade8b898c71ad587b2090b1da30d7</a> |
| Authentihash MD5 | <a href="https://www.virustotal.com/gui/search/authentihash%253A850ca45e16991f9560f708bf7a186754">850ca45e16991f9560f708bf7a186754</a> || Authentihash SHA1 | <a href="https://www.virustotal.com/gui/search/authentihash%253A800256c84e09de2c001868c0ec35211f6e9ad92a">800256c84e09de2c001868c0ec35211f6e9ad92a</a> || Authentihash SHA256 | <a href="https://www.virustotal.com/gui/search/authentihash%253A348679f0f44eb5a50601c48728a5afd2b4312c95eeb7179ce57d447c0d30f873">348679f0f44eb5a50601c48728a5afd2b4312c95eeb7179ce57d447c0d30f873</a> || Signature | PAN YAZILIM BILISIM TEKNOLOJILERI TICARET LTD. STI., GlobalSign CodeSigning CA - G2, GlobalSign   || Company | Pan Yazilim Bilisim Teknolojileri Tic. Ltd. Sti. || Description | PanCafe Manager File Monitor || Product | PanCafe Manager || OriginalFilename | PanMonFlt.sys |
#### Imports
{{< details "Expand" >}}* ntoskrnl.exe
* HAL.dll
* FLTMGR.SYS
{{< /details >}}
#### ImportedFunctions
{{< details "Expand" >}}* ExfInterlockedInsertTailList
* RtlEqualUnicodeString
* KeTickCount
* ExfInterlockedRemoveHeadList
* IoVolumeDeviceToDosName
* RtlAppendUnicodeStringToString
* DbgPrint
* RtlAppendUnicodeToString
* RtlInitUnicodeString
* RtlCopyUnicodeString
* memset
* memcpy
* ExAllocatePoolWithTag
* PsGetCurrentThreadId
* ExFreePoolWithTag
* IoQueryFileDosDeviceName
* RtlUnwind
* KeBugCheckEx
* KfAcquireSpinLock
* KfReleaseSpinLock
* FltUnregisterFilter
* FltQueryInformationFile
* FltRegisterFilter
* FltBuildDefaultSecurityDescriptor
* FltCreateCommunicationPort
* FltFreeSecurityDescriptor
* FltStartFiltering
* FltGetStreamHandleContext
* FltSetInformationFile
* FltDeleteContext
* FltAllocateContext
* FltSetStreamHandleContext
* FltReleaseContext
* FltIsDirectory
* FltParseFileName
* FltSendMessage
* FltCloseClientPort
* FltCloseCommunicationPort
{{< /details >}}
#### ExportedFunctions
{{< details "Expand" >}}{{< /details >}}



[*source*](https://github.com/magicsword-io/LOLDrivers/tree/main/yaml/panmonflt.yaml)

*last_updated:* 2023-04-19








{{< /column >}}
{{< /block >}}
