+++

description = ""
title = "CITMDRV_IA64.sys"
weight = 10

+++


{{< block "grid-1" >}}
{{< column "mt-2 pt-1">}}


# CITMDRV_IA64.sys ![:inline](/images/twitter_verified.png) 


### Description

CITMDRV_IA64.sys is a vulnerable driver and more information will be added as found.

- **Created**: 2023-01-09
- **Author**: Michael Haag
- **Acknowledgement**:  | [](https://twitter.com/)

{{< button "https://github.com/magicsword-io/LOLDrivers/raw/main/drivers/c7a57cd4bea07dadba2e2fb914379910.bin" "Download" >}}
{{< tip "warning" >}}
This download link contains the vulnerable driver!

{{< /tip >}}

### Commands

```
sc.exe create CITMDRV_IA64.sys binPath=C:\windows\temp\CITMDRV_IA64.sys     type=kernel &amp;&amp; sc.exe start CITMDRV_IA64.sys
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
| Filename           | CITMDRV_IA64.sys |
| MD5                | [c7a57cd4bea07dadba2e2fb914379910](https://www.virustotal.com/gui/file/c7a57cd4bea07dadba2e2fb914379910) |
| SHA1               | [ea877092d57373cb466b44e7dbcad4ce9a547344](https://www.virustotal.com/gui/file/ea877092d57373cb466b44e7dbcad4ce9a547344) |
| SHA256             | [1c8dfa14888bb58848b4792fb1d8a921976a9463be8334cff45cc96f1276049a](https://www.virustotal.com/gui/file/1c8dfa14888bb58848b4792fb1d8a921976a9463be8334cff45cc96f1276049a) |
| Authentihash MD5   | [2be85acec4d5e36a137af7ef046e0cc8](https://www.virustotal.com/gui/search/authentihash%253A2be85acec4d5e36a137af7ef046e0cc8) |
| Authentihash SHA1  | [b90403d206e5f76bbf699c9627461d9fdafa9aa5](https://www.virustotal.com/gui/search/authentihash%253Ab90403d206e5f76bbf699c9627461d9fdafa9aa5) |
| Authentihash SHA256| [d453110c9050320419c2064ddea08230de6c76f86b07dc58112208e3d24a809e](https://www.virustotal.com/gui/search/authentihash%253Ad453110c9050320419c2064ddea08230de6c76f86b07dc58112208e3d24a809e) |
| Publisher         | IBM Polska Sp. z o.o. |
| Signature         | IBM Polska Sp. z o.o., Symantec Class 3 SHA256 Code Signing CA, VeriSign   |


#### Imports
{{< details "Expand" >}}
* ntoskrnl.exe

{{< /details >}}
#### ImportedFunctions
{{< details "Expand" >}}
* ZwClose
* ZwOpenFile
* RtlInitUnicodeString
* ZwWriteFile
* DbgPrint
* ZwCreateFile
* vsprintf
* IoDeleteDevice
* IoDeleteSymbolicLink
* ZwMapViewOfSection
* ZwUnmapViewOfSection
* MmUnlockPages
* IoFreeMdl
* ZwOpenSection
* MmProbeAndLockPages
* IoAllocateMdl
* __C_specific_handler
* IofCompleteRequest
* IoCreateSymbolicLink
* IoCreateDevice
* KeTickCount
* KeBugCheckEx

{{< /details >}}
#### ExportedFunctions
{{< details "Expand" >}}

{{< /details >}}
-----
| Property           | Value |
|:-------------------|:------|
| Filename           | CITMDRV_IA64.sys |
| MD5                | [6909b5e86e00b4033fedfca1775b0e33](https://www.virustotal.com/gui/file/6909b5e86e00b4033fedfca1775b0e33) |
| SHA1               | [205c69f078a563f54f4c0da2d02a25e284370251](https://www.virustotal.com/gui/file/205c69f078a563f54f4c0da2d02a25e284370251) |
| SHA256             | [22418016e980e0a4a2d01ca210a17059916a4208352c1018b0079ccb19aaf86a](https://www.virustotal.com/gui/file/22418016e980e0a4a2d01ca210a17059916a4208352c1018b0079ccb19aaf86a) |
| Authentihash MD5   | [2be85acec4d5e36a137af7ef046e0cc8](https://www.virustotal.com/gui/search/authentihash%253A2be85acec4d5e36a137af7ef046e0cc8) |
| Authentihash SHA1  | [b90403d206e5f76bbf699c9627461d9fdafa9aa5](https://www.virustotal.com/gui/search/authentihash%253Ab90403d206e5f76bbf699c9627461d9fdafa9aa5) |
| Authentihash SHA256| [d453110c9050320419c2064ddea08230de6c76f86b07dc58112208e3d24a809e](https://www.virustotal.com/gui/search/authentihash%253Ad453110c9050320419c2064ddea08230de6c76f86b07dc58112208e3d24a809e) |
| Publisher         | IBM Polska Sp. z o.o. |
| Signature         | IBM Polska Sp. z o.o., VeriSign Class 3 Code Signing 2009-2 CA, VeriSign Class 3 Public Primary CA   |


#### Imports
{{< details "Expand" >}}
* ntoskrnl.exe

{{< /details >}}
#### ImportedFunctions
{{< details "Expand" >}}
* ZwClose
* ZwOpenFile
* RtlInitUnicodeString
* ZwWriteFile
* DbgPrint
* ZwCreateFile
* vsprintf
* IoDeleteDevice
* IoDeleteSymbolicLink
* ZwMapViewOfSection
* ZwUnmapViewOfSection
* MmUnlockPages
* IoFreeMdl
* ZwOpenSection
* MmProbeAndLockPages
* IoAllocateMdl
* __C_specific_handler
* IofCompleteRequest
* IoCreateSymbolicLink
* IoCreateDevice
* KeTickCount
* KeBugCheckEx

{{< /details >}}
#### ExportedFunctions
{{< details "Expand" >}}

{{< /details >}}
-----
| Property           | Value |
|:-------------------|:------|
| Filename           | CITMDRV_IA64.sys |
| MD5                | [fa173832dca1b1faeba095e5c82a1559](https://www.virustotal.com/gui/file/fa173832dca1b1faeba095e5c82a1559) |
| SHA1               | [f9feb60b23ca69072ce42264cd821fe588a186a6](https://www.virustotal.com/gui/file/f9feb60b23ca69072ce42264cd821fe588a186a6) |
| SHA256             | [405472a8f9400a54bb29d03b436ccd58cfd6442fe686f6d2ed4f63f002854659](https://www.virustotal.com/gui/file/405472a8f9400a54bb29d03b436ccd58cfd6442fe686f6d2ed4f63f002854659) |
| Authentihash MD5   | [2be85acec4d5e36a137af7ef046e0cc8](https://www.virustotal.com/gui/search/authentihash%253A2be85acec4d5e36a137af7ef046e0cc8) |
| Authentihash SHA1  | [b90403d206e5f76bbf699c9627461d9fdafa9aa5](https://www.virustotal.com/gui/search/authentihash%253Ab90403d206e5f76bbf699c9627461d9fdafa9aa5) |
| Authentihash SHA256| [d453110c9050320419c2064ddea08230de6c76f86b07dc58112208e3d24a809e](https://www.virustotal.com/gui/search/authentihash%253Ad453110c9050320419c2064ddea08230de6c76f86b07dc58112208e3d24a809e) |
| Publisher         | IBM Polska Sp. z o.o. |
| Signature         | IBM Polska Sp. z o.o., VeriSign Class 3 Code Signing 2009-2 CA, VeriSign Class 3 Public Primary Certification Authority (PCA3 G1 SHA1)   |


#### Imports
{{< details "Expand" >}}
* ntoskrnl.exe

{{< /details >}}
#### ImportedFunctions
{{< details "Expand" >}}
* ZwClose
* ZwOpenFile
* RtlInitUnicodeString
* ZwWriteFile
* DbgPrint
* ZwCreateFile
* vsprintf
* IoDeleteDevice
* IoDeleteSymbolicLink
* ZwMapViewOfSection
* ZwUnmapViewOfSection
* MmUnlockPages
* IoFreeMdl
* ZwOpenSection
* MmProbeAndLockPages
* IoAllocateMdl
* __C_specific_handler
* IofCompleteRequest
* IoCreateSymbolicLink
* IoCreateDevice
* KeTickCount
* KeBugCheckEx

{{< /details >}}
#### ExportedFunctions
{{< details "Expand" >}}

{{< /details >}}
-----
| Property           | Value |
|:-------------------|:------|
| Filename           | CITMDRV_IA64.sys |
| MD5                | [bbe4f5f8b0c0f32f384a83ae31f49a00](https://www.virustotal.com/gui/file/bbe4f5f8b0c0f32f384a83ae31f49a00) |
| SHA1               | [b25170e09c9fb7c0599bfba3cf617187f6a733ac](https://www.virustotal.com/gui/file/b25170e09c9fb7c0599bfba3cf617187f6a733ac) |
| SHA256             | [49f75746eebe14e5db11706b3e58accc62d4034d2f1c05c681ecef5d1ad933ba](https://www.virustotal.com/gui/file/49f75746eebe14e5db11706b3e58accc62d4034d2f1c05c681ecef5d1ad933ba) |
| Authentihash MD5   | [2be85acec4d5e36a137af7ef046e0cc8](https://www.virustotal.com/gui/search/authentihash%253A2be85acec4d5e36a137af7ef046e0cc8) |
| Authentihash SHA1  | [b90403d206e5f76bbf699c9627461d9fdafa9aa5](https://www.virustotal.com/gui/search/authentihash%253Ab90403d206e5f76bbf699c9627461d9fdafa9aa5) |
| Authentihash SHA256| [d453110c9050320419c2064ddea08230de6c76f86b07dc58112208e3d24a809e](https://www.virustotal.com/gui/search/authentihash%253Ad453110c9050320419c2064ddea08230de6c76f86b07dc58112208e3d24a809e) |
| Publisher         | IBM Polska Sp. z o.o. |
| Signature         | IBM Polska Sp. z o.o., VeriSign Class 3 Code Signing 2010 CA, VeriSign   |


#### Imports
{{< details "Expand" >}}
* ntoskrnl.exe

{{< /details >}}
#### ImportedFunctions
{{< details "Expand" >}}
* ZwClose
* ZwOpenFile
* RtlInitUnicodeString
* ZwWriteFile
* DbgPrint
* ZwCreateFile
* vsprintf
* IoDeleteDevice
* IoDeleteSymbolicLink
* ZwMapViewOfSection
* ZwUnmapViewOfSection
* MmUnlockPages
* IoFreeMdl
* ZwOpenSection
* MmProbeAndLockPages
* IoAllocateMdl
* __C_specific_handler
* IofCompleteRequest
* IoCreateSymbolicLink
* IoCreateDevice
* KeTickCount
* KeBugCheckEx

{{< /details >}}
#### ExportedFunctions
{{< details "Expand" >}}

{{< /details >}}
-----
| Property           | Value |
|:-------------------|:------|
| Filename           | CITMDRV_IA64.sys |
| MD5                | [c5f5d109f11aadebae94c77b27cb026f](https://www.virustotal.com/gui/file/c5f5d109f11aadebae94c77b27cb026f) |
| SHA1               | [160c96b5e5db8c96b821895582b501e3c2d5d6e7](https://www.virustotal.com/gui/file/160c96b5e5db8c96b821895582b501e3c2d5d6e7) |
| SHA256             | [4a3d4db86f580b1680d6454baee1c1a139e2dde7d55e972ba7c92ec3f555dce2](https://www.virustotal.com/gui/file/4a3d4db86f580b1680d6454baee1c1a139e2dde7d55e972ba7c92ec3f555dce2) |
| Authentihash MD5   | [2be85acec4d5e36a137af7ef046e0cc8](https://www.virustotal.com/gui/search/authentihash%253A2be85acec4d5e36a137af7ef046e0cc8) |
| Authentihash SHA1  | [b90403d206e5f76bbf699c9627461d9fdafa9aa5](https://www.virustotal.com/gui/search/authentihash%253Ab90403d206e5f76bbf699c9627461d9fdafa9aa5) |
| Authentihash SHA256| [d453110c9050320419c2064ddea08230de6c76f86b07dc58112208e3d24a809e](https://www.virustotal.com/gui/search/authentihash%253Ad453110c9050320419c2064ddea08230de6c76f86b07dc58112208e3d24a809e) |
| Publisher         | IBM Polska Sp. z o.o. |
| Signature         | IBM Polska Sp. z o.o., VeriSign Class 3 Code Signing 2010 CA, VeriSign   |


#### Imports
{{< details "Expand" >}}
* ntoskrnl.exe

{{< /details >}}
#### ImportedFunctions
{{< details "Expand" >}}
* ZwClose
* ZwOpenFile
* RtlInitUnicodeString
* ZwWriteFile
* DbgPrint
* ZwCreateFile
* vsprintf
* IoDeleteDevice
* IoDeleteSymbolicLink
* ZwMapViewOfSection
* ZwUnmapViewOfSection
* MmUnlockPages
* IoFreeMdl
* ZwOpenSection
* MmProbeAndLockPages
* IoAllocateMdl
* __C_specific_handler
* IofCompleteRequest
* IoCreateSymbolicLink
* IoCreateDevice
* KeTickCount
* KeBugCheckEx

{{< /details >}}
#### ExportedFunctions
{{< details "Expand" >}}

{{< /details >}}
-----
| Property           | Value |
|:-------------------|:------|
| Filename           | CITMDRV_IA64.sys |
| MD5                | [40bc58b7615d00eb55ad9ba700c340c1](https://www.virustotal.com/gui/file/40bc58b7615d00eb55ad9ba700c340c1) |
| SHA1               | [a2e0b3162cfa336cd4ab40a2acc95abe7dc53843](https://www.virustotal.com/gui/file/a2e0b3162cfa336cd4ab40a2acc95abe7dc53843) |
| SHA256             | [4ab41816abbf14d59e75b7fad49e2cb1c1feb27a3cb27402297a2a4793ff9da7](https://www.virustotal.com/gui/file/4ab41816abbf14d59e75b7fad49e2cb1c1feb27a3cb27402297a2a4793ff9da7) |
| Authentihash MD5   | [2be85acec4d5e36a137af7ef046e0cc8](https://www.virustotal.com/gui/search/authentihash%253A2be85acec4d5e36a137af7ef046e0cc8) |
| Authentihash SHA1  | [b90403d206e5f76bbf699c9627461d9fdafa9aa5](https://www.virustotal.com/gui/search/authentihash%253Ab90403d206e5f76bbf699c9627461d9fdafa9aa5) |
| Authentihash SHA256| [d453110c9050320419c2064ddea08230de6c76f86b07dc58112208e3d24a809e](https://www.virustotal.com/gui/search/authentihash%253Ad453110c9050320419c2064ddea08230de6c76f86b07dc58112208e3d24a809e) |
| Publisher         | IBM Polska Sp. z o.o. |
| Signature         | IBM Polska Sp. z o.o., Symantec Class 3 SHA256 Code Signing CA, VeriSign   |


#### Imports
{{< details "Expand" >}}
* ntoskrnl.exe

{{< /details >}}
#### ImportedFunctions
{{< details "Expand" >}}
* ZwClose
* ZwOpenFile
* RtlInitUnicodeString
* ZwWriteFile
* DbgPrint
* ZwCreateFile
* vsprintf
* IoDeleteDevice
* IoDeleteSymbolicLink
* ZwMapViewOfSection
* ZwUnmapViewOfSection
* MmUnlockPages
* IoFreeMdl
* ZwOpenSection
* MmProbeAndLockPages
* IoAllocateMdl
* __C_specific_handler
* IofCompleteRequest
* IoCreateSymbolicLink
* IoCreateDevice
* KeTickCount
* KeBugCheckEx

{{< /details >}}
#### ExportedFunctions
{{< details "Expand" >}}

{{< /details >}}
-----
| Property           | Value |
|:-------------------|:------|
| Filename           | CITMDRV_IA64.sys |
| MD5                | [839cbbc86453960e9eb6db814b776a40](https://www.virustotal.com/gui/file/839cbbc86453960e9eb6db814b776a40) |
| SHA1               | [4e826430a1389032f3fe06e2cc292f643fb0c417](https://www.virustotal.com/gui/file/4e826430a1389032f3fe06e2cc292f643fb0c417) |
| SHA256             | [54841d9f89e195196e65aa881834804fe3678f1cf6b328cab8703edd15e3ec57](https://www.virustotal.com/gui/file/54841d9f89e195196e65aa881834804fe3678f1cf6b328cab8703edd15e3ec57) |
| Authentihash MD5   | [2be85acec4d5e36a137af7ef046e0cc8](https://www.virustotal.com/gui/search/authentihash%253A2be85acec4d5e36a137af7ef046e0cc8) |
| Authentihash SHA1  | [b90403d206e5f76bbf699c9627461d9fdafa9aa5](https://www.virustotal.com/gui/search/authentihash%253Ab90403d206e5f76bbf699c9627461d9fdafa9aa5) |
| Authentihash SHA256| [d453110c9050320419c2064ddea08230de6c76f86b07dc58112208e3d24a809e](https://www.virustotal.com/gui/search/authentihash%253Ad453110c9050320419c2064ddea08230de6c76f86b07dc58112208e3d24a809e) |
| Publisher         | IBM Polska Sp. z o.o. |
| Signature         | IBM Polska Sp. z o.o., Symantec Class 3 SHA256 Code Signing CA, VeriSign   |


#### Imports
{{< details "Expand" >}}
* ntoskrnl.exe

{{< /details >}}
#### ImportedFunctions
{{< details "Expand" >}}
* ZwClose
* ZwOpenFile
* RtlInitUnicodeString
* ZwWriteFile
* DbgPrint
* ZwCreateFile
* vsprintf
* IoDeleteDevice
* IoDeleteSymbolicLink
* ZwMapViewOfSection
* ZwUnmapViewOfSection
* MmUnlockPages
* IoFreeMdl
* ZwOpenSection
* MmProbeAndLockPages
* IoAllocateMdl
* __C_specific_handler
* IofCompleteRequest
* IoCreateSymbolicLink
* IoCreateDevice
* KeTickCount
* KeBugCheckEx

{{< /details >}}
#### ExportedFunctions
{{< details "Expand" >}}

{{< /details >}}
-----
| Property           | Value |
|:-------------------|:------|
| Filename           | CITMDRV_IA64.sys |
| MD5                | [42f7cc4be348c3efd98b0f1233cf2d69](https://www.virustotal.com/gui/file/42f7cc4be348c3efd98b0f1233cf2d69) |
| SHA1               | [7ab4565ba24268f0adadb03a5506d4eb1dc7c181](https://www.virustotal.com/gui/file/7ab4565ba24268f0adadb03a5506d4eb1dc7c181) |
| SHA256             | [5ee292b605cd3751a24e5949aae615d472a3c72688632c3040dc311055b75a92](https://www.virustotal.com/gui/file/5ee292b605cd3751a24e5949aae615d472a3c72688632c3040dc311055b75a92) |
| Authentihash MD5   | [2be85acec4d5e36a137af7ef046e0cc8](https://www.virustotal.com/gui/search/authentihash%253A2be85acec4d5e36a137af7ef046e0cc8) |
| Authentihash SHA1  | [b90403d206e5f76bbf699c9627461d9fdafa9aa5](https://www.virustotal.com/gui/search/authentihash%253Ab90403d206e5f76bbf699c9627461d9fdafa9aa5) |
| Authentihash SHA256| [d453110c9050320419c2064ddea08230de6c76f86b07dc58112208e3d24a809e](https://www.virustotal.com/gui/search/authentihash%253Ad453110c9050320419c2064ddea08230de6c76f86b07dc58112208e3d24a809e) |
| Publisher         | IBM Polska Sp. z o.o. |
| Signature         | IBM Polska Sp. z o.o., VeriSign Class 3 Code Signing 2010 CA, VeriSign   |


#### Imports
{{< details "Expand" >}}
* ntoskrnl.exe

{{< /details >}}
#### ImportedFunctions
{{< details "Expand" >}}
* ZwClose
* ZwOpenFile
* RtlInitUnicodeString
* ZwWriteFile
* DbgPrint
* ZwCreateFile
* vsprintf
* IoDeleteDevice
* IoDeleteSymbolicLink
* ZwMapViewOfSection
* ZwUnmapViewOfSection
* MmUnlockPages
* IoFreeMdl
* ZwOpenSection
* MmProbeAndLockPages
* IoAllocateMdl
* __C_specific_handler
* IofCompleteRequest
* IoCreateSymbolicLink
* IoCreateDevice
* KeTickCount
* KeBugCheckEx

{{< /details >}}
#### ExportedFunctions
{{< details "Expand" >}}

{{< /details >}}
-----
| Property           | Value |
|:-------------------|:------|
| Filename           | CITMDRV_IA64.sys |
| MD5                | [2128e6c044ee86f822d952a261af0b48](https://www.virustotal.com/gui/file/2128e6c044ee86f822d952a261af0b48) |
| SHA1               | [dc7b022f8bd149efbcb2204a48dce75c72633526](https://www.virustotal.com/gui/file/dc7b022f8bd149efbcb2204a48dce75c72633526) |
| SHA256             | [76b86543ce05540048f954fed37bdda66360c4a3ddb8328213d5aef7a960c184](https://www.virustotal.com/gui/file/76b86543ce05540048f954fed37bdda66360c4a3ddb8328213d5aef7a960c184) |
| Authentihash MD5   | [2be85acec4d5e36a137af7ef046e0cc8](https://www.virustotal.com/gui/search/authentihash%253A2be85acec4d5e36a137af7ef046e0cc8) |
| Authentihash SHA1  | [b90403d206e5f76bbf699c9627461d9fdafa9aa5](https://www.virustotal.com/gui/search/authentihash%253Ab90403d206e5f76bbf699c9627461d9fdafa9aa5) |
| Authentihash SHA256| [d453110c9050320419c2064ddea08230de6c76f86b07dc58112208e3d24a809e](https://www.virustotal.com/gui/search/authentihash%253Ad453110c9050320419c2064ddea08230de6c76f86b07dc58112208e3d24a809e) |
| Publisher         | IBM Polska Sp. z o.o. |
| Signature         | IBM Polska Sp. z o.o., Symantec Class 3 SHA256 Code Signing CA, VeriSign   |


#### Imports
{{< details "Expand" >}}
* ntoskrnl.exe

{{< /details >}}
#### ImportedFunctions
{{< details "Expand" >}}
* ZwClose
* ZwOpenFile
* RtlInitUnicodeString
* ZwWriteFile
* DbgPrint
* ZwCreateFile
* vsprintf
* IoDeleteDevice
* IoDeleteSymbolicLink
* ZwMapViewOfSection
* ZwUnmapViewOfSection
* MmUnlockPages
* IoFreeMdl
* ZwOpenSection
* MmProbeAndLockPages
* IoAllocateMdl
* __C_specific_handler
* IofCompleteRequest
* IoCreateSymbolicLink
* IoCreateDevice
* KeTickCount
* KeBugCheckEx

{{< /details >}}
#### ExportedFunctions
{{< details "Expand" >}}

{{< /details >}}
-----
| Property           | Value |
|:-------------------|:------|
| Filename           | CITMDRV_IA64.sys |
| MD5                | [fd81af62964f5dd5eb4a828543a33dcf](https://www.virustotal.com/gui/file/fd81af62964f5dd5eb4a828543a33dcf) |
| SHA1               | [0307d76750dd98d707c699aee3b626643afb6936](https://www.virustotal.com/gui/file/0307d76750dd98d707c699aee3b626643afb6936) |
| SHA256             | [7f190f6e5ab0edafd63391506c2360230af4c2d56c45fc8996a168a1fc12d457](https://www.virustotal.com/gui/file/7f190f6e5ab0edafd63391506c2360230af4c2d56c45fc8996a168a1fc12d457) |
| Authentihash MD5   | [2be85acec4d5e36a137af7ef046e0cc8](https://www.virustotal.com/gui/search/authentihash%253A2be85acec4d5e36a137af7ef046e0cc8) |
| Authentihash SHA1  | [b90403d206e5f76bbf699c9627461d9fdafa9aa5](https://www.virustotal.com/gui/search/authentihash%253Ab90403d206e5f76bbf699c9627461d9fdafa9aa5) |
| Authentihash SHA256| [d453110c9050320419c2064ddea08230de6c76f86b07dc58112208e3d24a809e](https://www.virustotal.com/gui/search/authentihash%253Ad453110c9050320419c2064ddea08230de6c76f86b07dc58112208e3d24a809e) |
| Publisher         | IBM Polska Sp. z o.o. |
| Signature         | IBM Polska Sp. z o.o., VeriSign Class 3 Code Signing 2009-2 CA, VeriSign Class 3 Public Primary CA   |


#### Imports
{{< details "Expand" >}}
* ntoskrnl.exe

{{< /details >}}
#### ImportedFunctions
{{< details "Expand" >}}
* ZwClose
* ZwOpenFile
* RtlInitUnicodeString
* ZwWriteFile
* DbgPrint
* ZwCreateFile
* vsprintf
* IoDeleteDevice
* IoDeleteSymbolicLink
* ZwMapViewOfSection
* ZwUnmapViewOfSection
* MmUnlockPages
* IoFreeMdl
* ZwOpenSection
* MmProbeAndLockPages
* IoAllocateMdl
* __C_specific_handler
* IofCompleteRequest
* IoCreateSymbolicLink
* IoCreateDevice
* KeTickCount
* KeBugCheckEx

{{< /details >}}
#### ExportedFunctions
{{< details "Expand" >}}

{{< /details >}}
-----
| Property           | Value |
|:-------------------|:------|
| Filename           | CITMDRV_IA64.sys |
| MD5                | [010c0e5ac584e3ab97a2daf84cf436f5](https://www.virustotal.com/gui/file/010c0e5ac584e3ab97a2daf84cf436f5) |
| SHA1               | [5711c88e9e64e45b8fc4b90ab6f2dd6437dc5a8a](https://www.virustotal.com/gui/file/5711c88e9e64e45b8fc4b90ab6f2dd6437dc5a8a) |
| SHA256             | [845f1e228de249fc1ddf8dc28c39d03e8ad328a6277b6502d3932e83b879a65a](https://www.virustotal.com/gui/file/845f1e228de249fc1ddf8dc28c39d03e8ad328a6277b6502d3932e83b879a65a) |
| Authentihash MD5   | [2be85acec4d5e36a137af7ef046e0cc8](https://www.virustotal.com/gui/search/authentihash%253A2be85acec4d5e36a137af7ef046e0cc8) |
| Authentihash SHA1  | [b90403d206e5f76bbf699c9627461d9fdafa9aa5](https://www.virustotal.com/gui/search/authentihash%253Ab90403d206e5f76bbf699c9627461d9fdafa9aa5) |
| Authentihash SHA256| [d453110c9050320419c2064ddea08230de6c76f86b07dc58112208e3d24a809e](https://www.virustotal.com/gui/search/authentihash%253Ad453110c9050320419c2064ddea08230de6c76f86b07dc58112208e3d24a809e) |
| Publisher         | IBM Polska Sp. z o.o. |
| Signature         | IBM Polska Sp. z o.o., Symantec Class 3 SHA256 Code Signing CA, VeriSign   |


#### Imports
{{< details "Expand" >}}
* ntoskrnl.exe

{{< /details >}}
#### ImportedFunctions
{{< details "Expand" >}}
* ZwClose
* ZwOpenFile
* RtlInitUnicodeString
* ZwWriteFile
* DbgPrint
* ZwCreateFile
* vsprintf
* IoDeleteDevice
* IoDeleteSymbolicLink
* ZwMapViewOfSection
* ZwUnmapViewOfSection
* MmUnlockPages
* IoFreeMdl
* ZwOpenSection
* MmProbeAndLockPages
* IoAllocateMdl
* __C_specific_handler
* IofCompleteRequest
* IoCreateSymbolicLink
* IoCreateDevice
* KeTickCount
* KeBugCheckEx

{{< /details >}}
#### ExportedFunctions
{{< details "Expand" >}}

{{< /details >}}
-----
| Property           | Value |
|:-------------------|:------|
| Filename           | CITMDRV_IA64.sys |
| MD5                | [ff7b31fa6e9ab923bce8af31d1be5bb2](https://www.virustotal.com/gui/file/ff7b31fa6e9ab923bce8af31d1be5bb2) |
| SHA1               | [6714380bc0b8ab09b9a0d2fa66d1b025b646b946](https://www.virustotal.com/gui/file/6714380bc0b8ab09b9a0d2fa66d1b025b646b946) |
| SHA256             | [84bf1d0bcdf175cfe8aea2973e0373015793d43907410ae97e2071b2c4b8e2d4](https://www.virustotal.com/gui/file/84bf1d0bcdf175cfe8aea2973e0373015793d43907410ae97e2071b2c4b8e2d4) |
| Authentihash MD5   | [2be85acec4d5e36a137af7ef046e0cc8](https://www.virustotal.com/gui/search/authentihash%253A2be85acec4d5e36a137af7ef046e0cc8) |
| Authentihash SHA1  | [b90403d206e5f76bbf699c9627461d9fdafa9aa5](https://www.virustotal.com/gui/search/authentihash%253Ab90403d206e5f76bbf699c9627461d9fdafa9aa5) |
| Authentihash SHA256| [d453110c9050320419c2064ddea08230de6c76f86b07dc58112208e3d24a809e](https://www.virustotal.com/gui/search/authentihash%253Ad453110c9050320419c2064ddea08230de6c76f86b07dc58112208e3d24a809e) |
| Publisher         | IBM Polska Sp. z o.o. |
| Signature         | IBM Polska Sp. z o.o., VeriSign Class 3 Code Signing 2010 CA, VeriSign   |


#### Imports
{{< details "Expand" >}}
* ntoskrnl.exe

{{< /details >}}
#### ImportedFunctions
{{< details "Expand" >}}
* ZwClose
* ZwOpenFile
* RtlInitUnicodeString
* ZwWriteFile
* DbgPrint
* ZwCreateFile
* vsprintf
* IoDeleteDevice
* IoDeleteSymbolicLink
* ZwMapViewOfSection
* ZwUnmapViewOfSection
* MmUnlockPages
* IoFreeMdl
* ZwOpenSection
* MmProbeAndLockPages
* IoAllocateMdl
* __C_specific_handler
* IofCompleteRequest
* IoCreateSymbolicLink
* IoCreateDevice
* KeTickCount
* KeBugCheckEx

{{< /details >}}
#### ExportedFunctions
{{< details "Expand" >}}

{{< /details >}}
-----
| Property           | Value |
|:-------------------|:------|
| Filename           | CITMDRV_IA64.sys |
| MD5                | [7bd840ff7f15df79a9a71fec7db1243e](https://www.virustotal.com/gui/file/7bd840ff7f15df79a9a71fec7db1243e) |
| SHA1               | [8626ab1da6bfbdf61bd327eb944b39fd9df33d1d](https://www.virustotal.com/gui/file/8626ab1da6bfbdf61bd327eb944b39fd9df33d1d) |
| SHA256             | [8ef0ad86500094e8fa3d9e7d53163aa6feef67c09575c169873c494ed66f057f](https://www.virustotal.com/gui/file/8ef0ad86500094e8fa3d9e7d53163aa6feef67c09575c169873c494ed66f057f) |
| Authentihash MD5   | [2be85acec4d5e36a137af7ef046e0cc8](https://www.virustotal.com/gui/search/authentihash%253A2be85acec4d5e36a137af7ef046e0cc8) |
| Authentihash SHA1  | [b90403d206e5f76bbf699c9627461d9fdafa9aa5](https://www.virustotal.com/gui/search/authentihash%253Ab90403d206e5f76bbf699c9627461d9fdafa9aa5) |
| Authentihash SHA256| [d453110c9050320419c2064ddea08230de6c76f86b07dc58112208e3d24a809e](https://www.virustotal.com/gui/search/authentihash%253Ad453110c9050320419c2064ddea08230de6c76f86b07dc58112208e3d24a809e) |
| Publisher         | IBM Polska Sp. z o.o. |
| Signature         | IBM Polska Sp. z o.o., VeriSign Class 3 Code Signing 2010 CA, VeriSign   |


#### Imports
{{< details "Expand" >}}
* ntoskrnl.exe

{{< /details >}}
#### ImportedFunctions
{{< details "Expand" >}}
* ZwClose
* ZwOpenFile
* RtlInitUnicodeString
* ZwWriteFile
* DbgPrint
* ZwCreateFile
* vsprintf
* IoDeleteDevice
* IoDeleteSymbolicLink
* ZwMapViewOfSection
* ZwUnmapViewOfSection
* MmUnlockPages
* IoFreeMdl
* ZwOpenSection
* MmProbeAndLockPages
* IoAllocateMdl
* __C_specific_handler
* IofCompleteRequest
* IoCreateSymbolicLink
* IoCreateDevice
* KeTickCount
* KeBugCheckEx

{{< /details >}}
#### ExportedFunctions
{{< details "Expand" >}}

{{< /details >}}
-----
| Property           | Value |
|:-------------------|:------|
| Filename           | CITMDRV_IA64.sys |
| MD5                | [fa222bed731713904320723b9c085b11](https://www.virustotal.com/gui/file/fa222bed731713904320723b9c085b11) |
| SHA1               | [30a224b22592d952fbe2e6ad97eda4a8f2c734e0](https://www.virustotal.com/gui/file/30a224b22592d952fbe2e6ad97eda4a8f2c734e0) |
| SHA256             | [a56c2a2425eb3a4260cc7fc5c8d7bed7a3b4cd2af256185f24471c668853aee8](https://www.virustotal.com/gui/file/a56c2a2425eb3a4260cc7fc5c8d7bed7a3b4cd2af256185f24471c668853aee8) |
| Authentihash MD5   | [2be85acec4d5e36a137af7ef046e0cc8](https://www.virustotal.com/gui/search/authentihash%253A2be85acec4d5e36a137af7ef046e0cc8) |
| Authentihash SHA1  | [b90403d206e5f76bbf699c9627461d9fdafa9aa5](https://www.virustotal.com/gui/search/authentihash%253Ab90403d206e5f76bbf699c9627461d9fdafa9aa5) |
| Authentihash SHA256| [d453110c9050320419c2064ddea08230de6c76f86b07dc58112208e3d24a809e](https://www.virustotal.com/gui/search/authentihash%253Ad453110c9050320419c2064ddea08230de6c76f86b07dc58112208e3d24a809e) |
| Publisher         | IBM Polska Sp. z o.o. |
| Signature         | IBM Polska Sp. z o.o., Symantec Class 3 SHA256 Code Signing CA, VeriSign   |


#### Imports
{{< details "Expand" >}}
* ntoskrnl.exe

{{< /details >}}
#### ImportedFunctions
{{< details "Expand" >}}
* ZwClose
* ZwOpenFile
* RtlInitUnicodeString
* ZwWriteFile
* DbgPrint
* ZwCreateFile
* vsprintf
* IoDeleteDevice
* IoDeleteSymbolicLink
* ZwMapViewOfSection
* ZwUnmapViewOfSection
* MmUnlockPages
* IoFreeMdl
* ZwOpenSection
* MmProbeAndLockPages
* IoAllocateMdl
* __C_specific_handler
* IofCompleteRequest
* IoCreateSymbolicLink
* IoCreateDevice
* KeTickCount
* KeBugCheckEx

{{< /details >}}
#### ExportedFunctions
{{< details "Expand" >}}

{{< /details >}}
-----
| Property           | Value |
|:-------------------|:------|
| Filename           | CITMDRV_IA64.sys |
| MD5                | [f778489c7105a63e9e789a02412aaa5f](https://www.virustotal.com/gui/file/f778489c7105a63e9e789a02412aaa5f) |
| SHA1               | [c95db1e82619fb16f8eec9a8209b7b0e853a4ebe](https://www.virustotal.com/gui/file/c95db1e82619fb16f8eec9a8209b7b0e853a4ebe) |
| SHA256             | [ac3f613d457fc4d44fa27b2e0b1baa62c09415705efb5a40a4756da39b3ac165](https://www.virustotal.com/gui/file/ac3f613d457fc4d44fa27b2e0b1baa62c09415705efb5a40a4756da39b3ac165) |
| Authentihash MD5   | [2be85acec4d5e36a137af7ef046e0cc8](https://www.virustotal.com/gui/search/authentihash%253A2be85acec4d5e36a137af7ef046e0cc8) |
| Authentihash SHA1  | [b90403d206e5f76bbf699c9627461d9fdafa9aa5](https://www.virustotal.com/gui/search/authentihash%253Ab90403d206e5f76bbf699c9627461d9fdafa9aa5) |
| Authentihash SHA256| [d453110c9050320419c2064ddea08230de6c76f86b07dc58112208e3d24a809e](https://www.virustotal.com/gui/search/authentihash%253Ad453110c9050320419c2064ddea08230de6c76f86b07dc58112208e3d24a809e) |
| Publisher         | IBM Polska Sp. z o.o. |
| Signature         | IBM Polska Sp. z o.o., Symantec Class 3 SHA256 Code Signing CA, VeriSign   |


#### Imports
{{< details "Expand" >}}
* ntoskrnl.exe

{{< /details >}}
#### ImportedFunctions
{{< details "Expand" >}}
* ZwClose
* ZwOpenFile
* RtlInitUnicodeString
* ZwWriteFile
* DbgPrint
* ZwCreateFile
* vsprintf
* IoDeleteDevice
* IoDeleteSymbolicLink
* ZwMapViewOfSection
* ZwUnmapViewOfSection
* MmUnlockPages
* IoFreeMdl
* ZwOpenSection
* MmProbeAndLockPages
* IoAllocateMdl
* __C_specific_handler
* IofCompleteRequest
* IoCreateSymbolicLink
* IoCreateDevice
* KeTickCount
* KeBugCheckEx

{{< /details >}}
#### ExportedFunctions
{{< details "Expand" >}}

{{< /details >}}
-----
| Property           | Value |
|:-------------------|:------|
| Filename           | CITMDRV_IA64.sys |
| MD5                | [ed07f1a8038596574184e09211dfc30f](https://www.virustotal.com/gui/file/ed07f1a8038596574184e09211dfc30f) |
| SHA1               | [fe1d909ab38de1389a2a48352fd1c8415fd2eab0](https://www.virustotal.com/gui/file/fe1d909ab38de1389a2a48352fd1c8415fd2eab0) |
| SHA256             | [b1334a71cc73b3d0c54f62d8011bec330dfc355a239bf94a121f6e4c86a30a2e](https://www.virustotal.com/gui/file/b1334a71cc73b3d0c54f62d8011bec330dfc355a239bf94a121f6e4c86a30a2e) |
| Authentihash MD5   | [2be85acec4d5e36a137af7ef046e0cc8](https://www.virustotal.com/gui/search/authentihash%253A2be85acec4d5e36a137af7ef046e0cc8) |
| Authentihash SHA1  | [b90403d206e5f76bbf699c9627461d9fdafa9aa5](https://www.virustotal.com/gui/search/authentihash%253Ab90403d206e5f76bbf699c9627461d9fdafa9aa5) |
| Authentihash SHA256| [d453110c9050320419c2064ddea08230de6c76f86b07dc58112208e3d24a809e](https://www.virustotal.com/gui/search/authentihash%253Ad453110c9050320419c2064ddea08230de6c76f86b07dc58112208e3d24a809e) |
| Publisher         | IBM Polska Sp. z o.o. |
| Signature         | IBM Polska Sp. z o.o., VeriSign Class 3 Code Signing 2009-2 CA, VeriSign Class 3 Public Primary CA   |


#### Imports
{{< details "Expand" >}}
* ntoskrnl.exe

{{< /details >}}
#### ImportedFunctions
{{< details "Expand" >}}
* ZwClose
* ZwOpenFile
* RtlInitUnicodeString
* ZwWriteFile
* DbgPrint
* ZwCreateFile
* vsprintf
* IoDeleteDevice
* IoDeleteSymbolicLink
* ZwMapViewOfSection
* ZwUnmapViewOfSection
* MmUnlockPages
* IoFreeMdl
* ZwOpenSection
* MmProbeAndLockPages
* IoAllocateMdl
* __C_specific_handler
* IofCompleteRequest
* IoCreateSymbolicLink
* IoCreateDevice
* KeTickCount
* KeBugCheckEx

{{< /details >}}
#### ExportedFunctions
{{< details "Expand" >}}

{{< /details >}}
-----
| Property           | Value |
|:-------------------|:------|
| Filename           | CITMDRV_IA64.sys |
| MD5                | [14eead4d42728e9340ec8399a225c124](https://www.virustotal.com/gui/file/14eead4d42728e9340ec8399a225c124) |
| SHA1               | [b4d1554ec19504215d27de0758e13c35ddd6db3e](https://www.virustotal.com/gui/file/b4d1554ec19504215d27de0758e13c35ddd6db3e) |
| SHA256             | [b47be212352d407d0ef7458a7161c66b47c2aec8391dd101df11e65728337a6a](https://www.virustotal.com/gui/file/b47be212352d407d0ef7458a7161c66b47c2aec8391dd101df11e65728337a6a) |
| Authentihash MD5   | [2be85acec4d5e36a137af7ef046e0cc8](https://www.virustotal.com/gui/search/authentihash%253A2be85acec4d5e36a137af7ef046e0cc8) |
| Authentihash SHA1  | [b90403d206e5f76bbf699c9627461d9fdafa9aa5](https://www.virustotal.com/gui/search/authentihash%253Ab90403d206e5f76bbf699c9627461d9fdafa9aa5) |
| Authentihash SHA256| [d453110c9050320419c2064ddea08230de6c76f86b07dc58112208e3d24a809e](https://www.virustotal.com/gui/search/authentihash%253Ad453110c9050320419c2064ddea08230de6c76f86b07dc58112208e3d24a809e) |
| Publisher         | IBM Polska Sp. z o.o. |
| Signature         | IBM Polska Sp. z o.o., Symantec Class 3 SHA256 Code Signing CA, VeriSign   |


#### Imports
{{< details "Expand" >}}
* ntoskrnl.exe

{{< /details >}}
#### ImportedFunctions
{{< details "Expand" >}}
* ZwClose
* ZwOpenFile
* RtlInitUnicodeString
* ZwWriteFile
* DbgPrint
* ZwCreateFile
* vsprintf
* IoDeleteDevice
* IoDeleteSymbolicLink
* ZwMapViewOfSection
* ZwUnmapViewOfSection
* MmUnlockPages
* IoFreeMdl
* ZwOpenSection
* MmProbeAndLockPages
* IoAllocateMdl
* __C_specific_handler
* IofCompleteRequest
* IoCreateSymbolicLink
* IoCreateDevice
* KeTickCount
* KeBugCheckEx

{{< /details >}}
#### ExportedFunctions
{{< details "Expand" >}}

{{< /details >}}
-----
| Property           | Value |
|:-------------------|:------|
| Filename           | CITMDRV_IA64.sys |
| MD5                | [825703c494e0d270f797f1ecf070f698](https://www.virustotal.com/gui/file/825703c494e0d270f797f1ecf070f698) |
| SHA1               | [5dd2c31c4357a8b76db095364952b3d0e3935e1d](https://www.virustotal.com/gui/file/5dd2c31c4357a8b76db095364952b3d0e3935e1d) |
| SHA256             | [b9b3878ddc5dfb237d38f8d25067267870afd67d12a330397a8853209c4d889c](https://www.virustotal.com/gui/file/b9b3878ddc5dfb237d38f8d25067267870afd67d12a330397a8853209c4d889c) |
| Authentihash MD5   | [2be85acec4d5e36a137af7ef046e0cc8](https://www.virustotal.com/gui/search/authentihash%253A2be85acec4d5e36a137af7ef046e0cc8) |
| Authentihash SHA1  | [b90403d206e5f76bbf699c9627461d9fdafa9aa5](https://www.virustotal.com/gui/search/authentihash%253Ab90403d206e5f76bbf699c9627461d9fdafa9aa5) |
| Authentihash SHA256| [d453110c9050320419c2064ddea08230de6c76f86b07dc58112208e3d24a809e](https://www.virustotal.com/gui/search/authentihash%253Ad453110c9050320419c2064ddea08230de6c76f86b07dc58112208e3d24a809e) |
| Publisher         | IBM Polska Sp. z o.o. |
| Signature         | IBM Polska Sp. z o.o., Symantec Class 3 SHA256 Code Signing CA, VeriSign   |


#### Imports
{{< details "Expand" >}}
* ntoskrnl.exe

{{< /details >}}
#### ImportedFunctions
{{< details "Expand" >}}
* ZwClose
* ZwOpenFile
* RtlInitUnicodeString
* ZwWriteFile
* DbgPrint
* ZwCreateFile
* vsprintf
* IoDeleteDevice
* IoDeleteSymbolicLink
* ZwMapViewOfSection
* ZwUnmapViewOfSection
* MmUnlockPages
* IoFreeMdl
* ZwOpenSection
* MmProbeAndLockPages
* IoAllocateMdl
* __C_specific_handler
* IofCompleteRequest
* IoCreateSymbolicLink
* IoCreateDevice
* KeTickCount
* KeBugCheckEx

{{< /details >}}
#### ExportedFunctions
{{< details "Expand" >}}

{{< /details >}}
-----
| Property           | Value |
|:-------------------|:------|
| Filename           | CITMDRV_IA64.sys |
| MD5                | [9007c94c9d91ccff8d7f5d4cdddcc403](https://www.virustotal.com/gui/file/9007c94c9d91ccff8d7f5d4cdddcc403) |
| SHA1               | [ecb4d096a9c58643b02f328d2c7742a38e017cf0](https://www.virustotal.com/gui/file/ecb4d096a9c58643b02f328d2c7742a38e017cf0) |
| SHA256             | [db90e554ad249c2bd888282ecf7d8da4d1538dd364129a3327b54f8242dd5653](https://www.virustotal.com/gui/file/db90e554ad249c2bd888282ecf7d8da4d1538dd364129a3327b54f8242dd5653) |
| Authentihash MD5   | [2be85acec4d5e36a137af7ef046e0cc8](https://www.virustotal.com/gui/search/authentihash%253A2be85acec4d5e36a137af7ef046e0cc8) |
| Authentihash SHA1  | [b90403d206e5f76bbf699c9627461d9fdafa9aa5](https://www.virustotal.com/gui/search/authentihash%253Ab90403d206e5f76bbf699c9627461d9fdafa9aa5) |
| Authentihash SHA256| [d453110c9050320419c2064ddea08230de6c76f86b07dc58112208e3d24a809e](https://www.virustotal.com/gui/search/authentihash%253Ad453110c9050320419c2064ddea08230de6c76f86b07dc58112208e3d24a809e) |
| Publisher         | IBM Polska Sp. z o.o. |
| Signature         | IBM Polska Sp. z o.o., Symantec Class 3 SHA256 Code Signing CA, VeriSign   |


#### Imports
{{< details "Expand" >}}
* ntoskrnl.exe

{{< /details >}}
#### ImportedFunctions
{{< details "Expand" >}}
* ZwClose
* ZwOpenFile
* RtlInitUnicodeString
* ZwWriteFile
* DbgPrint
* ZwCreateFile
* vsprintf
* IoDeleteDevice
* IoDeleteSymbolicLink
* ZwMapViewOfSection
* ZwUnmapViewOfSection
* MmUnlockPages
* IoFreeMdl
* ZwOpenSection
* MmProbeAndLockPages
* IoAllocateMdl
* __C_specific_handler
* IofCompleteRequest
* IoCreateSymbolicLink
* IoCreateDevice
* KeTickCount
* KeBugCheckEx

{{< /details >}}
#### ExportedFunctions
{{< details "Expand" >}}

{{< /details >}}
-----
| Property           | Value |
|:-------------------|:------|
| Filename           | CITMDRV_IA64.sys |
| MD5                | [9b359b722ac80c4e0a5235264e1e0156](https://www.virustotal.com/gui/file/9b359b722ac80c4e0a5235264e1e0156) |
| SHA1               | [4a705af959af61bad48ef7579f839cb5ebd654d2](https://www.virustotal.com/gui/file/4a705af959af61bad48ef7579f839cb5ebd654d2) |
| SHA256             | [e61a54f6d3869b43c4eceac3016df73df67cce03878c5a6167166601c5d3f028](https://www.virustotal.com/gui/file/e61a54f6d3869b43c4eceac3016df73df67cce03878c5a6167166601c5d3f028) |
| Authentihash MD5   | [2be85acec4d5e36a137af7ef046e0cc8](https://www.virustotal.com/gui/search/authentihash%253A2be85acec4d5e36a137af7ef046e0cc8) |
| Authentihash SHA1  | [b90403d206e5f76bbf699c9627461d9fdafa9aa5](https://www.virustotal.com/gui/search/authentihash%253Ab90403d206e5f76bbf699c9627461d9fdafa9aa5) |
| Authentihash SHA256| [d453110c9050320419c2064ddea08230de6c76f86b07dc58112208e3d24a809e](https://www.virustotal.com/gui/search/authentihash%253Ad453110c9050320419c2064ddea08230de6c76f86b07dc58112208e3d24a809e) |
| Publisher         | IBM Polska Sp. z o.o. |
| Signature         | IBM Polska Sp. z o.o., VeriSign Class 3 Code Signing 2010 CA, VeriSign   |


#### Imports
{{< details "Expand" >}}
* ntoskrnl.exe

{{< /details >}}
#### ImportedFunctions
{{< details "Expand" >}}
* ZwClose
* ZwOpenFile
* RtlInitUnicodeString
* ZwWriteFile
* DbgPrint
* ZwCreateFile
* vsprintf
* IoDeleteDevice
* IoDeleteSymbolicLink
* ZwMapViewOfSection
* ZwUnmapViewOfSection
* MmUnlockPages
* IoFreeMdl
* ZwOpenSection
* MmProbeAndLockPages
* IoAllocateMdl
* __C_specific_handler
* IofCompleteRequest
* IoCreateSymbolicLink
* IoCreateDevice
* KeTickCount
* KeBugCheckEx

{{< /details >}}
#### ExportedFunctions
{{< details "Expand" >}}

{{< /details >}}
-----



[*source*](https://github.com/magicsword-io/LOLDrivers/tree/main/yaml/citmdrv_ia64.yaml)

*last_updated:* 2023-04-26








{{< /column >}}
{{< /block >}}
