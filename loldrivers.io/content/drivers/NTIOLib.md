+++

description = ""
title = "NTIOLib.sys"
weight = 10

+++


{{< block "grid-1" >}}
{{< column "mt-2 pt-1">}}


# NTIOLib.sys ![:inline](/images/twitter_verified.png) 


### Description

NTIOLib.sys is a vulnerable driver and more information will be added as found.

- **Created**: 2023-01-09
- **Author**: Michael Haag
- **Acknowledgement**:  | [](https://twitter.com/)

{{< button "https://github.com/magicsword-io/LOLDrivers/raw/main/drivers/6126065af2fc2639473d12ee3c0c198e.bin" "Download" >}}
{{< tip "warning" >}}
{% if driver.Category == "vulnerable driver" %}
This download link contains the vulnerable driver!
{% elif driver.Category == "malicious" %}
This download link contains the malicious driver!
{% endif %}
{{< /tip >}}

### Commands

```
sc.exe create NTIOLib.sys binPath=C:\windows\temp\NTIOLib.sys type=kernel &amp;&amp; sc.exe start NTIOLib.sys
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

| Filename | NTIOLib.sys |
|:---- | ---- | 
| MD5 | <a href="https://www.virustotal.com/gui/file/6126065af2fc2639473d12ee3c0c198e">6126065af2fc2639473d12ee3c0c198e</a> |
| SHA1 | <a href="https://www.virustotal.com/gui/file/d7e8aef8c8feb87ce722c0b9abf34a7e6bab6eb4">d7e8aef8c8feb87ce722c0b9abf34a7e6bab6eb4</a> |
| SHA256 | <a href="https://www.virustotal.com/gui/file/09bedbf7a41e0f8dabe4f41d331db58373ce15b2e9204540873a1884f38bdde1">09bedbf7a41e0f8dabe4f41d331db58373ce15b2e9204540873a1884f38bdde1</a> |
| Authentihash MD5 | <a href="https://www.virustotal.com/gui/search/authentihash%253Afb5bbdd2bc73cd1f1f4bf727e6ddb137">fb5bbdd2bc73cd1f1f4bf727e6ddb137</a> || Authentihash SHA1 | <a href="https://www.virustotal.com/gui/search/authentihash%253A918768712f37fe0f3092b2ea452906d06f189bb3">918768712f37fe0f3092b2ea452906d06f189bb3</a> || Authentihash SHA256 | <a href="https://www.virustotal.com/gui/search/authentihash%253A5b08a501124d13262c86889617071743521aeefc2d77f678d541aa8dbad52992">5b08a501124d13262c86889617071743521aeefc2d77f678d541aa8dbad52992</a> || Signature | MICRO-STAR INTERNATIONAL CO., LTD., GlobalSign CodeSigning CA - G2, GlobalSign Root CA - R1   || Company | MSI || Description | NTIOLib || Product | NTIOLib || OriginalFilename | NTIOLib_X64.sys |
#### Imports
{{< details "Expand" >}}* ntoskrnl.exe
* HAL.dll
{{< /details >}}
#### ImportedFunctions
{{< details "Expand" >}}* MmUnmapIoSpace
* MmMapIoSpace
* IofCompleteRequest
* IoDeleteDevice
* IoCreateDevice
* KeBugCheckEx
* RtlInitUnicodeString
* IoCreateSymbolicLink
* IoDeleteSymbolicLink
* __C_specific_handler
* HalSetBusDataByOffset
* HalGetBusDataByOffset
{{< /details >}}
#### ExportedFunctions
{{< details "Expand" >}}{{< /details >}}
| Filename | NTIOLib.sys |
|:---- | ---- | 
| MD5 | <a href="https://www.virustotal.com/gui/file/c6f8983dd3d75640c072a8459b8fa55a">c6f8983dd3d75640c072a8459b8fa55a</a> |
| SHA1 | <a href="https://www.virustotal.com/gui/file/5e6ddd2b39a3de0016385cbd7aa50e49451e376d">5e6ddd2b39a3de0016385cbd7aa50e49451e376d</a> |
| SHA256 | <a href="https://www.virustotal.com/gui/file/101402d4f5d1ae413ded499c78a5fcbbc7e3bae9b000d64c1dd64e3c48c37558">101402d4f5d1ae413ded499c78a5fcbbc7e3bae9b000d64c1dd64e3c48c37558</a> |
| Authentihash MD5 | <a href="https://www.virustotal.com/gui/search/authentihash%253Ab3f5d7d5ea5ddb56cae089ab780d2058">b3f5d7d5ea5ddb56cae089ab780d2058</a> || Authentihash SHA1 | <a href="https://www.virustotal.com/gui/search/authentihash%253Ab648e51b784f071adbf9f53048e3765efb96ab8a">b648e51b784f071adbf9f53048e3765efb96ab8a</a> || Authentihash SHA256 | <a href="https://www.virustotal.com/gui/search/authentihash%253A745273e1620bc657d2210ae1b5abb49f4f5928829f95c8ef01ce151bdbb4c32f">745273e1620bc657d2210ae1b5abb49f4f5928829f95c8ef01ce151bdbb4c32f</a> || Signature | MICRO-STAR INTERNATIONAL CO., LTD., GlobalSign CodeSigning CA - G2, GlobalSign Root CA - R1   || Company | MSI || Description | NTIOLib || Product | NTIOLib || OriginalFilename | NTIOLib.sys |
#### Imports
{{< details "Expand" >}}* ntoskrnl.exe
* HAL.dll
{{< /details >}}
#### ImportedFunctions
{{< details "Expand" >}}* MmUnmapIoSpace
* MmMapIoSpace
* IofCompleteRequest
* IoDeleteDevice
* IoCreateDevice
* KeBugCheckEx
* RtlInitUnicodeString
* IoCreateSymbolicLink
* IoDeleteSymbolicLink
* __C_specific_handler
* HalSetBusDataByOffset
* HalGetBusDataByOffset
{{< /details >}}
#### ExportedFunctions
{{< details "Expand" >}}{{< /details >}}
| Filename | NTIOLib.sys |
|:---- | ---- | 
| MD5 | <a href="https://www.virustotal.com/gui/file/f7cbbb5eb263ec9a35a1042f52e82ca4">f7cbbb5eb263ec9a35a1042f52e82ca4</a> |
| SHA1 | <a href="https://www.virustotal.com/gui/file/976777d39d73034df6b113dfce1aa6e1d00ffcfd">976777d39d73034df6b113dfce1aa6e1d00ffcfd</a> |
| SHA256 | <a href="https://www.virustotal.com/gui/file/131d5490ceb9a5b2324d8e927fea5becfc633015661de2f4c2f2375a3a3b64c6">131d5490ceb9a5b2324d8e927fea5becfc633015661de2f4c2f2375a3a3b64c6</a> |
| Authentihash MD5 | <a href="https://www.virustotal.com/gui/search/authentihash%253A63cc49f8ae8897706dec2444951c0414">63cc49f8ae8897706dec2444951c0414</a> || Authentihash SHA1 | <a href="https://www.virustotal.com/gui/search/authentihash%253Aae69d3501e7fe1e2109998beed9da13f74e032c2">ae69d3501e7fe1e2109998beed9da13f74e032c2</a> || Authentihash SHA256 | <a href="https://www.virustotal.com/gui/search/authentihash%253A7334c46a55acf8bb18435ab60ed9b89f2c1ab31587ef052730358efc32fddb62">7334c46a55acf8bb18435ab60ed9b89f2c1ab31587ef052730358efc32fddb62</a> || Signature | MICRO-STAR INTERNATIONAL CO., LTD., GlobalSign CodeSigning CA - G2, GlobalSign Root CA - R1   || Company | MSI || Description | NTIOLib || Product | NTIOLib || OriginalFilename | NTIOLib.sys |
#### Imports
{{< details "Expand" >}}* ntoskrnl.exe
* HAL.dll
{{< /details >}}
#### ImportedFunctions
{{< details "Expand" >}}* MmUnmapIoSpace
* MmMapIoSpace
* IofCompleteRequest
* IoDeleteDevice
* IoCreateDevice
* KeBugCheckEx
* RtlInitUnicodeString
* IoCreateSymbolicLink
* IoDeleteSymbolicLink
* __C_specific_handler
* HalSetBusDataByOffset
* HalGetBusDataByOffset
{{< /details >}}
#### ExportedFunctions
{{< details "Expand" >}}{{< /details >}}
| Filename | NTIOLib.sys |
|:---- | ---- | 
| MD5 | <a href="https://www.virustotal.com/gui/file/7ed6030f14e66e743241f2c1fa783e69">7ed6030f14e66e743241f2c1fa783e69</a> |
| SHA1 | <a href="https://www.virustotal.com/gui/file/9c6749fc6c1127f8788bff70e0ce9062959637c9">9c6749fc6c1127f8788bff70e0ce9062959637c9</a> |
| SHA256 | <a href="https://www.virustotal.com/gui/file/1ddfe4756f5db9fb319d6c6da9c41c588a729d9e7817190b027b38e9c076d219">1ddfe4756f5db9fb319d6c6da9c41c588a729d9e7817190b027b38e9c076d219</a> |
| Authentihash MD5 | <a href="https://www.virustotal.com/gui/search/authentihash%253A07744c410b3e3a459576524f1b522a88">07744c410b3e3a459576524f1b522a88</a> || Authentihash SHA1 | <a href="https://www.virustotal.com/gui/search/authentihash%253Abfa958230e3816f9879e16ec391e94b607f292e6">bfa958230e3816f9879e16ec391e94b607f292e6</a> || Authentihash SHA256 | <a href="https://www.virustotal.com/gui/search/authentihash%253A7af3585ca7c2dd65032fa48759a0124db2c5bbca5fc8caf8bb8f61fa5085149d">7af3585ca7c2dd65032fa48759a0124db2c5bbca5fc8caf8bb8f61fa5085149d</a> || Signature | MICRO-STAR INTERNATIONAL CO., LTD., GlobalSign CodeSigning CA - G2, GlobalSign Root CA - R1   || Company | MSI || Description | NTIOLib || Product | NTIOLib || OriginalFilename | NTIOLib.sys |
#### Imports
{{< details "Expand" >}}* ntoskrnl.exe
* HAL.dll
{{< /details >}}
#### ImportedFunctions
{{< details "Expand" >}}* MmUnmapIoSpace
* MmMapIoSpace
* IofCompleteRequest
* IoDeleteDevice
* IoCreateDevice
* KeBugCheckEx
* RtlInitUnicodeString
* IoCreateSymbolicLink
* IoDeleteSymbolicLink
* __C_specific_handler
* HalSetBusDataByOffset
* HalGetBusDataByOffset
{{< /details >}}
#### ExportedFunctions
{{< details "Expand" >}}{{< /details >}}
| Filename | NTIOLib.sys |
|:---- | ---- | 
| MD5 | <a href="https://www.virustotal.com/gui/file/3651a6990fe38711ebb285143f867a43">3651a6990fe38711ebb285143f867a43</a> |
| SHA1 | <a href="https://www.virustotal.com/gui/file/53acd4d9e7ba0b1056cf52af0d191f226eddf312">53acd4d9e7ba0b1056cf52af0d191f226eddf312</a> |
| SHA256 | <a href="https://www.virustotal.com/gui/file/1e8b0c1966e566a523d652e00f7727d8b0663f1dfdce3b9a09b9adfaef48d8ee">1e8b0c1966e566a523d652e00f7727d8b0663f1dfdce3b9a09b9adfaef48d8ee</a> |
| Authentihash MD5 | <a href="https://www.virustotal.com/gui/search/authentihash%253A575bfa9a34097f8d19982dcdd9118094">575bfa9a34097f8d19982dcdd9118094</a> || Authentihash SHA1 | <a href="https://www.virustotal.com/gui/search/authentihash%253A9369dbe6e082a2af351daebeef1c464af33cc270">9369dbe6e082a2af351daebeef1c464af33cc270</a> || Authentihash SHA256 | <a href="https://www.virustotal.com/gui/search/authentihash%253A6f96c129eb96bc4df9a7d247a98fecb9a3801dde63281ac1aba3d2ef869d32a5">6f96c129eb96bc4df9a7d247a98fecb9a3801dde63281ac1aba3d2ef869d32a5</a> || Signature | MICRO-STAR INTERNATIONAL CO., LTD., GlobalSign CodeSigning CA - G2, GlobalSign Root CA - R1   || Company | MSI || Description | NTIOLib_X64 || Product | NTIOLib_X64 || OriginalFilename | NTIOLib_X64.sys |
#### Imports
{{< details "Expand" >}}* ntoskrnl.exe
* HAL.dll
{{< /details >}}
#### ImportedFunctions
{{< details "Expand" >}}* MmUnmapIoSpace
* MmMapIoSpace
* IofCompleteRequest
* IoDeleteDevice
* IoCreateDevice
* KeBugCheckEx
* RtlInitUnicodeString
* IoCreateSymbolicLink
* IoDeleteSymbolicLink
* __C_specific_handler
* HalSetBusDataByOffset
* HalGetBusDataByOffset
{{< /details >}}
#### ExportedFunctions
{{< details "Expand" >}}{{< /details >}}
| Filename | NTIOLib.sys |
|:---- | ---- | 
| MD5 | <a href="https://www.virustotal.com/gui/file/736c4b85ce346ddf3b49b1e3abb4e72a">736c4b85ce346ddf3b49b1e3abb4e72a</a> |
| SHA1 | <a href="https://www.virustotal.com/gui/file/3abb9d0a9d600200ae19c706e570465ef0a15643">3abb9d0a9d600200ae19c706e570465ef0a15643</a> |
| SHA256 | <a href="https://www.virustotal.com/gui/file/2bbe65cbec3bb069e92233924f7ee1f95ffa16173fceb932c34f68d862781250">2bbe65cbec3bb069e92233924f7ee1f95ffa16173fceb932c34f68d862781250</a> |
| Authentihash MD5 | <a href="https://www.virustotal.com/gui/search/authentihash%253Afb364fe88525eface63e291f7e86338e">fb364fe88525eface63e291f7e86338e</a> || Authentihash SHA1 | <a href="https://www.virustotal.com/gui/search/authentihash%253A0f661f61f0106faeda1d6cbe83b81aaf3ea4d28c">0f661f61f0106faeda1d6cbe83b81aaf3ea4d28c</a> || Authentihash SHA256 | <a href="https://www.virustotal.com/gui/search/authentihash%253A299f36c717c5d5d77a8e9c15879e95cd825f74e77c7ed24e7cccbefeb38a2165">299f36c717c5d5d77a8e9c15879e95cd825f74e77c7ed24e7cccbefeb38a2165</a> || Signature | MICRO-STAR INTERNATIONAL CO., GlobalSign CodeSigning CA - G2, GlobalSign   || Company | MSI || Description | NTIOLib For MSISimple_OC || Product | NTIOLib || OriginalFilename | NTIOLib.sys |
#### Imports
{{< details "Expand" >}}* ntoskrnl.exe
* HAL.dll
{{< /details >}}
#### ImportedFunctions
{{< details "Expand" >}}* MmUnmapIoSpace
* MmMapIoSpace
* IofCompleteRequest
* IoDeleteDevice
* IoCreateDevice
* KeBugCheckEx
* RtlInitUnicodeString
* IoCreateSymbolicLink
* IoDeleteSymbolicLink
* __C_specific_handler
* HalSetBusDataByOffset
* HalGetBusDataByOffset
{{< /details >}}
#### ExportedFunctions
{{< details "Expand" >}}{{< /details >}}
| Filename | NTIOLib.sys |
|:---- | ---- | 
| MD5 | <a href="https://www.virustotal.com/gui/file/4a06bcd96ef0b90a1753a805b4235f28">4a06bcd96ef0b90a1753a805b4235f28</a> |
| SHA1 | <a href="https://www.virustotal.com/gui/file/27eab595ec403580236e04101172247c4f5d5426">27eab595ec403580236e04101172247c4f5d5426</a> |
| SHA256 | <a href="https://www.virustotal.com/gui/file/30706f110725199e338e9cc1c940d9a644d19a14f0eb8847712cba4cacda67ab">30706f110725199e338e9cc1c940d9a644d19a14f0eb8847712cba4cacda67ab</a> |
| Authentihash MD5 | <a href="https://www.virustotal.com/gui/search/authentihash%253A1a384cdc0edc4e14d6dfb5b242e9313f">1a384cdc0edc4e14d6dfb5b242e9313f</a> || Authentihash SHA1 | <a href="https://www.virustotal.com/gui/search/authentihash%253A13874ae76957845e9315eedf0f5f2b59eedcb9a6">13874ae76957845e9315eedf0f5f2b59eedcb9a6</a> || Authentihash SHA256 | <a href="https://www.virustotal.com/gui/search/authentihash%253A1f210a62de46c5acb868a083465b94287331ec28acd3b269e64ab6c3f372021f">1f210a62de46c5acb868a083465b94287331ec28acd3b269e64ab6c3f372021f</a> || Signature | MICRO-STAR INTERNATIONAL CO., LTD., GlobalSign CodeSigning CA - G2, GlobalSign   || Company | MSI || Description | MSI ComCenService Driver || Product | NTIOLib || OriginalFilename | NTIOLib.sys |
#### Imports
{{< details "Expand" >}}* ntoskrnl.exe
* HAL.dll
{{< /details >}}
#### ImportedFunctions
{{< details "Expand" >}}* MmUnmapIoSpace
* MmMapIoSpace
* IofCompleteRequest
* IoDeleteDevice
* IoCreateDevice
* KeBugCheckEx
* RtlInitUnicodeString
* IoCreateSymbolicLink
* IoDeleteSymbolicLink
* __C_specific_handler
* HalSetBusDataByOffset
* HalGetBusDataByOffset
{{< /details >}}
#### ExportedFunctions
{{< details "Expand" >}}{{< /details >}}
| Filename | NTIOLib.sys |
|:---- | ---- | 
| MD5 | <a href="https://www.virustotal.com/gui/file/63e333d64a8716e1ae59f914cb686ae8">63e333d64a8716e1ae59f914cb686ae8</a> |
| SHA1 | <a href="https://www.virustotal.com/gui/file/78b9481607ca6f3a80b4515c432ddfe6550b18a8">78b9481607ca6f3a80b4515c432ddfe6550b18a8</a> |
| SHA256 | <a href="https://www.virustotal.com/gui/file/3124b0411b8077605db2a9b7909d8240e0d554496600e2706e531c93c931e1b5">3124b0411b8077605db2a9b7909d8240e0d554496600e2706e531c93c931e1b5</a> |
| Authentihash MD5 | <a href="https://www.virustotal.com/gui/search/authentihash%253A9e87790870d27c78e12a870557a5decf">9e87790870d27c78e12a870557a5decf</a> || Authentihash SHA1 | <a href="https://www.virustotal.com/gui/search/authentihash%253Aff09c47ebaa82cdde41a1be4e65f5a7cafb28322">ff09c47ebaa82cdde41a1be4e65f5a7cafb28322</a> || Authentihash SHA256 | <a href="https://www.virustotal.com/gui/search/authentihash%253A051dad67cc6cb6b6e20b1230b04c09cc360d106a6b7000e0991381356ace0811">051dad67cc6cb6b6e20b1230b04c09cc360d106a6b7000e0991381356ace0811</a> || Signature | MICRO-STAR INTERNATIONAL CO., LTD., GlobalSign CodeSigning CA - G2, GlobalSign Root CA - R1   || Company | MSI || Description | NTIOLib for MSIFrequency_CC || Product | NTIOLib || OriginalFilename | NTIOLib.sys |
#### Imports
{{< details "Expand" >}}* ntoskrnl.exe
* HAL.dll
{{< /details >}}
#### ImportedFunctions
{{< details "Expand" >}}* MmUnmapIoSpace
* MmMapIoSpace
* IofCompleteRequest
* IoDeleteDevice
* IoCreateDevice
* KeBugCheckEx
* RtlInitUnicodeString
* IoCreateSymbolicLink
* IoDeleteSymbolicLink
* __C_specific_handler
* HalSetBusDataByOffset
* HalGetBusDataByOffset
{{< /details >}}
#### ExportedFunctions
{{< details "Expand" >}}{{< /details >}}
| Filename | NTIOLib.sys |
|:---- | ---- | 
| MD5 | <a href="https://www.virustotal.com/gui/file/79483cb29a0c428e1362ec8642109eee">79483cb29a0c428e1362ec8642109eee</a> |
| SHA1 | <a href="https://www.virustotal.com/gui/file/414cd15d6c991d19fb5be02e3b9fb0e6c5ce731c">414cd15d6c991d19fb5be02e3b9fb0e6c5ce731c</a> |
| SHA256 | <a href="https://www.virustotal.com/gui/file/38fa0c663c8689048726666f1c5e019feaa9da8278f1df6ff62da33961891d2a">38fa0c663c8689048726666f1c5e019feaa9da8278f1df6ff62da33961891d2a</a> |
| Authentihash MD5 | <a href="https://www.virustotal.com/gui/search/authentihash%253A4f3fc3f46b55c66e36a411e0389d9740">4f3fc3f46b55c66e36a411e0389d9740</a> || Authentihash SHA1 | <a href="https://www.virustotal.com/gui/search/authentihash%253Afed54cfff38966133b7fbc067246bbfca871118b">fed54cfff38966133b7fbc067246bbfca871118b</a> || Authentihash SHA256 | <a href="https://www.virustotal.com/gui/search/authentihash%253A9a1d483d6ca994942533fcfe10c11b1725bbb9551e435476453a57ce7ff17029">9a1d483d6ca994942533fcfe10c11b1725bbb9551e435476453a57ce7ff17029</a> || Signature | Micro-Star Int&#39;l Co. Ltd., GlobalSign ObjectSign CA, GlobalSign Primary Object Publishing CA, GlobalSign   || Company | MSI || Description | NTIOLib || Product | NTIOLib || OriginalFilename | NTIOLib.sys |
#### Imports
{{< details "Expand" >}}* ntoskrnl.exe
* HAL.dll
{{< /details >}}
#### ImportedFunctions
{{< details "Expand" >}}* MmUnmapIoSpace
* MmMapIoSpace
* IofCompleteRequest
* IoDeleteDevice
* IoCreateDevice
* KeBugCheckEx
* RtlInitUnicodeString
* IoCreateSymbolicLink
* IoDeleteSymbolicLink
* __C_specific_handler
* HalSetBusDataByOffset
* HalGetBusDataByOffset
{{< /details >}}
#### ExportedFunctions
{{< details "Expand" >}}{{< /details >}}
| Filename | NTIOLib.sys |
|:---- | ---- | 
| MD5 | <a href="https://www.virustotal.com/gui/file/23cf3da010497eb2bf39a5c5a57e437c">23cf3da010497eb2bf39a5c5a57e437c</a> |
| SHA1 | <a href="https://www.virustotal.com/gui/file/d9c09dd725bc7bc3c19b4db37866015817a516ef">d9c09dd725bc7bc3c19b4db37866015817a516ef</a> |
| SHA256 | <a href="https://www.virustotal.com/gui/file/39cfde7d401efce4f550e0a9461f5fc4d71fa07235e1336e4f0b4882bd76550e">39cfde7d401efce4f550e0a9461f5fc4d71fa07235e1336e4f0b4882bd76550e</a> |
| Authentihash MD5 | <a href="https://www.virustotal.com/gui/search/authentihash%253Ad3ef4e7146fce9f2a17134d42c07166b">d3ef4e7146fce9f2a17134d42c07166b</a> || Authentihash SHA1 | <a href="https://www.virustotal.com/gui/search/authentihash%253Aee34907ac4afce04fe1bab85e68d7e743db05841">ee34907ac4afce04fe1bab85e68d7e743db05841</a> || Authentihash SHA256 | <a href="https://www.virustotal.com/gui/search/authentihash%253Aa6bf32fafa57bcbb84b06db0d7d28e4b1457ead69c33fa883d5abe84ecd91b51">a6bf32fafa57bcbb84b06db0d7d28e4b1457ead69c33fa883d5abe84ecd91b51</a> || Signature | MICRO-STAR INTERNATIONAL CO., LTD., GlobalSign CodeSigning CA - G2, GlobalSign Root CA - R1   || Company | MSI || Description | NTIOLib || Product | NTIOLib || OriginalFilename | NTIOLib.sys |
#### Imports
{{< details "Expand" >}}* ntoskrnl.exe
* HAL.dll
{{< /details >}}
#### ImportedFunctions
{{< details "Expand" >}}* MmUnmapIoSpace
* MmMapIoSpace
* IofCompleteRequest
* IoDeleteDevice
* IoCreateDevice
* KeBugCheckEx
* RtlInitUnicodeString
* IoCreateSymbolicLink
* IoDeleteSymbolicLink
* __C_specific_handler
* HalSetBusDataByOffset
* HalGetBusDataByOffset
{{< /details >}}
#### ExportedFunctions
{{< details "Expand" >}}{{< /details >}}
| Filename | NTIOLib.sys |
|:---- | ---- | 
| MD5 | <a href="https://www.virustotal.com/gui/file/9638f265b1ddd5da6ecdf5c0619dcbe6">9638f265b1ddd5da6ecdf5c0619dcbe6</a> |
| SHA1 | <a href="https://www.virustotal.com/gui/file/9c256edd10823ca76c0443a330e523027b70522d">9c256edd10823ca76c0443a330e523027b70522d</a> |
| SHA256 | <a href="https://www.virustotal.com/gui/file/3d9e83b189fcf5c3541c62d1f54a0da0a4e5b62c3243d2989afc46644056c8e3">3d9e83b189fcf5c3541c62d1f54a0da0a4e5b62c3243d2989afc46644056c8e3</a> |
| Authentihash MD5 | <a href="https://www.virustotal.com/gui/search/authentihash%253Aff9b15a51f11874a9abe7a1b9f4cfd0d">ff9b15a51f11874a9abe7a1b9f4cfd0d</a> || Authentihash SHA1 | <a href="https://www.virustotal.com/gui/search/authentihash%253A0d3956de7c3a7788727358867abf34880eaa7100">0d3956de7c3a7788727358867abf34880eaa7100</a> || Authentihash SHA256 | <a href="https://www.virustotal.com/gui/search/authentihash%253Acf3ec8972720f84d73e907bb293de40468a0d605ce0da658a786f7b4842b3c62">cf3ec8972720f84d73e907bb293de40468a0d605ce0da658a786f7b4842b3c62</a> || Signature | MICRO-STAR INTERNATIONAL CO., LTD., GlobalSign CodeSigning CA - G2, GlobalSign Root CA - R1   || Company | MSI || Description | NTIOLib For NTIOLib_ECO || Product | NTIOLib || OriginalFilename | NTIOLib.sys |
#### Imports
{{< details "Expand" >}}* ntoskrnl.exe
* HAL.dll
{{< /details >}}
#### ImportedFunctions
{{< details "Expand" >}}* MmUnmapIoSpace
* MmMapIoSpace
* IofCompleteRequest
* IoDeleteDevice
* IoCreateDevice
* KeBugCheckEx
* RtlInitUnicodeString
* IoCreateSymbolicLink
* IoDeleteSymbolicLink
* __C_specific_handler
* HalSetBusDataByOffset
* HalGetBusDataByOffset
{{< /details >}}
#### ExportedFunctions
{{< details "Expand" >}}{{< /details >}}
| Filename | NTIOLib.sys |
|:---- | ---- | 
| MD5 | <a href="https://www.virustotal.com/gui/file/f2f728d2f69765f5dfda913d407783d2">f2f728d2f69765f5dfda913d407783d2</a> |
| SHA1 | <a href="https://www.virustotal.com/gui/file/35829e096a15e559fcbabf3441d99e580ca3b26e">35829e096a15e559fcbabf3441d99e580ca3b26e</a> |
| SHA256 | <a href="https://www.virustotal.com/gui/file/3f2fda9a7a9c57b7138687bbce49a2e156d6095dddabb3454ea09737e02c3fa5">3f2fda9a7a9c57b7138687bbce49a2e156d6095dddabb3454ea09737e02c3fa5</a> |
| Authentihash MD5 | <a href="https://www.virustotal.com/gui/search/authentihash%253A2d87365d63e81ef0edc577bf0cb33995">2d87365d63e81ef0edc577bf0cb33995</a> || Authentihash SHA1 | <a href="https://www.virustotal.com/gui/search/authentihash%253Ab472d32094e258b2af60914db8604cd0bf439c4b">b472d32094e258b2af60914db8604cd0bf439c4b</a> || Authentihash SHA256 | <a href="https://www.virustotal.com/gui/search/authentihash%253Ad33f19a12cd8e8649a56ce2a41e2b56d2ed80f203e5ededc4114c78ef773ffa8">d33f19a12cd8e8649a56ce2a41e2b56d2ed80f203e5ededc4114c78ef773ffa8</a> || Signature | MICRO-STAR INTERNATIONAL CO., LTD., GlobalSign CodeSigning CA - G2, GlobalSign Root CA - R1   || Company | MSI || Description | NTIOLib || Product | NTIOLib || OriginalFilename | NTIOLib.sys |
#### Imports
{{< details "Expand" >}}* ntoskrnl.exe
* HAL.dll
{{< /details >}}
#### ImportedFunctions
{{< details "Expand" >}}* MmUnmapIoSpace
* MmMapIoSpace
* IofCompleteRequest
* IoDeleteDevice
* IoCreateDevice
* KeBugCheckEx
* RtlInitUnicodeString
* IoCreateSymbolicLink
* IoDeleteSymbolicLink
* __C_specific_handler
* HalSetBusDataByOffset
* HalGetBusDataByOffset
{{< /details >}}
#### ExportedFunctions
{{< details "Expand" >}}{{< /details >}}
| Filename | NTIOLib.sys |
|:---- | ---- | 
| MD5 | <a href="https://www.virustotal.com/gui/file/992ded5b623be3c228f32edb4ca3f2d2">992ded5b623be3c228f32edb4ca3f2d2</a> |
| SHA1 | <a href="https://www.virustotal.com/gui/file/b8de3a1aeeda9deea43e3f768071125851c85bd0">b8de3a1aeeda9deea43e3f768071125851c85bd0</a> |
| SHA256 | <a href="https://www.virustotal.com/gui/file/47f0cdaa2359a63ad1389ef4a635f1f6eee1f63bdf6ef177f114bdcdadc2e005">47f0cdaa2359a63ad1389ef4a635f1f6eee1f63bdf6ef177f114bdcdadc2e005</a> |
| Authentihash MD5 | <a href="https://www.virustotal.com/gui/search/authentihash%253A1d0d0ef174a767359bb32e53fe346416">1d0d0ef174a767359bb32e53fe346416</a> || Authentihash SHA1 | <a href="https://www.virustotal.com/gui/search/authentihash%253A4dbbf2558cdbdaf4a5e5ec65e844f5abdace5514">4dbbf2558cdbdaf4a5e5ec65e844f5abdace5514</a> || Authentihash SHA256 | <a href="https://www.virustotal.com/gui/search/authentihash%253A809403706c3669a0d67bd35a87f66714989d1bc66e2aa6ca5979781ae3c4fdb0">809403706c3669a0d67bd35a87f66714989d1bc66e2aa6ca5979781ae3c4fdb0</a> || Signature | MICRO-STAR INTERNATIONAL CO., LTD., GlobalSign CodeSigning CA - G2, GlobalSign Root CA - R1   || Company | MSI || Description | NTIOLib || Product | NTIOLib || OriginalFilename | NTIOLib.sys |
#### Imports
{{< details "Expand" >}}* ntoskrnl.exe
* HAL.dll
{{< /details >}}
#### ImportedFunctions
{{< details "Expand" >}}* MmUnmapIoSpace
* MmMapIoSpace
* IofCompleteRequest
* IoDeleteDevice
* IoCreateDevice
* KeBugCheckEx
* RtlInitUnicodeString
* IoCreateSymbolicLink
* IoDeleteSymbolicLink
* __C_specific_handler
* HalSetBusDataByOffset
* HalGetBusDataByOffset
{{< /details >}}
#### ExportedFunctions
{{< details "Expand" >}}{{< /details >}}
| Filename | NTIOLib.sys |
|:---- | ---- | 
| MD5 | <a href="https://www.virustotal.com/gui/file/c3fea895fe95ea7a57d9f4d7abed5e71">c3fea895fe95ea7a57d9f4d7abed5e71</a> |
| SHA1 | <a href="https://www.virustotal.com/gui/file/054a50293c7b4eea064c91ef59cf120d8100f237">054a50293c7b4eea064c91ef59cf120d8100f237</a> |
| SHA256 | <a href="https://www.virustotal.com/gui/file/50d5eaa168c077ce5b7f15b3f2c43bd2b86b07b1e926c1b332f8cb13bd2e0793">50d5eaa168c077ce5b7f15b3f2c43bd2b86b07b1e926c1b332f8cb13bd2e0793</a> |
| Authentihash MD5 | <a href="https://www.virustotal.com/gui/search/authentihash%253A922f6d3d0dda7748bad7a537a8bc9e4e">922f6d3d0dda7748bad7a537a8bc9e4e</a> || Authentihash SHA1 | <a href="https://www.virustotal.com/gui/search/authentihash%253A71355d9ebcf35492b60c3f936550d30310a31049">71355d9ebcf35492b60c3f936550d30310a31049</a> || Authentihash SHA256 | <a href="https://www.virustotal.com/gui/search/authentihash%253A9d734d6443a707d601d76577692dc613b35201518856d0189b037f7a4fbd420d">9d734d6443a707d601d76577692dc613b35201518856d0189b037f7a4fbd420d</a> || Signature | Micro-Star Int&#39;l Co. Ltd., GlobalSign ObjectSign CA, GlobalSign Primary Object Publishing CA, GlobalSign Root CA - R1   || Company | MSI || Description | NTIOLib || Product | NTIOLib || OriginalFilename | NTIOLib.sys |
#### Imports
{{< details "Expand" >}}* ntoskrnl.exe
* HAL.dll
{{< /details >}}
#### ImportedFunctions
{{< details "Expand" >}}* MmUnmapIoSpace
* MmMapIoSpace
* IofCompleteRequest
* IoDeleteDevice
* IoCreateDevice
* KeBugCheckEx
* RtlInitUnicodeString
* IoCreateSymbolicLink
* IoDeleteSymbolicLink
* __C_specific_handler
* HalSetBusDataByOffset
* HalGetBusDataByOffset
{{< /details >}}
#### ExportedFunctions
{{< details "Expand" >}}{{< /details >}}
| Filename | NTIOLib.sys |
|:---- | ---- | 
| MD5 | <a href="https://www.virustotal.com/gui/file/0395b4e0eb21693590ad1cfdf7044b8b">0395b4e0eb21693590ad1cfdf7044b8b</a> |
| SHA1 | <a href="https://www.virustotal.com/gui/file/d94f2fb3198e14bfe69b44fb9f00f2551f7248b2">d94f2fb3198e14bfe69b44fb9f00f2551f7248b2</a> |
| SHA256 | <a href="https://www.virustotal.com/gui/file/56a3c9ac137d862a85b4004f043d46542a1b61c6acb438098a9640469e2d80e7">56a3c9ac137d862a85b4004f043d46542a1b61c6acb438098a9640469e2d80e7</a> |
| Authentihash MD5 | <a href="https://www.virustotal.com/gui/search/authentihash%253Ac6830e904e56ea951005ea7639eedd35">c6830e904e56ea951005ea7639eedd35</a> || Authentihash SHA1 | <a href="https://www.virustotal.com/gui/search/authentihash%253Ac57c0dd18135bca5fdb094858a70033c006cd281">c57c0dd18135bca5fdb094858a70033c006cd281</a> || Authentihash SHA256 | <a href="https://www.virustotal.com/gui/search/authentihash%253A4a05ad47cd63932b3df2d0f1f42617321729772211bec651fe061140d3e75957">4a05ad47cd63932b3df2d0f1f42617321729772211bec651fe061140d3e75957</a> || Signature | MICRO-STAR INTERNATIONAL CO., LTD., GlobalSign CodeSigning CA - G2, GlobalSign Root CA - R1   || Company | MSI || Description | NTIOLib || Product | NTIOLib || OriginalFilename | NTIOLib.sys |
#### Imports
{{< details "Expand" >}}* ntoskrnl.exe
* HAL.dll
{{< /details >}}
#### ImportedFunctions
{{< details "Expand" >}}* MmUnmapIoSpace
* MmMapIoSpace
* IofCompleteRequest
* IoDeleteDevice
* IoCreateDevice
* KeBugCheckEx
* RtlInitUnicodeString
* IoCreateSymbolicLink
* IoDeleteSymbolicLink
* __C_specific_handler
* HalSetBusDataByOffset
* HalGetBusDataByOffset
{{< /details >}}
#### ExportedFunctions
{{< details "Expand" >}}{{< /details >}}
| Filename | NTIOLib.sys |
|:---- | ---- | 
| MD5 | <a href="https://www.virustotal.com/gui/file/68dde686d6999ad2e5d182b20403240b">68dde686d6999ad2e5d182b20403240b</a> |
| SHA1 | <a href="https://www.virustotal.com/gui/file/01a578a3a39697c4de8e3dab04dba55a4c35163e">01a578a3a39697c4de8e3dab04dba55a4c35163e</a> |
| SHA256 | <a href="https://www.virustotal.com/gui/file/591bd5e92dfa0117b3daa29750e73e2db25baa717c31217539d30ffb1f7f3a52">591bd5e92dfa0117b3daa29750e73e2db25baa717c31217539d30ffb1f7f3a52</a> |
| Authentihash MD5 | <a href="https://www.virustotal.com/gui/search/authentihash%253A3b7d9b57810ca80137223615a97635e0">3b7d9b57810ca80137223615a97635e0</a> || Authentihash SHA1 | <a href="https://www.virustotal.com/gui/search/authentihash%253A8d9f65a6a9048ec91dd010216071c4ec983887c7">8d9f65a6a9048ec91dd010216071c4ec983887c7</a> || Authentihash SHA256 | <a href="https://www.virustotal.com/gui/search/authentihash%253A4e92baa37cd8b665ca0851f8442766aaf3b96fa61ea137d5972d5eb059389a05">4e92baa37cd8b665ca0851f8442766aaf3b96fa61ea137d5972d5eb059389a05</a> || Signature | MICRO-STAR INTERNATIONAL CO., LTD., GlobalSign CodeSigning CA - G2, GlobalSign Root CA - R1   || Company | MSI || Description | NTIOLib For MSIRatio_CC || Product | NTIOLib || OriginalFilename | NTIOLib.sys |
#### Imports
{{< details "Expand" >}}* ntoskrnl.exe
* HAL.dll
{{< /details >}}
#### ImportedFunctions
{{< details "Expand" >}}* MmUnmapIoSpace
* MmMapIoSpace
* IofCompleteRequest
* IoDeleteDevice
* IoCreateDevice
* KeBugCheckEx
* RtlInitUnicodeString
* IoCreateSymbolicLink
* IoDeleteSymbolicLink
* __C_specific_handler
* HalSetBusDataByOffset
* HalGetBusDataByOffset
{{< /details >}}
#### ExportedFunctions
{{< details "Expand" >}}{{< /details >}}
| Filename | NTIOLib.sys |
|:---- | ---- | 
| MD5 | <a href="https://www.virustotal.com/gui/file/34069a15ae3aa0e879cd0d81708e4bcc">34069a15ae3aa0e879cd0d81708e4bcc</a> |
| SHA1 | <a href="https://www.virustotal.com/gui/file/14bf0eaa90e012169745b3e30c281a327751e316">14bf0eaa90e012169745b3e30c281a327751e316</a> |
| SHA256 | <a href="https://www.virustotal.com/gui/file/5d530e111400785d183057113d70623e17af32931668ab7c7fc826f0fd4f91a3">5d530e111400785d183057113d70623e17af32931668ab7c7fc826f0fd4f91a3</a> |
| Authentihash MD5 | <a href="https://www.virustotal.com/gui/search/authentihash%253A066bcfa3fdd0925385faf92debce887c">066bcfa3fdd0925385faf92debce887c</a> || Authentihash SHA1 | <a href="https://www.virustotal.com/gui/search/authentihash%253Aa2948b9d2e2ee9f4929b39acad6c850ea70dd34c">a2948b9d2e2ee9f4929b39acad6c850ea70dd34c</a> || Authentihash SHA256 | <a href="https://www.virustotal.com/gui/search/authentihash%253A7fa5c326b294f4fc537207a27947c2fcbbfa4eabde1ba4727c92cd8613e0fc7f">7fa5c326b294f4fc537207a27947c2fcbbfa4eabde1ba4727c92cd8613e0fc7f</a> || Signature | MICRO-STAR INTERNATIONAL CO., GlobalSign CodeSigning CA - G2, GlobalSign   || Company | MSI || Description | NTIOLib_X64 || Product | NTIOLib_X64 || OriginalFilename | NTIOLib_X64.sys |
#### Imports
{{< details "Expand" >}}* ntoskrnl.exe
* HAL.dll
{{< /details >}}
#### ImportedFunctions
{{< details "Expand" >}}* MmUnmapIoSpace
* MmMapIoSpace
* IofCompleteRequest
* IoDeleteDevice
* IoCreateDevice
* KeBugCheckEx
* RtlInitUnicodeString
* IoCreateSymbolicLink
* IoDeleteSymbolicLink
* __C_specific_handler
* HalSetBusDataByOffset
* HalGetBusDataByOffset
{{< /details >}}
#### ExportedFunctions
{{< details "Expand" >}}{{< /details >}}
| Filename | NTIOLib.sys |
|:---- | ---- | 
| MD5 | <a href="https://www.virustotal.com/gui/file/3f39f013168428c8e505a7b9e6cba8a2">3f39f013168428c8e505a7b9e6cba8a2</a> |
| SHA1 | <a href="https://www.virustotal.com/gui/file/f50c6b84dfb8f2d53ba3bce000a55f0a486c0e79">f50c6b84dfb8f2d53ba3bce000a55f0a486c0e79</a> |
| SHA256 | <a href="https://www.virustotal.com/gui/file/6f1ff29e2e710f6d064dc74e8e011331d807c32cc2a622cbe507fd4b4d43f8f4">6f1ff29e2e710f6d064dc74e8e011331d807c32cc2a622cbe507fd4b4d43f8f4</a> |
| Authentihash MD5 | <a href="https://www.virustotal.com/gui/search/authentihash%253A7c60ced61bb34cad2982f5ddb1306754">7c60ced61bb34cad2982f5ddb1306754</a> || Authentihash SHA1 | <a href="https://www.virustotal.com/gui/search/authentihash%253Ad02d19abf19569df72ea2c5071330de3d57e0982">d02d19abf19569df72ea2c5071330de3d57e0982</a> || Authentihash SHA256 | <a href="https://www.virustotal.com/gui/search/authentihash%253Afa861c61102cbcaa1e5f6020deaa066c4fcdfaee3ded1ee156ab81d59ad54f9a">fa861c61102cbcaa1e5f6020deaa066c4fcdfaee3ded1ee156ab81d59ad54f9a</a> || Signature | Micro-Star Int&#39;l Co. Ltd., GlobalSign ObjectSign CA, GlobalSign Primary Object Publishing CA, GlobalSign Root CA - R1   || Company | MSI || Description | NTIOLib || Product | NTIOLib || OriginalFilename | NTIOLib.sys |
#### Imports
{{< details "Expand" >}}* ntoskrnl.exe
* HAL.dll
{{< /details >}}
#### ImportedFunctions
{{< details "Expand" >}}* MmUnmapIoSpace
* MmMapIoSpace
* IofCompleteRequest
* IoDeleteDevice
* IoCreateDevice
* KeBugCheckEx
* RtlInitUnicodeString
* IoCreateSymbolicLink
* IoDeleteSymbolicLink
* __C_specific_handler
* HalSetBusDataByOffset
* HalGetBusDataByOffset
{{< /details >}}
#### ExportedFunctions
{{< details "Expand" >}}{{< /details >}}
| Filename | NTIOLib.sys |
|:---- | ---- | 
| MD5 | <a href="https://www.virustotal.com/gui/file/1ed043249c21ab201edccb37f1d40af9">1ed043249c21ab201edccb37f1d40af9</a> |
| SHA1 | <a href="https://www.virustotal.com/gui/file/6100eb82a25d64a7a7702e94c2b21333bc15bd08">6100eb82a25d64a7a7702e94c2b21333bc15bd08</a> |
| SHA256 | <a href="https://www.virustotal.com/gui/file/79e2d37632c417138970b4feba91b7e10c2ea251c5efe3d1fc6fa0190f176b57">79e2d37632c417138970b4feba91b7e10c2ea251c5efe3d1fc6fa0190f176b57</a> |
| Authentihash MD5 | <a href="https://www.virustotal.com/gui/search/authentihash%253Aef516589154145d31284df600c9ad58b">ef516589154145d31284df600c9ad58b</a> || Authentihash SHA1 | <a href="https://www.virustotal.com/gui/search/authentihash%253Adbed3d7755df2c30d7e445529ed2bbe60ce9ee2d">dbed3d7755df2c30d7e445529ed2bbe60ce9ee2d</a> || Authentihash SHA256 | <a href="https://www.virustotal.com/gui/search/authentihash%253A6bed7f1304c6785a06064b04e0e3cb55384588f18ea2fc348a6fcd5784f47558">6bed7f1304c6785a06064b04e0e3cb55384588f18ea2fc348a6fcd5784f47558</a> || Signature | Micro-Star Int&#39;l Co. Ltd., GlobalSign ObjectSign CA, GlobalSign Primary Object Publishing CA, GlobalSign Root CA - R1   || Company | MSI || Description | NTIOLib || Product | NTIOLib || OriginalFilename | NTIOLib.sys |
#### Imports
{{< details "Expand" >}}* ntoskrnl.exe
* HAL.dll
{{< /details >}}
#### ImportedFunctions
{{< details "Expand" >}}* MmUnmapIoSpace
* MmMapIoSpace
* IofCompleteRequest
* IoDeleteDevice
* IoCreateDevice
* KeBugCheckEx
* RtlInitUnicodeString
* IoCreateSymbolicLink
* IoDeleteSymbolicLink
* __C_specific_handler
* HalSetBusDataByOffset
* HalGetBusDataByOffset
{{< /details >}}
#### ExportedFunctions
{{< details "Expand" >}}{{< /details >}}
| Filename | NTIOLib.sys |
|:---- | ---- | 
| MD5 | <a href="https://www.virustotal.com/gui/file/96b463b6fa426ae42c414177af550ba2">96b463b6fa426ae42c414177af550ba2</a> |
| SHA1 | <a href="https://www.virustotal.com/gui/file/bf87e32a651bdfd9b9244a8cf24fca0e459eb614">bf87e32a651bdfd9b9244a8cf24fca0e459eb614</a> |
| SHA256 | <a href="https://www.virustotal.com/gui/file/85866e8c25d82c1ec91d7a8076c7d073cccf421cf57d9c83d80d63943a4edd94">85866e8c25d82c1ec91d7a8076c7d073cccf421cf57d9c83d80d63943a4edd94</a> |
| Authentihash MD5 | <a href="https://www.virustotal.com/gui/search/authentihash%253A133e1582c5d14c52ac3590c9d2ada850">133e1582c5d14c52ac3590c9d2ada850</a> || Authentihash SHA1 | <a href="https://www.virustotal.com/gui/search/authentihash%253Aa22e6b855062f1154ae8f244e2652e04b4ea5b4c">a22e6b855062f1154ae8f244e2652e04b4ea5b4c</a> || Authentihash SHA256 | <a href="https://www.virustotal.com/gui/search/authentihash%253A5a63937a6320f50c4782d0675104932907d16a91d89088ac979a7a0129aad986">5a63937a6320f50c4782d0675104932907d16a91d89088ac979a7a0129aad986</a> || Signature | MICRO-STAR INTERNATIONAL CO., LTD., GlobalSign CodeSigning CA - G2, GlobalSign Root CA - R1   || Company | MSI || Description | NTIOLib || Product | NTIOLib || OriginalFilename | NTIOLib.sys |
#### Imports
{{< details "Expand" >}}* ntoskrnl.exe
* HAL.dll
{{< /details >}}
#### ImportedFunctions
{{< details "Expand" >}}* MmUnmapIoSpace
* MmMapIoSpace
* IofCompleteRequest
* IoDeleteDevice
* IoCreateDevice
* KeBugCheckEx
* RtlInitUnicodeString
* IoCreateSymbolicLink
* IoDeleteSymbolicLink
* __C_specific_handler
* HalSetBusDataByOffset
* HalGetBusDataByOffset
{{< /details >}}
#### ExportedFunctions
{{< details "Expand" >}}{{< /details >}}
| Filename | NTIOLib.sys |
|:---- | ---- | 
| MD5 | <a href="https://www.virustotal.com/gui/file/0752f113d983030939b4ab98b0812cf0">0752f113d983030939b4ab98b0812cf0</a> |
| SHA1 | <a href="https://www.virustotal.com/gui/file/28b1c0b91eb6afd2d26b239c9f93beb053867a1a">28b1c0b91eb6afd2d26b239c9f93beb053867a1a</a> |
| SHA256 | <a href="https://www.virustotal.com/gui/file/89b0017bc30cc026e32b758c66a1af88bd54c6a78e11ec2908ff854e00ac46be">89b0017bc30cc026e32b758c66a1af88bd54c6a78e11ec2908ff854e00ac46be</a> |
| Authentihash MD5 | <a href="https://www.virustotal.com/gui/search/authentihash%253A761bee6879171d50932f73cfa9c718e0">761bee6879171d50932f73cfa9c718e0</a> || Authentihash SHA1 | <a href="https://www.virustotal.com/gui/search/authentihash%253A33b2e3af695f0febd39d02d8f931e92ad88461f4">33b2e3af695f0febd39d02d8f931e92ad88461f4</a> || Authentihash SHA256 | <a href="https://www.virustotal.com/gui/search/authentihash%253Ae951858d5317724c015eef07d402e8bcb33cf1a7c2ccf7a75cea63e3430d16a2">e951858d5317724c015eef07d402e8bcb33cf1a7c2ccf7a75cea63e3430d16a2</a> || Signature | Micro-Star Int&#39;l Co. Ltd., GlobalSign ObjectSign CA, GlobalSign Primary Object Publishing CA, GlobalSign Root CA - R1   || Company | MSI || Description | NTIOLib || Product | NTIOLib || OriginalFilename | NTIOLib.sys |
#### Imports
{{< details "Expand" >}}* ntoskrnl.exe
* HAL.dll
{{< /details >}}
#### ImportedFunctions
{{< details "Expand" >}}* MmUnmapIoSpace
* MmMapIoSpace
* IofCompleteRequest
* IoDeleteDevice
* IoCreateDevice
* KeBugCheckEx
* RtlInitUnicodeString
* IoCreateSymbolicLink
* IoDeleteSymbolicLink
* __C_specific_handler
* HalSetBusDataByOffset
* HalGetBusDataByOffset
{{< /details >}}
#### ExportedFunctions
{{< details "Expand" >}}{{< /details >}}
| Filename | NTIOLib.sys |
|:---- | ---- | 
| MD5 | <a href="https://www.virustotal.com/gui/file/6cce5bb9c8c2a8293df2d3b1897941a2">6cce5bb9c8c2a8293df2d3b1897941a2</a> |
| SHA1 | <a href="https://www.virustotal.com/gui/file/879fcc6795cebe67718388228e715c470de87dca">879fcc6795cebe67718388228e715c470de87dca</a> |
| SHA256 | <a href="https://www.virustotal.com/gui/file/9254f012009d55f555418ff85f7d93b184ab7cb0e37aecdfdab62cfe94dea96b">9254f012009d55f555418ff85f7d93b184ab7cb0e37aecdfdab62cfe94dea96b</a> |
| Authentihash MD5 | <a href="https://www.virustotal.com/gui/search/authentihash%253A63ea2f5ce789857efaf657ae86d029c5">63ea2f5ce789857efaf657ae86d029c5</a> || Authentihash SHA1 | <a href="https://www.virustotal.com/gui/search/authentihash%253A33286e984b12811b38b2ad3396451388e2f24424">33286e984b12811b38b2ad3396451388e2f24424</a> || Authentihash SHA256 | <a href="https://www.virustotal.com/gui/search/authentihash%253A98f5cb928827e8dadc79c1be4f27f67755dbeb802c3485af9cace78b9eb65c59">98f5cb928827e8dadc79c1be4f27f67755dbeb802c3485af9cace78b9eb65c59</a> || Signature | MICRO-STAR INTERNATIONAL CO., LTD., GlobalSign CodeSigning CA - G2, GlobalSign Root CA - R1   || Company | MSI || Description | NTIOLib for MSIDDR_CC || Product | NTIOLib || OriginalFilename | NTIOLib.sys |
#### Imports
{{< details "Expand" >}}* ntoskrnl.exe
* HAL.dll
{{< /details >}}
#### ImportedFunctions
{{< details "Expand" >}}* MmUnmapIoSpace
* MmMapIoSpace
* IofCompleteRequest
* IoDeleteDevice
* IoCreateDevice
* KeBugCheckEx
* RtlInitUnicodeString
* IoCreateSymbolicLink
* IoDeleteSymbolicLink
* __C_specific_handler
* HalSetBusDataByOffset
* HalGetBusDataByOffset
{{< /details >}}
#### ExportedFunctions
{{< details "Expand" >}}{{< /details >}}
| Filename | NTIOLib.sys |
|:---- | ---- | 
| MD5 | <a href="https://www.virustotal.com/gui/file/64efbffaa153b0d53dc1bccda4279299">64efbffaa153b0d53dc1bccda4279299</a> |
| SHA1 | <a href="https://www.virustotal.com/gui/file/15df139494d2c40a645fb010908551185c27f3c5">15df139494d2c40a645fb010908551185c27f3c5</a> |
| SHA256 | <a href="https://www.virustotal.com/gui/file/9529efb1837b1005e5e8f477773752078e0a46500c748bc30c9b5084d04082e6">9529efb1837b1005e5e8f477773752078e0a46500c748bc30c9b5084d04082e6</a> |
| Authentihash MD5 | <a href="https://www.virustotal.com/gui/search/authentihash%253Ac6788d75093368b6dc2bc373df4591b8">c6788d75093368b6dc2bc373df4591b8</a> || Authentihash SHA1 | <a href="https://www.virustotal.com/gui/search/authentihash%253Aa3799e1aa983ad65de762a430f3286eefeff61e0">a3799e1aa983ad65de762a430f3286eefeff61e0</a> || Authentihash SHA256 | <a href="https://www.virustotal.com/gui/search/authentihash%253A1ef80a6b63766ca36e2f2a7d29c49dc5859a58604bd8fde15011d8c379f76e01">1ef80a6b63766ca36e2f2a7d29c49dc5859a58604bd8fde15011d8c379f76e01</a> || Signature | MICRO-STAR INTERNATIONAL CO., LTD., GlobalSign CodeSigning CA - G2, GlobalSign Root CA - R1   || Company | MSI || Description | NTIOLib || Product | NTIOLib || OriginalFilename | NTIOLib.sys |
#### Imports
{{< details "Expand" >}}* ntoskrnl.exe
* HAL.dll
{{< /details >}}
#### ImportedFunctions
{{< details "Expand" >}}* MmUnmapIoSpace
* MmMapIoSpace
* IofCompleteRequest
* IoDeleteDevice
* IoCreateDevice
* KeBugCheckEx
* RtlInitUnicodeString
* IoCreateSymbolicLink
* IoDeleteSymbolicLink
* __C_specific_handler
* HalSetBusDataByOffset
* HalGetBusDataByOffset
{{< /details >}}
#### ExportedFunctions
{{< details "Expand" >}}{{< /details >}}
| Filename | NTIOLib.sys |
|:---- | ---- | 
| MD5 | <a href="https://www.virustotal.com/gui/file/2da209dde8188076a9579bd256dc90d0">2da209dde8188076a9579bd256dc90d0</a> |
| SHA1 | <a href="https://www.virustotal.com/gui/file/1f7501e01d84a2297c85cb39880ec4e40ac3fe8a">1f7501e01d84a2297c85cb39880ec4e40ac3fe8a</a> |
| SHA256 | <a href="https://www.virustotal.com/gui/file/984a77e5424c6d099051441005f2938ae92b31b5ad8f6521c6b001932862add7">984a77e5424c6d099051441005f2938ae92b31b5ad8f6521c6b001932862add7</a> |
| Authentihash MD5 | <a href="https://www.virustotal.com/gui/search/authentihash%253A5e4c54660e02b951d67e54ce3c16dcc9">5e4c54660e02b951d67e54ce3c16dcc9</a> || Authentihash SHA1 | <a href="https://www.virustotal.com/gui/search/authentihash%253A14e798609095df77d135dd2afae8277e0a968d99">14e798609095df77d135dd2afae8277e0a968d99</a> || Authentihash SHA256 | <a href="https://www.virustotal.com/gui/search/authentihash%253A5eb233ed9df3c1def326e2c63ee304dc85af303f8c9f038c993aa6e34f91ffaf">5eb233ed9df3c1def326e2c63ee304dc85af303f8c9f038c993aa6e34f91ffaf</a> || Signature | MICRO-STAR INTERNATIONAL CO., LTD., GlobalSign CodeSigning CA - G2, GlobalSign Root CA - R1   || Company | MSI || Description | NTIOLib || Product | NTIOLib || OriginalFilename | NTIOLib.sys |
#### Imports
{{< details "Expand" >}}* ntoskrnl.exe
* HAL.dll
{{< /details >}}
#### ImportedFunctions
{{< details "Expand" >}}* MmUnmapIoSpace
* MmMapIoSpace
* IofCompleteRequest
* IoDeleteDevice
* IoCreateDevice
* KeBugCheckEx
* RtlInitUnicodeString
* IoCreateSymbolicLink
* IoDeleteSymbolicLink
* __C_specific_handler
* HalSetBusDataByOffset
* HalGetBusDataByOffset
{{< /details >}}
#### ExportedFunctions
{{< details "Expand" >}}{{< /details >}}
| Filename | NTIOLib.sys |
|:---- | ---- | 
| MD5 | <a href="https://www.virustotal.com/gui/file/84ba7af6ada1b3ea5efb9871a0613fc6">84ba7af6ada1b3ea5efb9871a0613fc6</a> |
| SHA1 | <a href="https://www.virustotal.com/gui/file/152b6bb9ffd2ffec00cc46f5c6e29362d0e66e67">152b6bb9ffd2ffec00cc46f5c6e29362d0e66e67</a> |
| SHA256 | <a href="https://www.virustotal.com/gui/file/98b734dda78c16ebcaa4afeb31007926542b63b2f163b2f733fa0d00dbb344d8">98b734dda78c16ebcaa4afeb31007926542b63b2f163b2f733fa0d00dbb344d8</a> |
| Authentihash MD5 | <a href="https://www.virustotal.com/gui/search/authentihash%253Ae2fde714a590d75cec614058707ac9d7">e2fde714a590d75cec614058707ac9d7</a> || Authentihash SHA1 | <a href="https://www.virustotal.com/gui/search/authentihash%253A450a92b5d604ad2c7d848ab96dc1c0455c7d1f92">450a92b5d604ad2c7d848ab96dc1c0455c7d1f92</a> || Authentihash SHA256 | <a href="https://www.virustotal.com/gui/search/authentihash%253A5dfb950d4771c35f4f82626b5d8859cce74bf03db67f2be3036631894a62eca8">5dfb950d4771c35f4f82626b5d8859cce74bf03db67f2be3036631894a62eca8</a> || Signature | MICRO-STAR INTERNATIONAL CO., GlobalSign CodeSigning CA - G2, GlobalSign   || Company | MSI || Description | NTIOLib for DebugLED || Product | NTIOLib || OriginalFilename | NTIOLib.sys |
#### Imports
{{< details "Expand" >}}* ntoskrnl.exe
* HAL.dll
{{< /details >}}
#### ImportedFunctions
{{< details "Expand" >}}* MmUnmapIoSpace
* MmMapIoSpace
* IofCompleteRequest
* IoDeleteDevice
* IoCreateDevice
* KeBugCheckEx
* RtlInitUnicodeString
* IoCreateSymbolicLink
* IoDeleteSymbolicLink
* __C_specific_handler
* HalSetBusDataByOffset
* HalGetBusDataByOffset
{{< /details >}}
#### ExportedFunctions
{{< details "Expand" >}}{{< /details >}}
| Filename | NTIOLib.sys |
|:---- | ---- | 
| MD5 | <a href="https://www.virustotal.com/gui/file/1b32c54b95121ab1683c7b83b2db4b96">1b32c54b95121ab1683c7b83b2db4b96</a> |
| SHA1 | <a href="https://www.virustotal.com/gui/file/5f8356ffa8201f338dd2ea979eb47881a6db9f03">5f8356ffa8201f338dd2ea979eb47881a6db9f03</a> |
| SHA256 | <a href="https://www.virustotal.com/gui/file/99f4994a0e5bd1bf6e3f637d3225c69ff4cd620557e23637533e7f18d7d6cba1">99f4994a0e5bd1bf6e3f637d3225c69ff4cd620557e23637533e7f18d7d6cba1</a> |
| Authentihash MD5 | <a href="https://www.virustotal.com/gui/search/authentihash%253Ab36ce3dc6e3ca0e76c9f9a7d4d331524">b36ce3dc6e3ca0e76c9f9a7d4d331524</a> || Authentihash SHA1 | <a href="https://www.virustotal.com/gui/search/authentihash%253A0b68901f632deadc3f0691febe7d0dacb8a2d4d8">0b68901f632deadc3f0691febe7d0dacb8a2d4d8</a> || Authentihash SHA256 | <a href="https://www.virustotal.com/gui/search/authentihash%253Abb4e3aa888a779238b210d6406aa480f01d27ea28d20699b1ec29a59dae19913">bb4e3aa888a779238b210d6406aa480f01d27ea28d20699b1ec29a59dae19913</a> || Signature | Micro-Star Int&#39;l Co. Ltd., GlobalSign ObjectSign CA, GlobalSign Primary Object Publishing CA, GlobalSign Root CA - R1   || Company | MSI || Description | NTIOLib || Product | NTIOLib || OriginalFilename | NTIOLib.sys |
#### Imports
{{< details "Expand" >}}* ntoskrnl.exe
* HAL.dll
{{< /details >}}
#### ImportedFunctions
{{< details "Expand" >}}* MmUnmapIoSpace
* MmMapIoSpace
* IofCompleteRequest
* IoDeleteDevice
* IoCreateDevice
* KeBugCheckEx
* RtlInitUnicodeString
* IoCreateSymbolicLink
* IoDeleteSymbolicLink
* __C_specific_handler
* HalSetBusDataByOffset
* HalGetBusDataByOffset
{{< /details >}}
#### ExportedFunctions
{{< details "Expand" >}}{{< /details >}}
| Filename | NTIOLib.sys |
|:---- | ---- | 
| MD5 | <a href="https://www.virustotal.com/gui/file/b0baac4d6cbac384a633c71858b35a2e">b0baac4d6cbac384a633c71858b35a2e</a> |
| SHA1 | <a href="https://www.virustotal.com/gui/file/a7bd05de737f8ea57857f1e0845a25677df01872">a7bd05de737f8ea57857f1e0845a25677df01872</a> |
| SHA256 | <a href="https://www.virustotal.com/gui/file/9c10e2ec4f9ef591415f9a784b93dc9c9cdafa7c69602c0dc860c5b62222e449">9c10e2ec4f9ef591415f9a784b93dc9c9cdafa7c69602c0dc860c5b62222e449</a> |
| Authentihash MD5 | <a href="https://www.virustotal.com/gui/search/authentihash%253A498e18a0df3d49779e5d50e2ce1e8385">498e18a0df3d49779e5d50e2ce1e8385</a> || Authentihash SHA1 | <a href="https://www.virustotal.com/gui/search/authentihash%253Acb7ed29416920b38a00695d11751ca6766a7b5f9">cb7ed29416920b38a00695d11751ca6766a7b5f9</a> || Authentihash SHA256 | <a href="https://www.virustotal.com/gui/search/authentihash%253A48ac8ae911c490e1b7f7813c0f345677e110ffaa9ef385b86ca25e5519e2c0de">48ac8ae911c490e1b7f7813c0f345677e110ffaa9ef385b86ca25e5519e2c0de</a> || Signature | Micro-Star Int&#39;l Co. Ltd., GlobalSign ObjectSign CA, GlobalSign Primary Object Publishing CA, GlobalSign   || Company | MSI || Description | NTIOLib || Product | NTIOLib || OriginalFilename | NTIOLib.sys |
#### Imports
{{< details "Expand" >}}* ntoskrnl.exe
* HAL.dll
{{< /details >}}
#### ImportedFunctions
{{< details "Expand" >}}* MmUnmapIoSpace
* MmMapIoSpace
* IofCompleteRequest
* IoDeleteDevice
* IoCreateDevice
* KeBugCheckEx
* RtlInitUnicodeString
* IoCreateSymbolicLink
* IoDeleteSymbolicLink
* __C_specific_handler
* HalSetBusDataByOffset
* HalGetBusDataByOffset
{{< /details >}}
#### ExportedFunctions
{{< details "Expand" >}}{{< /details >}}
| Filename | NTIOLib.sys |
|:---- | ---- | 
| MD5 | <a href="https://www.virustotal.com/gui/file/b89b097b8b8aecb8341d05136f334ebb">b89b097b8b8aecb8341d05136f334ebb</a> |
| SHA1 | <a href="https://www.virustotal.com/gui/file/cce9b82f01ec68f450f5fe4312f40d929c6a506e">cce9b82f01ec68f450f5fe4312f40d929c6a506e</a> |
| SHA256 | <a href="https://www.virustotal.com/gui/file/a961f5939088238d76757669a9a81905e33f247c9c635b908daac146ae063499">a961f5939088238d76757669a9a81905e33f247c9c635b908daac146ae063499</a> |
| Authentihash MD5 | <a href="https://www.virustotal.com/gui/search/authentihash%253Ab70f71ebef5d45dcf99098beb0f72951">b70f71ebef5d45dcf99098beb0f72951</a> || Authentihash SHA1 | <a href="https://www.virustotal.com/gui/search/authentihash%253A049b1cd656849214bd5c864c79e3b27be6b46b34">049b1cd656849214bd5c864c79e3b27be6b46b34</a> || Authentihash SHA256 | <a href="https://www.virustotal.com/gui/search/authentihash%253Ac1795ec9d05d0efe56e76bf4b76a09a804d3cd5b0e75bc47049d5ee488fc2bec">c1795ec9d05d0efe56e76bf4b76a09a804d3cd5b0e75bc47049d5ee488fc2bec</a> || Signature | Micro-Star Int&#39;l Co. Ltd., GlobalSign ObjectSign CA, GlobalSign Primary Object Publishing CA, GlobalSign Root CA - R1   || Company | MSI || Description | NTIOLib || Product | NTIOLib || OriginalFilename | NTIOLib.sys |
#### Imports
{{< details "Expand" >}}* ntoskrnl.exe
* HAL.dll
{{< /details >}}
#### ImportedFunctions
{{< details "Expand" >}}* MmUnmapIoSpace
* MmMapIoSpace
* IofCompleteRequest
* IoDeleteDevice
* IoCreateDevice
* KeBugCheckEx
* RtlInitUnicodeString
* IoCreateSymbolicLink
* IoDeleteSymbolicLink
* __C_specific_handler
* HalSetBusDataByOffset
* HalGetBusDataByOffset
{{< /details >}}
#### ExportedFunctions
{{< details "Expand" >}}{{< /details >}}
| Filename | NTIOLib.sys |
|:---- | ---- | 
| MD5 | <a href="https://www.virustotal.com/gui/file/a711e6ab17802fabf2e69e0cd57c54cd">a711e6ab17802fabf2e69e0cd57c54cd</a> |
| SHA1 | <a href="https://www.virustotal.com/gui/file/e35a2b009d54e1a0b231d8a276251f64231b66a3">e35a2b009d54e1a0b231d8a276251f64231b66a3</a> |
| SHA256 | <a href="https://www.virustotal.com/gui/file/a9706e320179993dade519a83061477ace195daa1b788662825484813001f526">a9706e320179993dade519a83061477ace195daa1b788662825484813001f526</a> |
| Authentihash MD5 | <a href="https://www.virustotal.com/gui/search/authentihash%253Aec3966c4b4ec6fc15ff0940548fd10c2">ec3966c4b4ec6fc15ff0940548fd10c2</a> || Authentihash SHA1 | <a href="https://www.virustotal.com/gui/search/authentihash%253A531a782723ecc50ea4fcfbbfe4b94465782a21d0">531a782723ecc50ea4fcfbbfe4b94465782a21d0</a> || Authentihash SHA256 | <a href="https://www.virustotal.com/gui/search/authentihash%253Aeae8045d43f16e33232fd8bd2399f48b14f8a6391c9fffe38960c03fee978b27">eae8045d43f16e33232fd8bd2399f48b14f8a6391c9fffe38960c03fee978b27</a> || Signature | MICRO-STAR INTERNATIONAL CO., LTD., GlobalSign CodeSigning CA - G2, GlobalSign Root CA - R1   || Company | MSI || Description | NTIOLib || Product | NTIOLib || OriginalFilename | NTIOLib.sys |
#### Imports
{{< details "Expand" >}}* ntoskrnl.exe
* HAL.dll
{{< /details >}}
#### ImportedFunctions
{{< details "Expand" >}}* MmUnmapIoSpace
* MmMapIoSpace
* IofCompleteRequest
* IoDeleteDevice
* IoCreateDevice
* KeBugCheckEx
* RtlInitUnicodeString
* IoCreateSymbolicLink
* IoDeleteSymbolicLink
* __C_specific_handler
* HalSetBusDataByOffset
* HalGetBusDataByOffset
{{< /details >}}
#### ExportedFunctions
{{< details "Expand" >}}{{< /details >}}
| Filename | NTIOLib.sys |
|:---- | ---- | 
| MD5 | <a href="https://www.virustotal.com/gui/file/490b1f404c4f31f4538b36736c990136">490b1f404c4f31f4538b36736c990136</a> |
| SHA1 | <a href="https://www.virustotal.com/gui/file/37364cb5f5cefd68e5eca56f95c0ab4aff43afcc">37364cb5f5cefd68e5eca56f95c0ab4aff43afcc</a> |
| SHA256 | <a href="https://www.virustotal.com/gui/file/b7a20b5f15e1871b392782c46ebcc897929443d82073ee4dcb3874b6a5976b5d">b7a20b5f15e1871b392782c46ebcc897929443d82073ee4dcb3874b6a5976b5d</a> |
| Authentihash MD5 | <a href="https://www.virustotal.com/gui/search/authentihash%253A364af1be1135ce8bede31bb6c201f7bb">364af1be1135ce8bede31bb6c201f7bb</a> || Authentihash SHA1 | <a href="https://www.virustotal.com/gui/search/authentihash%253A3d0c8e9e7fcd431a91d4c4ea088d94fa371d546b">3d0c8e9e7fcd431a91d4c4ea088d94fa371d546b</a> || Authentihash SHA256 | <a href="https://www.virustotal.com/gui/search/authentihash%253Ac1c18591d7b68fafa870f3d0f1124a353682765236674cc7476c5f1cc71b1528">c1c18591d7b68fafa870f3d0f1124a353682765236674cc7476c5f1cc71b1528</a> || Signature | Micro-Star Int&#39;l Co. Ltd., GlobalSign ObjectSign CA, GlobalSign Primary Object Publishing CA, GlobalSign   || Company | MSI || Description | NTIOLib || Product | NTIOLib || OriginalFilename | NTIOLib.sys |
#### Imports
{{< details "Expand" >}}* ntoskrnl.exe
* HAL.dll
{{< /details >}}
#### ImportedFunctions
{{< details "Expand" >}}* MmUnmapIoSpace
* MmMapIoSpace
* IofCompleteRequest
* IoDeleteDevice
* IoCreateDevice
* KeBugCheckEx
* RtlInitUnicodeString
* IoCreateSymbolicLink
* IoDeleteSymbolicLink
* __C_specific_handler
* HalSetBusDataByOffset
* HalGetBusDataByOffset
{{< /details >}}
#### ExportedFunctions
{{< details "Expand" >}}{{< /details >}}
| Filename | NTIOLib.sys |
|:---- | ---- | 
| MD5 | <a href="https://www.virustotal.com/gui/file/6f5d54ab483659ac78672440422ae3f1">6f5d54ab483659ac78672440422ae3f1</a> |
| SHA1 | <a href="https://www.virustotal.com/gui/file/d62fa51e520022483bdc5847141658de689c0c29">d62fa51e520022483bdc5847141658de689c0c29</a> |
| SHA256 | <a href="https://www.virustotal.com/gui/file/cc586254e9e89e88334adee44e332166119307e79c2f18f6c2ab90ce8ba7fc9b">cc586254e9e89e88334adee44e332166119307e79c2f18f6c2ab90ce8ba7fc9b</a> |
| Authentihash MD5 | <a href="https://www.virustotal.com/gui/search/authentihash%253Ac7069e41aab11ec8cb06657e6e8babd0">c7069e41aab11ec8cb06657e6e8babd0</a> || Authentihash SHA1 | <a href="https://www.virustotal.com/gui/search/authentihash%253A156907d0ca2ecff7efa07f479622b018af74bf2f">156907d0ca2ecff7efa07f479622b018af74bf2f</a> || Authentihash SHA256 | <a href="https://www.virustotal.com/gui/search/authentihash%253A9c513f4d4c38a10af9f4a967bb6c7901275adf0df8046fc7e1b7e4c3e3c7c3cf">9c513f4d4c38a10af9f4a967bb6c7901275adf0df8046fc7e1b7e4c3e3c7c3cf</a> || Signature | MICRO-STAR INTERNATIONAL CO., LTD., GlobalSign CodeSigning CA - G2, GlobalSign Root CA - R1   || Company | MSI || Description | NTIOLib || Product | NTIOLib || OriginalFilename | NTIOLib_X64.sys |
#### Imports
{{< details "Expand" >}}* ntoskrnl.exe
* HAL.dll
{{< /details >}}
#### ImportedFunctions
{{< details "Expand" >}}* MmUnmapIoSpace
* MmMapIoSpace
* IofCompleteRequest
* IoDeleteDevice
* IoCreateDevice
* KeBugCheckEx
* RtlInitUnicodeString
* IoCreateSymbolicLink
* IoDeleteSymbolicLink
* __C_specific_handler
* HalSetBusDataByOffset
* HalGetBusDataByOffset
{{< /details >}}
#### ExportedFunctions
{{< details "Expand" >}}{{< /details >}}
| Filename | NTIOLib.sys |
|:---- | ---- | 
| MD5 | <a href="https://www.virustotal.com/gui/file/dd04cd3de0c19bede84e9c95a86b3ca8">dd04cd3de0c19bede84e9c95a86b3ca8</a> |
| SHA1 | <a href="https://www.virustotal.com/gui/file/93aa3bb934b74160446df3a47fa085fd7f3a6be9">93aa3bb934b74160446df3a47fa085fd7f3a6be9</a> |
| SHA256 | <a href="https://www.virustotal.com/gui/file/cd4a249c3ef65af285d0f8f30a8a96e83688486aab515836318a2559757a89bb">cd4a249c3ef65af285d0f8f30a8a96e83688486aab515836318a2559757a89bb</a> |
| Authentihash MD5 | <a href="https://www.virustotal.com/gui/search/authentihash%253A55cd6f1f309b3409bf2cb92a4eb56e74">55cd6f1f309b3409bf2cb92a4eb56e74</a> || Authentihash SHA1 | <a href="https://www.virustotal.com/gui/search/authentihash%253Ae7558eaa5e3357ca3010ee219cf52fdf46e5cd5a">e7558eaa5e3357ca3010ee219cf52fdf46e5cd5a</a> || Authentihash SHA256 | <a href="https://www.virustotal.com/gui/search/authentihash%253Aa502c904a7fe42183d3ea66f1e01fbd4321eb202280b054b9124dd333f093ba2">a502c904a7fe42183d3ea66f1e01fbd4321eb202280b054b9124dd333f093ba2</a> || Signature | MICRO-STAR INTERNATIONAL CO., LTD., GlobalSign CodeSigning CA - G2, GlobalSign Root CA - R1   || Company | MSI || Description | NTIOLib || Product | NTIOLib || OriginalFilename | NTIOLib.sys |
#### Imports
{{< details "Expand" >}}* ntoskrnl.exe
* HAL.dll
{{< /details >}}
#### ImportedFunctions
{{< details "Expand" >}}* MmUnmapIoSpace
* MmMapIoSpace
* IofCompleteRequest
* IoDeleteDevice
* IoCreateDevice
* KeBugCheckEx
* RtlInitUnicodeString
* IoCreateSymbolicLink
* IoDeleteSymbolicLink
* __C_specific_handler
* HalSetBusDataByOffset
* HalGetBusDataByOffset
{{< /details >}}
#### ExportedFunctions
{{< details "Expand" >}}{{< /details >}}
| Filename | NTIOLib.sys |
|:---- | ---- | 
| MD5 | <a href="https://www.virustotal.com/gui/file/95e4c7b0384da89dce8ea6f31c3613d9">95e4c7b0384da89dce8ea6f31c3613d9</a> |
| SHA1 | <a href="https://www.virustotal.com/gui/file/ec4cc6de4c779bb1ca1dd32ee3a03f7e8d633a9b">ec4cc6de4c779bb1ca1dd32ee3a03f7e8d633a9b</a> |
| SHA256 | <a href="https://www.virustotal.com/gui/file/cf4b5fa853ce809f1924df3a3ae3c4e191878c4ea5248d8785dc7e51807a512b">cf4b5fa853ce809f1924df3a3ae3c4e191878c4ea5248d8785dc7e51807a512b</a> |
| Authentihash MD5 | <a href="https://www.virustotal.com/gui/search/authentihash%253A0c06dcbb129db21d296df3f6f8e98514">0c06dcbb129db21d296df3f6f8e98514</a> || Authentihash SHA1 | <a href="https://www.virustotal.com/gui/search/authentihash%253Ad3642da8e37cb772b1dd7b75a69323a4a00566c8">d3642da8e37cb772b1dd7b75a69323a4a00566c8</a> || Authentihash SHA256 | <a href="https://www.virustotal.com/gui/search/authentihash%253Ace89124d29b5e562bbcc2f07b1dfac0f22dd66ad3deb32dd32c8c138a3739ef8">ce89124d29b5e562bbcc2f07b1dfac0f22dd66ad3deb32dd32c8c138a3739ef8</a> || Signature | MICRO-STAR INTERNATIONAL CO., LTD., GlobalSign CodeSigning CA - G2, GlobalSign Root CA - R1   || Company | MSI || Description | NTIOLib for MSIClock_CC || Product | NTIOLib || OriginalFilename | NTIOLib.sys |
#### Imports
{{< details "Expand" >}}* ntoskrnl.exe
* HAL.dll
{{< /details >}}
#### ImportedFunctions
{{< details "Expand" >}}* MmUnmapIoSpace
* MmMapIoSpace
* IofCompleteRequest
* IoDeleteDevice
* IoCreateDevice
* KeBugCheckEx
* RtlInitUnicodeString
* IoCreateSymbolicLink
* IoDeleteSymbolicLink
* __C_specific_handler
* HalSetBusDataByOffset
* HalGetBusDataByOffset
{{< /details >}}
#### ExportedFunctions
{{< details "Expand" >}}{{< /details >}}
| Filename | NTIOLib.sys |
|:---- | ---- | 
| MD5 | <a href="https://www.virustotal.com/gui/file/9aa7ed7809eec0d8bc6c545a1d18107a">9aa7ed7809eec0d8bc6c545a1d18107a</a> |
| SHA1 | <a href="https://www.virustotal.com/gui/file/35f1ba60ba0da8512a0b1b15ee8e30fe240d77cd">35f1ba60ba0da8512a0b1b15ee8e30fe240d77cd</a> |
| SHA256 | <a href="https://www.virustotal.com/gui/file/d0bd1ae72aeb5f3eabf1531a635f990e5eaae7fdd560342f915f723766c80889">d0bd1ae72aeb5f3eabf1531a635f990e5eaae7fdd560342f915f723766c80889</a> |
| Authentihash MD5 | <a href="https://www.virustotal.com/gui/search/authentihash%253A37256f56e87f5530dd63e3069a3e3252">37256f56e87f5530dd63e3069a3e3252</a> || Authentihash SHA1 | <a href="https://www.virustotal.com/gui/search/authentihash%253A17f4ab1865a5a2be4768cd25019439441fd0e10b">17f4ab1865a5a2be4768cd25019439441fd0e10b</a> || Authentihash SHA256 | <a href="https://www.virustotal.com/gui/search/authentihash%253A61a3bf24d4e3eac56c380b022dfc195bad4cc8d03156cdc3ba743faab582284a">61a3bf24d4e3eac56c380b022dfc195bad4cc8d03156cdc3ba743faab582284a</a> || Signature | MICRO-STAR INTERNATIONAL CO., LTD., GlobalSign CodeSigning CA - G2, GlobalSign Root CA - R1   || Company | MSI || Description | NTIOLib || Product | NTIOLib || OriginalFilename | NTIOLib.sys |
#### Imports
{{< details "Expand" >}}* ntoskrnl.exe
* HAL.dll
{{< /details >}}
#### ImportedFunctions
{{< details "Expand" >}}* MmUnmapIoSpace
* MmMapIoSpace
* IofCompleteRequest
* IoDeleteDevice
* IoCreateDevice
* KeBugCheckEx
* RtlInitUnicodeString
* IoCreateSymbolicLink
* IoDeleteSymbolicLink
* __C_specific_handler
* HalSetBusDataByOffset
* HalGetBusDataByOffset
{{< /details >}}
#### ExportedFunctions
{{< details "Expand" >}}{{< /details >}}
| Filename | NTIOLib.sys |
|:---- | ---- | 
| MD5 | <a href="https://www.virustotal.com/gui/file/c02f70960fa934b8defa16a03d7f6556">c02f70960fa934b8defa16a03d7f6556</a> |
| SHA1 | <a href="https://www.virustotal.com/gui/file/3805e4e08ad342d224973ecdade8b00c40ed31be">3805e4e08ad342d224973ecdade8b00c40ed31be</a> |
| SHA256 | <a href="https://www.virustotal.com/gui/file/d8b58f6a89a7618558e37afc360cd772b6731e3ba367f8d58734ecee2244a530">d8b58f6a89a7618558e37afc360cd772b6731e3ba367f8d58734ecee2244a530</a> |
| Authentihash MD5 | <a href="https://www.virustotal.com/gui/search/authentihash%253Ac6830e904e56ea951005ea7639eedd35">c6830e904e56ea951005ea7639eedd35</a> || Authentihash SHA1 | <a href="https://www.virustotal.com/gui/search/authentihash%253Ac57c0dd18135bca5fdb094858a70033c006cd281">c57c0dd18135bca5fdb094858a70033c006cd281</a> || Authentihash SHA256 | <a href="https://www.virustotal.com/gui/search/authentihash%253A4a05ad47cd63932b3df2d0f1f42617321729772211bec651fe061140d3e75957">4a05ad47cd63932b3df2d0f1f42617321729772211bec651fe061140d3e75957</a> || Signature | Micro-Star Int&#39;l Co. Ltd., GlobalSign ObjectSign CA, GlobalSign Primary Object Publishing CA, GlobalSign Root CA - R1   || Company | MSI || Description | NTIOLib || Product | NTIOLib || OriginalFilename | NTIOLib.sys |
#### Imports
{{< details "Expand" >}}* ntoskrnl.exe
* HAL.dll
{{< /details >}}
#### ImportedFunctions
{{< details "Expand" >}}* MmUnmapIoSpace
* MmMapIoSpace
* IofCompleteRequest
* IoDeleteDevice
* IoCreateDevice
* KeBugCheckEx
* RtlInitUnicodeString
* IoCreateSymbolicLink
* IoDeleteSymbolicLink
* __C_specific_handler
* HalSetBusDataByOffset
* HalGetBusDataByOffset
{{< /details >}}
#### ExportedFunctions
{{< details "Expand" >}}{{< /details >}}
| Filename | NTIOLib.sys |
|:---- | ---- | 
| MD5 | <a href="https://www.virustotal.com/gui/file/300c5b1795c9b6cc1bc4d7d55c7bbe85">300c5b1795c9b6cc1bc4d7d55c7bbe85</a> |
| SHA1 | <a href="https://www.virustotal.com/gui/file/65d8a7c2e867b22d1c14592b020c548dd0665646">65d8a7c2e867b22d1c14592b020c548dd0665646</a> |
| SHA256 | <a href="https://www.virustotal.com/gui/file/d92eab70bcece4432258c9c9a914483a2267f6ab5ce2630048d3a99e8cb1b482">d92eab70bcece4432258c9c9a914483a2267f6ab5ce2630048d3a99e8cb1b482</a> |
| Authentihash MD5 | <a href="https://www.virustotal.com/gui/search/authentihash%253A6b5dd12cfdee0cf8a654eacc65028c36">6b5dd12cfdee0cf8a654eacc65028c36</a> || Authentihash SHA1 | <a href="https://www.virustotal.com/gui/search/authentihash%253A081d87fdb40a348b85382c63ea029281f213b778">081d87fdb40a348b85382c63ea029281f213b778</a> || Authentihash SHA256 | <a href="https://www.virustotal.com/gui/search/authentihash%253Ad82a938dc7b0077a06d940bd3ce6097e3b02cdc254ec6fd863c0e526f2af69fa">d82a938dc7b0077a06d940bd3ce6097e3b02cdc254ec6fd863c0e526f2af69fa</a> || Signature | MICRO-STAR INTERNATIONAL CO., LTD., GlobalSign CodeSigning CA - G2, GlobalSign Root CA - R1   || Company | MSI || Description | NTIOLib || Product | NTIOLib || OriginalFilename | NTIOLib.sys |
#### Imports
{{< details "Expand" >}}* ntoskrnl.exe
* HAL.dll
{{< /details >}}
#### ImportedFunctions
{{< details "Expand" >}}* MmUnmapIoSpace
* MmMapIoSpace
* IofCompleteRequest
* IoDeleteDevice
* IoCreateDevice
* KeBugCheckEx
* RtlInitUnicodeString
* IoCreateSymbolicLink
* IoDeleteSymbolicLink
* __C_specific_handler
* HalSetBusDataByOffset
* HalGetBusDataByOffset
{{< /details >}}
#### ExportedFunctions
{{< details "Expand" >}}{{< /details >}}
| Filename | NTIOLib.sys |
|:---- | ---- | 
| MD5 | <a href="https://www.virustotal.com/gui/file/3dbf69f935ea48571ea6b0f5a2878896">3dbf69f935ea48571ea6b0f5a2878896</a> |
| SHA1 | <a href="https://www.virustotal.com/gui/file/c8d87f3cd34c572870e63a696cf771580e6ea81b">c8d87f3cd34c572870e63a696cf771580e6ea81b</a> |
| SHA256 | <a href="https://www.virustotal.com/gui/file/e005e8d183e853a27ad3bb56f25489f369c11b0d47e3d4095aad9291b3343bf1">e005e8d183e853a27ad3bb56f25489f369c11b0d47e3d4095aad9291b3343bf1</a> |
| Authentihash MD5 | <a href="https://www.virustotal.com/gui/search/authentihash%253Ac80d819869c1718a58dfada2167e842c">c80d819869c1718a58dfada2167e842c</a> || Authentihash SHA1 | <a href="https://www.virustotal.com/gui/search/authentihash%253A0d6b74ac325c816bfdc20aa4a0fc0eb2cd45f4e6">0d6b74ac325c816bfdc20aa4a0fc0eb2cd45f4e6</a> || Authentihash SHA256 | <a href="https://www.virustotal.com/gui/search/authentihash%253Af8ffb8a23be71c26f784905110b7e752473be55216300d08a83c40c1496fb6c1">f8ffb8a23be71c26f784905110b7e752473be55216300d08a83c40c1496fb6c1</a> || Signature | MICRO-STAR INTERNATIONAL CO., LTD., GlobalSign CodeSigning CA - G2, GlobalSign Root CA - R1   || Company | MSI || Description | NTIOLib || Product | NTIOLib || OriginalFilename | NTIOLib.sys |
#### Imports
{{< details "Expand" >}}* ntoskrnl.exe
* HAL.dll
{{< /details >}}
#### ImportedFunctions
{{< details "Expand" >}}* MmUnmapIoSpace
* MmMapIoSpace
* IofCompleteRequest
* IoDeleteDevice
* IoCreateDevice
* KeBugCheckEx
* RtlInitUnicodeString
* IoCreateSymbolicLink
* IoDeleteSymbolicLink
* __C_specific_handler
* HalSetBusDataByOffset
* HalGetBusDataByOffset
{{< /details >}}
#### ExportedFunctions
{{< details "Expand" >}}{{< /details >}}
| Filename | NTIOLib.sys |
|:---- | ---- | 
| MD5 | <a href="https://www.virustotal.com/gui/file/8d63e1a9ff4cafee1af179c0c544365c">8d63e1a9ff4cafee1af179c0c544365c</a> |
| SHA1 | <a href="https://www.virustotal.com/gui/file/c4d7fb9db3c3459f7e8c0e3d48c95c7c9c4cff60">c4d7fb9db3c3459f7e8c0e3d48c95c7c9c4cff60</a> |
| SHA256 | <a href="https://www.virustotal.com/gui/file/e68d453d333854787f8470c8baef3e0d082f26df5aa19c0493898bcf3401e39a">e68d453d333854787f8470c8baef3e0d082f26df5aa19c0493898bcf3401e39a</a> |
| Authentihash MD5 | <a href="https://www.virustotal.com/gui/search/authentihash%253A7e9154ee514d494701eb8559524f8e2e">7e9154ee514d494701eb8559524f8e2e</a> || Authentihash SHA1 | <a href="https://www.virustotal.com/gui/search/authentihash%253A95c5f63e97d18e1ccc449a79ec952a5f6e76b9eb">95c5f63e97d18e1ccc449a79ec952a5f6e76b9eb</a> || Authentihash SHA256 | <a href="https://www.virustotal.com/gui/search/authentihash%253A543ee203b355c4cbac74d9bac71fb73c0c5c5c3afe268e2ae8ae48d61d350709">543ee203b355c4cbac74d9bac71fb73c0c5c5c3afe268e2ae8ae48d61d350709</a> || Signature | MICRO-STAR INTERNATIONAL CO., LTD., GlobalSign CodeSigning CA - G2, GlobalSign Root CA - R1   || Company | MSI || Description | NTIOLib For MSISimple_OC || Product | NTIOLib || OriginalFilename | NTIOLib.sys |
#### Imports
{{< details "Expand" >}}* ntoskrnl.exe
* HAL.dll
{{< /details >}}
#### ImportedFunctions
{{< details "Expand" >}}* MmUnmapIoSpace
* MmMapIoSpace
* IofCompleteRequest
* IoDeleteDevice
* IoCreateDevice
* KeBugCheckEx
* RtlInitUnicodeString
* IoCreateSymbolicLink
* IoDeleteSymbolicLink
* __C_specific_handler
* HalSetBusDataByOffset
* HalGetBusDataByOffset
{{< /details >}}
#### ExportedFunctions
{{< details "Expand" >}}{{< /details >}}
| Filename | NTIOLib.sys |
|:---- | ---- | 
| MD5 | <a href="https://www.virustotal.com/gui/file/e9a30edef1105b8a64218f892b2e56ed">e9a30edef1105b8a64218f892b2e56ed</a> |
| SHA1 | <a href="https://www.virustotal.com/gui/file/d34a7c497c603f3f7fcad546dc4097c2da17c430">d34a7c497c603f3f7fcad546dc4097c2da17c430</a> |
| SHA256 | <a href="https://www.virustotal.com/gui/file/e83908eba2501a00ef9e74e7d1c8b4ff1279f1cd6051707fd51824f87e4378fa">e83908eba2501a00ef9e74e7d1c8b4ff1279f1cd6051707fd51824f87e4378fa</a> |
| Authentihash MD5 | <a href="https://www.virustotal.com/gui/search/authentihash%253A01a9049b40b0e848649dd1e0d224e63e">01a9049b40b0e848649dd1e0d224e63e</a> || Authentihash SHA1 | <a href="https://www.virustotal.com/gui/search/authentihash%253A9030ba396131afec733fc208ef55a4d37b6ffc07">9030ba396131afec733fc208ef55a4d37b6ffc07</a> || Authentihash SHA256 | <a href="https://www.virustotal.com/gui/search/authentihash%253A826e80ea5f657c75127c066b86caea8089f33b09b12c3d393fca8efedd40c1ef">826e80ea5f657c75127c066b86caea8089f33b09b12c3d393fca8efedd40c1ef</a> || Signature | MICRO-STAR INTERNATIONAL CO., LTD., GlobalSign CodeSigning CA - G2, GlobalSign Root CA - R1   || Company | MSI || Description | NTIOLib for MSICPU_CC || Product | NTIOLib || OriginalFilename | NTIOLib.sys |
#### Imports
{{< details "Expand" >}}* ntoskrnl.exe
* HAL.dll
{{< /details >}}
#### ImportedFunctions
{{< details "Expand" >}}* MmUnmapIoSpace
* MmMapIoSpace
* IofCompleteRequest
* IoDeleteDevice
* IoCreateDevice
* KeBugCheckEx
* RtlInitUnicodeString
* IoCreateSymbolicLink
* IoDeleteSymbolicLink
* __C_specific_handler
* HalSetBusDataByOffset
* HalGetBusDataByOffset
{{< /details >}}
#### ExportedFunctions
{{< details "Expand" >}}{{< /details >}}
| Filename | NTIOLib.sys |
|:---- | ---- | 
| MD5 | <a href="https://www.virustotal.com/gui/file/361a598d8bb92c13b18abb7cac850b01">361a598d8bb92c13b18abb7cac850b01</a> |
| SHA1 | <a href="https://www.virustotal.com/gui/file/1fd7f881ea4a1dbb5c9aeb9e7ad659a85421745b">1fd7f881ea4a1dbb5c9aeb9e7ad659a85421745b</a> |
| SHA256 | <a href="https://www.virustotal.com/gui/file/ef86c4e5ee1dbc4f81cd864e8cd2f4a2a85ee4475b9a9ab698a4ae1cc71fbeb0">ef86c4e5ee1dbc4f81cd864e8cd2f4a2a85ee4475b9a9ab698a4ae1cc71fbeb0</a> |
| Authentihash MD5 | <a href="https://www.virustotal.com/gui/search/authentihash%253A94faebdbb74a0b99a8a17430671cdf9e">94faebdbb74a0b99a8a17430671cdf9e</a> || Authentihash SHA1 | <a href="https://www.virustotal.com/gui/search/authentihash%253Aaca4c47b4823b5653cb42e599ee6168f435bdcc7">aca4c47b4823b5653cb42e599ee6168f435bdcc7</a> || Authentihash SHA256 | <a href="https://www.virustotal.com/gui/search/authentihash%253A21a6689456d9833453d5247e4c5faf13edcd4835408e033c40ae1a225711ae8f">21a6689456d9833453d5247e4c5faf13edcd4835408e033c40ae1a225711ae8f</a> || Signature | MICRO-STAR INTERNATIONAL CO., LTD., GlobalSign CodeSigning CA - G2, GlobalSign Root CA - R1   || Company | MSI || Description | NTIOLib || Product | NTIOLib || OriginalFilename | NTIOLib.sys |
#### Imports
{{< details "Expand" >}}* ntoskrnl.exe
* HAL.dll
{{< /details >}}
#### ImportedFunctions
{{< details "Expand" >}}* MmUnmapIoSpace
* MmMapIoSpace
* IofCompleteRequest
* IoDeleteDevice
* IoCreateDevice
* KeBugCheckEx
* RtlInitUnicodeString
* IoCreateSymbolicLink
* IoDeleteSymbolicLink
* __C_specific_handler
* HalSetBusDataByOffset
* HalGetBusDataByOffset
{{< /details >}}
#### ExportedFunctions
{{< details "Expand" >}}{{< /details >}}
| Filename | NTIOLib.sys |
|:---- | ---- | 
| MD5 | <a href="https://www.virustotal.com/gui/file/7b43dfd84de5e81162ebcfafb764b769">7b43dfd84de5e81162ebcfafb764b769</a> |
| SHA1 | <a href="https://www.virustotal.com/gui/file/0b8b83f245d94107cb802a285e6529161d9a834d">0b8b83f245d94107cb802a285e6529161d9a834d</a> |
| SHA256 | <a href="https://www.virustotal.com/gui/file/f088b2ba27dacd5c28f8ee428f1350dca4bc7c6606309c287c801b2e1da1a53d">f088b2ba27dacd5c28f8ee428f1350dca4bc7c6606309c287c801b2e1da1a53d</a> |
| Authentihash MD5 | <a href="https://www.virustotal.com/gui/search/authentihash%253A85dcbf05c91ceacc919a1638dd3c8f9f">85dcbf05c91ceacc919a1638dd3c8f9f</a> || Authentihash SHA1 | <a href="https://www.virustotal.com/gui/search/authentihash%253A3d947aff431bb8ec02d9be3b4499312a62d4fec9">3d947aff431bb8ec02d9be3b4499312a62d4fec9</a> || Authentihash SHA256 | <a href="https://www.virustotal.com/gui/search/authentihash%253A5c22b7f65de948fdb74ffc3b5bae68f109bf7404a154ddbfa25dfd53e1bde667">5c22b7f65de948fdb74ffc3b5bae68f109bf7404a154ddbfa25dfd53e1bde667</a> || Signature | MICRO-STAR INTERNATIONAL CO., LTD., GlobalSign CodeSigning CA - G2, GlobalSign Root CA - R1   || Company | MSI || Description | NTIOLib || Product | NTIOLib || OriginalFilename | NTIOLib.sys |
#### Imports
{{< details "Expand" >}}* ntoskrnl.exe
* HAL.dll
{{< /details >}}
#### ImportedFunctions
{{< details "Expand" >}}* MmUnmapIoSpace
* MmMapIoSpace
* IofCompleteRequest
* IoDeleteDevice
* IoCreateDevice
* KeBugCheckEx
* RtlInitUnicodeString
* IoCreateSymbolicLink
* IoDeleteSymbolicLink
* __C_specific_handler
* HalSetBusDataByOffset
* HalGetBusDataByOffset
{{< /details >}}
#### ExportedFunctions
{{< details "Expand" >}}{{< /details >}}
| Filename | NTIOLib.sys |
|:---- | ---- | 
| MD5 | <a href="https://www.virustotal.com/gui/file/f66b96aa7ae430b56289409241645099">f66b96aa7ae430b56289409241645099</a> |
| SHA1 | <a href="https://www.virustotal.com/gui/file/c969f1f73922fd95db1992a5b552fbc488366a40">c969f1f73922fd95db1992a5b552fbc488366a40</a> |
| SHA256 | <a href="https://www.virustotal.com/gui/file/fd8669794c67b396c12fc5f08e9c004fdf851a82faf302846878173e4fbecb03">fd8669794c67b396c12fc5f08e9c004fdf851a82faf302846878173e4fbecb03</a> |
| Authentihash MD5 | <a href="https://www.virustotal.com/gui/search/authentihash%253Ab9951498dd00ac42a36a6f5d59ebe98d">b9951498dd00ac42a36a6f5d59ebe98d</a> || Authentihash SHA1 | <a href="https://www.virustotal.com/gui/search/authentihash%253A0c429ee64668374fdf6d187071d4f0a932992a5f">0c429ee64668374fdf6d187071d4f0a932992a5f</a> || Authentihash SHA256 | <a href="https://www.virustotal.com/gui/search/authentihash%253A2e5648f892460e2a2a450519b523007ca6973a3679a59c07582aa5bdbd6584d4">2e5648f892460e2a2a450519b523007ca6973a3679a59c07582aa5bdbd6584d4</a> || Signature | Micro-Star Int&#39;l Co. Ltd., GlobalSign ObjectSign CA, GlobalSign Primary Object Publishing CA, GlobalSign   || Company | MSI || Description | NTIOLib || Product | NTIOLib || OriginalFilename | NTIOLib.sys |
#### Imports
{{< details "Expand" >}}* ntoskrnl.exe
* HAL.dll
{{< /details >}}
#### ImportedFunctions
{{< details "Expand" >}}* MmUnmapIoSpace
* MmMapIoSpace
* IofCompleteRequest
* IoDeleteDevice
* IoCreateDevice
* KeBugCheckEx
* RtlInitUnicodeString
* IoCreateSymbolicLink
* IoDeleteSymbolicLink
* __C_specific_handler
* HalSetBusDataByOffset
* HalGetBusDataByOffset
{{< /details >}}
#### ExportedFunctions
{{< details "Expand" >}}{{< /details >}}



[*source*](https://github.com/magicsword-io/LOLDrivers/tree/main/yaml/ntiolib.yaml)

*last_updated:* 2023-04-19








{{< /column >}}
{{< /block >}}
