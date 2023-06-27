+++

description = ""
title = "e32bc3da-4db1-4858-a62c-6fbe4db6afbd"
weight = 10
displayTitle = "RTCore64.sys"
+++


{{< block "grid-1" >}}
{{< column "mt-2 pt-1">}}


# RTCore64.sys ![:inline](/images/twitter_verified.png) 


### Description

The driver in Micro-Star MSI Afterburner 4.6.2.15658 (aka RTCore64.sys and RTCore32.sys) allows any authenticated user to read and write to arbitrary memory, I/O ports, and MSRs. This can be exploited for privilege escalation, code execution under high privileges, and information disclosure. These signed drivers can also be used to bypass the Microsoft driver-signing policy to deploy malicious code.
- **UUID**: e32bc3da-4db1-4858-a62c-6fbe4db6afbd
- **Created**: 2023-01-09
- **Author**: Michael Haag
- **Acknowledgement**:  | [](https://twitter.com/)

{{< button "https://github.com/magicsword-io/LOLDrivers/raw/main/drivers/2d8e4f38b36c334d0a32a7324832501d.bin" "Download" >}}
{{< tip "warning" >}}
This download link contains the vulnerable driver!

{{< /tip >}}

### Commands

```
sc.exe create RTCore64.sys binPath=C:\windows\temp\RTCore64.sys type=kernel &amp;&amp; sc.exe start RTCore64.sys
```


| Use Case | Privileges | Operating System | 
|:---- | ---- | ---- |
| Elevate privileges | kernel | Windows 10 |



### Detections


{{< block "grid-3" >}}
{{< column >}}
#### YARA 🏹
{{< details "Expand" >}}

{{< button "https://github.com/magicsword-io/LOLDrivers/tree/main/detections/yara/yara-rules_vuln_drivers_strict.yar" "Exact Match" >}}{{< tip >}}with header and size limitation{{< /tip >}} 

{{< button "https://github.com/magicsword-io/LOLDrivers/tree/main/detections/yara/yara-rules_vuln_drivers.yar" "Threat Hunting" >}}{{< tip >}}without header and size limitation{{< /tip >}} 

{{< button "https://github.com/magicsword-io/LOLDrivers/tree/main/detections/yara/yara-rules_vuln_strict_renamed.yar" "Renamed" >}}{{< tip >}}for renamed driver files{{< /tip >}} 


{{< /details >}}
{{< /column >}}



{{< column >}}

#### Sigma 🛡️
{{< details "Expand" >}}
{{< button "https://github.com/magicsword-io/LOLDrivers/tree/main/detections/sigma/driver_load_win_vuln_drivers_names.yml" "Names" >}}{{< tip >}}detects loading using name only{{< /tip >}} 


{{< button "https://github.com/magicsword-io/LOLDrivers/tree/main/detections/sigma/driver_load_win_vuln_drivers.yml" "Hashes" >}}{{< tip >}}detects loading using hashes only{{< /tip >}} 

{{< /details >}}

{{< /column >}}


{{< column "mb-2" >}}

#### Sysmon 🔎
{{< details "Expand" >}}
{{< button "https://github.com/magicsword-io/LOLDrivers/tree/main/detections/sysmon/sysmon_config_vulnerable_hashes_block.xml" "Block" >}}{{< tip >}}on hashes{{< /tip >}} 

{{< button "https://github.com/magicsword-io/LOLDrivers/tree/main/detections/sysmon_config_vulnerable_hashes.xml" "Alert" >}}{{< tip >}}on hashes{{< /tip >}} 

{{< /details >}}

{{< /column >}}
{{< /block >}}


### Resources
<br>
<li><a href="https://github.com/elastic/protections-artifacts/search?q=VulnDriver">https://github.com/elastic/protections-artifacts/search?q=VulnDriver</a></li>
<li><a href="https://news.sophos.com/en-us/2022/10/04/blackbyte-ransomware-returns/">https://news.sophos.com/en-us/2022/10/04/blackbyte-ransomware-returns/</a></li>
<li><a href="https://github.com/elastic/protections-artifacts/search?q=VulnDriver">https://github.com/elastic/protections-artifacts/search?q=VulnDriver</a></li>
<li><a href="https://github.com/VoidSec/Exploit-Development/tree/b82b6d3ac1cce66221101d3e0f4634aa64cb4ca7/windows/x64/kernel/RTCore64_MSI_Afterburner_v.4.6.4.16117">https://github.com/VoidSec/Exploit-Development/tree/b82b6d3ac1cce66221101d3e0f4634aa64cb4ca7/windows/x64/kernel/RTCore64_MSI_Afterburner_v.4.6.4.16117</a></li>
<br>


### Known Vulnerable Samples

| Property           | Value |
|:-------------------|:------|
| Filename           | RTCore64.sys |
| MD5                | [2d8e4f38b36c334d0a32a7324832501d](https://www.virustotal.com/gui/file/2d8e4f38b36c334d0a32a7324832501d) |
| SHA1               | [f6f11ad2cd2b0cf95ed42324876bee1d83e01775](https://www.virustotal.com/gui/file/f6f11ad2cd2b0cf95ed42324876bee1d83e01775) |
| SHA256             | [01aa278b07b58dc46c84bd0b1b5c8e9ee4e62ea0bf7a695862444af32e87f1fd](https://www.virustotal.com/gui/file/01aa278b07b58dc46c84bd0b1b5c8e9ee4e62ea0bf7a695862444af32e87f1fd) |
| Authentihash MD5   | [538e5e595c61d2ea8defb7b047784734](https://www.virustotal.com/gui/search/authentihash%253A538e5e595c61d2ea8defb7b047784734) |
| Authentihash SHA1  | [4a68c2d7a4c471e062a32c83a36eedb45a619683](https://www.virustotal.com/gui/search/authentihash%253A4a68c2d7a4c471e062a32c83a36eedb45a619683) |
| Authentihash SHA256| [478c36f8af7844a80e24c1822507beef6314519185717ec7ae224a0e04b2f330](https://www.virustotal.com/gui/search/authentihash%253A478c36f8af7844a80e24c1822507beef6314519185717ec7ae224a0e04b2f330) |
| RichPEHeaderHash MD5   | [ebe2ae976914018e88e9fc480e7b6269](https://www.virustotal.com/gui/search/rich_pe_header_hash%253Aebe2ae976914018e88e9fc480e7b6269) |
| RichPEHeaderHash SHA1  | [960715bfbccb53b6c4eccca3b232b25640e15b52](https://www.virustotal.com/gui/search/rich_pe_header_hash%253A960715bfbccb53b6c4eccca3b232b25640e15b52) |
| RichPEHeaderHash SHA256| [d755e9f3cb861f5227319238f1811265e332e36a922b9a25da38b122a791fdfa](https://www.virustotal.com/gui/search/rich_pe_header_hash%253Ad755e9f3cb861f5227319238f1811265e332e36a922b9a25da38b122a791fdfa) |

#### Certificates

{{< details "Expand" >}}
###### Certificate 0400000000012f4ee152d7
| Field                             | Value                      |
|-----------------------------------|----------------------------|
| ToBeSigned (TBS) MD5              | e140543fe3256027cfa79fc3c19c1776  |
| ToBeSigned (TBS) SHA1             | c655f94eb1ecc93de319fc0c9a2dc6c5ec063728 |
| ToBeSigned (TBS) SHA256           | 3ca71e85908ff67368e4dc00253f5691b9e6d50c966e7784143d75fb92aa3448 |
| Subject                           | C=BE, O=GlobalSign nv,sa, CN=GlobalSign Timestamping CA , G2 |
| ValidFrom                         | 2011-04-13 10:00:00 |
| ValidTo                           | 2028-01-28 12:00:00 |
| Signature                         | 4e5e56901e46b4d94931f3bb1739281bc216ddfd41dc0905049b6fb2a29ad6992e40990055b5ea3fa52076d38634d417cc553ac782eeefa8babcd8069f1550dfcd167b523a02d7191afdaff0785ce04bc518df3a241edaacb8a95804020730dbb0125efe31bef00448f4f070f83a5e5683cf3dfb0dbcf4c5ed979db9d4dba52784e3389b8ba735864420a43b6da46a0ba183fd28ebdaef28f6cc885dfb0a3b00abe021ebe22f356c0f8e344597eba2f79933357ecb9a8abb454de73f9fc2d98afa65b26ec77e65ffe892e12c31a2f7b02736488f266f3bee4d761f79c3e57f9635bc2d0ecc01b08e7fff518080a792d4b34446648c874f166307314b63b0dff3 |
| SignatureAlgorithmOID             | 1.2.840.113549.1.1.5 |
| IsCertificateAuthority            | True |
| SerialNumber                      | 0400000000012f4ee152d7 |
| Version                           | 3 |
###### Certificate 0400000000012f4ee1355c
| Field                             | Value                      |
|-----------------------------------|----------------------------|
| ToBeSigned (TBS) MD5              | f6a9e8eb8784f3f694b4e353c08a0ff5  |
| ToBeSigned (TBS) SHA1             | 589a7d4df869395601ba7538a65afae8c4616385 |
| ToBeSigned (TBS) SHA256           | cbdc9a0ad785d0c2013211746b42234e18bdc7d54a7a260647badc1c9e712ed4 |
| Subject                           | C=BE, O=GlobalSign nv,sa, CN=GlobalSign CodeSigning CA , G2 |
| ValidFrom                         | 2011-04-13 10:00:00 |
| ValidTo                           | 2019-04-13 10:00:00 |
| Signature                         | 225cc5dd3df40b70d8e3f5e7c58e0901bbb196365c5a07adc7a8444951257aae0da4193b929ccfb94226bb3b6c97e7c7ce116d6891da8d6df1534d54388c61f3c8827669be81320b31c36cc99e200a582ff048fe7e4807aad743589473540431a9780d3b8cb070c13d7ed7bd2f2ac3e2f58f0c90dc6ba5c8be685e5d6df878d2be49951e15780891fb34c8be84adbce0c6dd18dbf3caf07bc2143c18b803ba953e211e3f60697a7f6a039e8d4af9f0282c30845eec267242b16dcb64c3128cd6844b67417cb103177809e3ada8b6962da47e80034f88f7c16b5a4615cd2c198bd8709ce52d49886072a8a4195270435edad64603b0680e24ef4af60b2524ef24 |
| SignatureAlgorithmOID             | 1.2.840.113549.1.1.5 |
| IsCertificateAuthority            | True |
| SerialNumber                      | 0400000000012f4ee1355c |
| Version                           | 3 |
###### Certificate 1121d699a764973ef1f8427ee919cc534114
| Field                             | Value                      |
|-----------------------------------|----------------------------|
| ToBeSigned (TBS) MD5              | acb5170547d76873f1e4ff18ed5de2eb  |
| ToBeSigned (TBS) SHA1             | bd6e261e75b807381bada7287de04d259258a5fa |
| ToBeSigned (TBS) SHA256           | 4783380498acf592286ef2dea0fcc5bdea3f54d5e374d3e3497df9d5f662cfb6 |
| Subject                           | C=SG, O=GMO GlobalSign Pte Ltd, CN=GlobalSign TSA for MS Authenticode , G2 |
| ValidFrom                         | 2016-05-24 00:00:00 |
| ValidTo                           | 2027-06-24 00:00:00 |
| Signature                         | 8fa91a916d04a637200e8396de23d36b6e1f6edd643d682122b5f84736698ee1a545c724a222b72909cc545aaec6bccd638eb33d5048e5b4ccaecd928d9e288b134a11aabda3efd3b236fcb4a172bf6d9763798c44bc702f7ef3bcdd8253ab1af6ebfa1c97bcb6379ca41c30bcabbc2d4736df922003e871c658f675059a34f00b595a824434aa80e42f84f6475d96c9b6caca9db7a6bae450d3d437b8ba200ed0d3922a5bc459bba16ddb3cce449dc1382aade38dbdcd09771a10be670a02366488b9b31b26eee79e60c446a8bc61336ccf4eb99cb96af09f37feb53d4f9ad34dffde208e4e97a6fd9f09bc4dca1876c9b04d8550f280d21d06f5580407b118 |
| SignatureAlgorithmOID             | 1.2.840.113549.1.1.5 |
| IsCertificateAuthority            | False |
| SerialNumber                      | 1121d699a764973ef1f8427ee919cc534114 |
| Version                           | 3 |
###### Certificate 112158044863e4dc19cf29a85668b7f45842
| Field                             | Value                      |
|-----------------------------------|----------------------------|
| ToBeSigned (TBS) MD5              | 403bb44a62aed1a94bd5df05b3292482  |
| ToBeSigned (TBS) SHA1             | e4a0353e75940ab1e8cbff2f433f186c7f0b0f09 |
| ToBeSigned (TBS) SHA256           | 5b81998ed98b343c04134c336e03f3051779eae0e9f882e8339593d18556375d |
| Subject                           | C=TW, ST=Taiwan, L=New Taipei City, O=MICRO,STAR INTERNATIONAL CO., LTD., OU=MICRO,STAR INTERNATIONAL CO., LTD., CN=MICRO,STAR INTERNATIONAL CO., LTD. |
| ValidFrom                         | 2014-06-03 09:16:15 |
| ValidTo                           | 2017-09-03 09:16:15 |
| Signature                         | 8c35a5b5d3503f50119ab8f99b07a4bb4b71cafaf983206f744545c2997ae1762032fa2d37f4780cfe83bfa999d7bcbd863dc4a51ff39978160e2e191482ae6d7f08e8ffa337c96d8c2d38ddf476a497265a890c1bbf0dee89b1abd32343889a3757732d205ba06525fa8f6e15005405a53e55cef71ac0b6af3a640e4c8aef5e950ab8a8b5c8bcddb2ade96ad9473a3d860ae16fdbe3362cabfd916da089167d906d378dbf4534f7ffb77d87baba29f8f5bbbd9b4b7c127ac170a270dc7a7272d38fdf3bbadbfb448d47e5dd4d310a588666a0d66762e1b3704b1e00e39739190c02f4b981cf2d27ba07d2472ec320edf29e263f26278995d162102968c999b3 |
| SignatureAlgorithmOID             | 1.2.840.113549.1.1.5 |
| IsCertificateAuthority            | False |
| SerialNumber                      | 112158044863e4dc19cf29a85668b7f45842 |
| Version                           | 3 |
###### Certificate 610b7f6b000000000019
| Field                             | Value                      |
|-----------------------------------|----------------------------|
| ToBeSigned (TBS) MD5              | 4798d55be7663a75649cda4dedc686ef  |
| ToBeSigned (TBS) SHA1             | 0f1ab2937b245d9466ea6f9bf056a5942e3989cf |
| ToBeSigned (TBS) SHA256           | ef14ea05bb066ee9f4188196dd69cd769b283ac4d7555db52f5e76922d3456e1 |
| Subject                           | C=BE, O=GlobalSign nv,sa, OU=Root CA, CN=GlobalSign Root CA |
| ValidFrom                         | 2006-05-23 17:00:51 |
| ValidTo                           | 2016-05-23 17:10:51 |
| Signature                         | 13c56c5e077f3c57ff9b315f3fbd955425c679f92c31034d64694b56d95b976f7cf3f0d024657538639813701613f7a701f1c623e085866c0bf080945a75e87ce41e92b473bfc1b3a7b00bd31884cbcc09a35c9c4f3eb03a9c2d1bc404ef9737966fe5ecbaac6ab3d4e23cdf8b25e7acbc624531dda40a72e41bf8784301ccba3914de5d90aed85acf5eca46815133d5a60e5867d3d8665888169beeb11acaad91138421da9a6e20efda007428bac95ff34d5dc3da25692554ea44bcc39b29331cd63c961f8781c553d72a2733d42e197c08586ddb4e1999a9ea5ff39a9d8c513a5a5cbd2fa908359b54a7db351a521633343aa380046afdb4838cad90cf0c3a6596ec334e1826b849bbeb8192ff134d324b23c733e7b6716b15f69c80e6bcb76cbe41d5033a7133150050743b0e5df996aaed903eab134c809926bc38a5eb0236891db620be83ab10f8199ed76379d4aeb12f6136f94a4ba833c70e7241f9f1b1907eae46efde397b75a0411459041d42bc4788b8130e05fa1df0808dff70c677d84bdc460e231a72d5bfdefeaaae69583cfc5c46e4d5819a8b6e6559771a32a590a6b6649364fd0753c9a0de28ad2a6cc638d181ce98f54019e92c1743a4265fd3443053e41d02baa40a2f16dd7a60275242bbad98372897e4b8d27911e3108c48d5305d0a0c52def588ea8d1a2d67c9f4801484b7850cd16628a5c66f2461 |
| SignatureAlgorithmOID             | 1.2.840.113549.1.1.5 |
| IsCertificateAuthority            | True |
| SerialNumber                      | 610b7f6b000000000019 |
| Version                           | 3 |

{{< /details >}}
#### Imports
{{< details "Expand" >}}
* ntoskrnl.exe
* HAL.dll

{{< /details >}}
#### Imports
{{< details "Expand" >}}
* ntoskrnl.exe
* HAL.dll

{{< /details >}}
#### ImportedFunctions
{{< details "Expand" >}}
* ZwMapViewOfSection
* ObReferenceObjectByHandle
* ZwOpenSection
* MmMapIoSpace
* __C_specific_handler
* ZwClose
* ZwUnmapViewOfSection
* MmUnmapIoSpace
* IoCreateSymbolicLink
* IoCreateDevice
* RtlInitUnicodeString
* IoDeleteSymbolicLink
* IofCompleteRequest
* IoDeleteDevice
* HalTranslateBusAddress
* HalGetBusDataByOffset
* HalSetBusDataByOffset

{{< /details >}}
#### ExportedFunctions
{{< details "Expand" >}}

{{< /details >}}

#### Signature
{{< details "Expand" >}}
```
{
  "Certificates": [
    {
      "IsCertificateAuthority": true,
      "SerialNumber": "0400000000012f4ee152d7",
      "Signature": "4e5e56901e46b4d94931f3bb1739281bc216ddfd41dc0905049b6fb2a29ad6992e40990055b5ea3fa52076d38634d417cc553ac782eeefa8babcd8069f1550dfcd167b523a02d7191afdaff0785ce04bc518df3a241edaacb8a95804020730dbb0125efe31bef00448f4f070f83a5e5683cf3dfb0dbcf4c5ed979db9d4dba52784e3389b8ba735864420a43b6da46a0ba183fd28ebdaef28f6cc885dfb0a3b00abe021ebe22f356c0f8e344597eba2f79933357ecb9a8abb454de73f9fc2d98afa65b26ec77e65ffe892e12c31a2f7b02736488f266f3bee4d761f79c3e57f9635bc2d0ecc01b08e7fff518080a792d4b34446648c874f166307314b63b0dff3",
      "SignatureAlgorithmOID": "1.2.840.113549.1.1.5",
      "Subject": "C=BE, O=GlobalSign nv,sa, CN=GlobalSign Timestamping CA , G2",
      "TBS": {
        "MD5": "e140543fe3256027cfa79fc3c19c1776",
        "SHA1": "c655f94eb1ecc93de319fc0c9a2dc6c5ec063728",
        "SHA256": "3ca71e85908ff67368e4dc00253f5691b9e6d50c966e7784143d75fb92aa3448"
      },
      "ValidFrom": "2011-04-13 10:00:00",
      "ValidTo": "2028-01-28 12:00:00",
      "Version": 3
    },
    {
      "IsCertificateAuthority": true,
      "SerialNumber": "0400000000012f4ee1355c",
      "Signature": "225cc5dd3df40b70d8e3f5e7c58e0901bbb196365c5a07adc7a8444951257aae0da4193b929ccfb94226bb3b6c97e7c7ce116d6891da8d6df1534d54388c61f3c8827669be81320b31c36cc99e200a582ff048fe7e4807aad743589473540431a9780d3b8cb070c13d7ed7bd2f2ac3e2f58f0c90dc6ba5c8be685e5d6df878d2be49951e15780891fb34c8be84adbce0c6dd18dbf3caf07bc2143c18b803ba953e211e3f60697a7f6a039e8d4af9f0282c30845eec267242b16dcb64c3128cd6844b67417cb103177809e3ada8b6962da47e80034f88f7c16b5a4615cd2c198bd8709ce52d49886072a8a4195270435edad64603b0680e24ef4af60b2524ef24",
      "SignatureAlgorithmOID": "1.2.840.113549.1.1.5",
      "Subject": "C=BE, O=GlobalSign nv,sa, CN=GlobalSign CodeSigning CA , G2",
      "TBS": {
        "MD5": "f6a9e8eb8784f3f694b4e353c08a0ff5",
        "SHA1": "589a7d4df869395601ba7538a65afae8c4616385",
        "SHA256": "cbdc9a0ad785d0c2013211746b42234e18bdc7d54a7a260647badc1c9e712ed4"
      },
      "ValidFrom": "2011-04-13 10:00:00",
      "ValidTo": "2019-04-13 10:00:00",
      "Version": 3
    },
    {
      "IsCertificateAuthority": false,
      "SerialNumber": "1121d699a764973ef1f8427ee919cc534114",
      "Signature": "8fa91a916d04a637200e8396de23d36b6e1f6edd643d682122b5f84736698ee1a545c724a222b72909cc545aaec6bccd638eb33d5048e5b4ccaecd928d9e288b134a11aabda3efd3b236fcb4a172bf6d9763798c44bc702f7ef3bcdd8253ab1af6ebfa1c97bcb6379ca41c30bcabbc2d4736df922003e871c658f675059a34f00b595a824434aa80e42f84f6475d96c9b6caca9db7a6bae450d3d437b8ba200ed0d3922a5bc459bba16ddb3cce449dc1382aade38dbdcd09771a10be670a02366488b9b31b26eee79e60c446a8bc61336ccf4eb99cb96af09f37feb53d4f9ad34dffde208e4e97a6fd9f09bc4dca1876c9b04d8550f280d21d06f5580407b118",
      "SignatureAlgorithmOID": "1.2.840.113549.1.1.5",
      "Subject": "C=SG, O=GMO GlobalSign Pte Ltd, CN=GlobalSign TSA for MS Authenticode , G2",
      "TBS": {
        "MD5": "acb5170547d76873f1e4ff18ed5de2eb",
        "SHA1": "bd6e261e75b807381bada7287de04d259258a5fa",
        "SHA256": "4783380498acf592286ef2dea0fcc5bdea3f54d5e374d3e3497df9d5f662cfb6"
      },
      "ValidFrom": "2016-05-24 00:00:00",
      "ValidTo": "2027-06-24 00:00:00",
      "Version": 3
    },
    {
      "IsCertificateAuthority": false,
      "SerialNumber": "112158044863e4dc19cf29a85668b7f45842",
      "Signature": "8c35a5b5d3503f50119ab8f99b07a4bb4b71cafaf983206f744545c2997ae1762032fa2d37f4780cfe83bfa999d7bcbd863dc4a51ff39978160e2e191482ae6d7f08e8ffa337c96d8c2d38ddf476a497265a890c1bbf0dee89b1abd32343889a3757732d205ba06525fa8f6e15005405a53e55cef71ac0b6af3a640e4c8aef5e950ab8a8b5c8bcddb2ade96ad9473a3d860ae16fdbe3362cabfd916da089167d906d378dbf4534f7ffb77d87baba29f8f5bbbd9b4b7c127ac170a270dc7a7272d38fdf3bbadbfb448d47e5dd4d310a588666a0d66762e1b3704b1e00e39739190c02f4b981cf2d27ba07d2472ec320edf29e263f26278995d162102968c999b3",
      "SignatureAlgorithmOID": "1.2.840.113549.1.1.5",
      "Subject": "C=TW, ST=Taiwan, L=New Taipei City, O=MICRO,STAR INTERNATIONAL CO., LTD., OU=MICRO,STAR INTERNATIONAL CO., LTD., CN=MICRO,STAR INTERNATIONAL CO., LTD.",
      "TBS": {
        "MD5": "403bb44a62aed1a94bd5df05b3292482",
        "SHA1": "e4a0353e75940ab1e8cbff2f433f186c7f0b0f09",
        "SHA256": "5b81998ed98b343c04134c336e03f3051779eae0e9f882e8339593d18556375d"
      },
      "ValidFrom": "2014-06-03 09:16:15",
      "ValidTo": "2017-09-03 09:16:15",
      "Version": 3
    },
    {
      "IsCertificateAuthority": true,
      "SerialNumber": "610b7f6b000000000019",
      "Signature": "13c56c5e077f3c57ff9b315f3fbd955425c679f92c31034d64694b56d95b976f7cf3f0d024657538639813701613f7a701f1c623e085866c0bf080945a75e87ce41e92b473bfc1b3a7b00bd31884cbcc09a35c9c4f3eb03a9c2d1bc404ef9737966fe5ecbaac6ab3d4e23cdf8b25e7acbc624531dda40a72e41bf8784301ccba3914de5d90aed85acf5eca46815133d5a60e5867d3d8665888169beeb11acaad91138421da9a6e20efda007428bac95ff34d5dc3da25692554ea44bcc39b29331cd63c961f8781c553d72a2733d42e197c08586ddb4e1999a9ea5ff39a9d8c513a5a5cbd2fa908359b54a7db351a521633343aa380046afdb4838cad90cf0c3a6596ec334e1826b849bbeb8192ff134d324b23c733e7b6716b15f69c80e6bcb76cbe41d5033a7133150050743b0e5df996aaed903eab134c809926bc38a5eb0236891db620be83ab10f8199ed76379d4aeb12f6136f94a4ba833c70e7241f9f1b1907eae46efde397b75a0411459041d42bc4788b8130e05fa1df0808dff70c677d84bdc460e231a72d5bfdefeaaae69583cfc5c46e4d5819a8b6e6559771a32a590a6b6649364fd0753c9a0de28ad2a6cc638d181ce98f54019e92c1743a4265fd3443053e41d02baa40a2f16dd7a60275242bbad98372897e4b8d27911e3108c48d5305d0a0c52def588ea8d1a2d67c9f4801484b7850cd16628a5c66f2461",
      "SignatureAlgorithmOID": "1.2.840.113549.1.1.5",
      "Subject": "C=BE, O=GlobalSign nv,sa, OU=Root CA, CN=GlobalSign Root CA",
      "TBS": {
        "MD5": "4798d55be7663a75649cda4dedc686ef",
        "SHA1": "0f1ab2937b245d9466ea6f9bf056a5942e3989cf",
        "SHA256": "ef14ea05bb066ee9f4188196dd69cd769b283ac4d7555db52f5e76922d3456e1"
      },
      "ValidFrom": "2006-05-23 17:00:51",
      "ValidTo": "2016-05-23 17:10:51",
      "Version": 3
    }
  ],
  "CertificatesInfo": "",
  "Signer": [
    {
      "Issuer": "C=BE, O=GlobalSign nv,sa, CN=GlobalSign CodeSigning CA , G2",
      "SerialNumber": "112158044863e4dc19cf29a85668b7f45842",
      "Version": 1
    }
  ],
  "SignerInfo": ""
}
```

{{< /details >}}
-----
| Property           | Value |
|:-------------------|:------|
| Filename           | RTCore64.sys |
| MD5                | [0ec361f2fba49c73260af351c39ff9cb](https://www.virustotal.com/gui/file/0ec361f2fba49c73260af351c39ff9cb) |
| SHA1               | [af50109b112995f8c82be8ef3a88be404510cdde](https://www.virustotal.com/gui/file/af50109b112995f8c82be8ef3a88be404510cdde) |
| SHA256             | [cdd2a4575a46bada4837a6153a79c14d60ee3129830717ef09e0e3efd9d00812](https://www.virustotal.com/gui/file/cdd2a4575a46bada4837a6153a79c14d60ee3129830717ef09e0e3efd9d00812) |
| Authentihash MD5   | [63fd0d800cac53db02638349cea2f8e7](https://www.virustotal.com/gui/search/authentihash%253A63fd0d800cac53db02638349cea2f8e7) |
| Authentihash SHA1  | [3856e573765f090afbbb9e5be4c886653402f755](https://www.virustotal.com/gui/search/authentihash%253A3856e573765f090afbbb9e5be4c886653402f755) |
| Authentihash SHA256| [ff8d17761c1645bdd1f0eccc69024907bbbfbe5c60679402b7d02f95b16310fe](https://www.virustotal.com/gui/search/authentihash%253Aff8d17761c1645bdd1f0eccc69024907bbbfbe5c60679402b7d02f95b16310fe) |
| RichPEHeaderHash MD5   | [ef0782d8ffe1c09386ae12bb2a2ca29c](https://www.virustotal.com/gui/search/rich_pe_header_hash%253Aef0782d8ffe1c09386ae12bb2a2ca29c) |
| RichPEHeaderHash SHA1  | [39449f1e1ca8b17755e87827b9a394a4143d5b07](https://www.virustotal.com/gui/search/rich_pe_header_hash%253A39449f1e1ca8b17755e87827b9a394a4143d5b07) |
| RichPEHeaderHash SHA256| [f56fbdad98db55f8a8a7391c059ec563e0f6754624895ec154a2dd9d1fa350d5](https://www.virustotal.com/gui/search/rich_pe_header_hash%253Af56fbdad98db55f8a8a7391c059ec563e0f6754624895ec154a2dd9d1fa350d5) |


#### Imports
{{< details "Expand" >}}
* ntoskrnl.exe
* HAL.dll

{{< /details >}}
#### Imports
{{< details "Expand" >}}
* ntoskrnl.exe
* HAL.dll

{{< /details >}}
#### ImportedFunctions
{{< details "Expand" >}}
* ZwMapViewOfSection
* ObReferenceObjectByHandle
* ZwOpenSection
* MmMapIoSpace
* IofCompleteRequest
* MmUnmapIoSpace
* ZwClose
* _except_handler3
* IoCreateSymbolicLink
* IoCreateDevice
* KeTickCount
* RtlInitUnicodeString
* IoDeleteSymbolicLink
* ZwUnmapViewOfSection
* IoDeleteDevice
* HalTranslateBusAddress
* HalGetBusDataByOffset
* HalSetBusDataByOffset

{{< /details >}}
#### ExportedFunctions
{{< details "Expand" >}}

{{< /details >}}

#### Signature
{{< details "Expand" >}}
```
{
  "Certificates": [
    {
      "IsCertificateAuthority": true,
      "SerialNumber": "0400000000012f4ee152d7",
      "Signature": "4e5e56901e46b4d94931f3bb1739281bc216ddfd41dc0905049b6fb2a29ad6992e40990055b5ea3fa52076d38634d417cc553ac782eeefa8babcd8069f1550dfcd167b523a02d7191afdaff0785ce04bc518df3a241edaacb8a95804020730dbb0125efe31bef00448f4f070f83a5e5683cf3dfb0dbcf4c5ed979db9d4dba52784e3389b8ba735864420a43b6da46a0ba183fd28ebdaef28f6cc885dfb0a3b00abe021ebe22f356c0f8e344597eba2f79933357ecb9a8abb454de73f9fc2d98afa65b26ec77e65ffe892e12c31a2f7b02736488f266f3bee4d761f79c3e57f9635bc2d0ecc01b08e7fff518080a792d4b34446648c874f166307314b63b0dff3",
      "SignatureAlgorithmOID": "1.2.840.113549.1.1.5",
      "Subject": "C=BE, O=GlobalSign nv,sa, CN=GlobalSign Timestamping CA , G2",
      "TBS": {
        "MD5": "e140543fe3256027cfa79fc3c19c1776",
        "SHA1": "c655f94eb1ecc93de319fc0c9a2dc6c5ec063728",
        "SHA256": "3ca71e85908ff67368e4dc00253f5691b9e6d50c966e7784143d75fb92aa3448"
      },
      "ValidFrom": "2011-04-13 10:00:00",
      "ValidTo": "2028-01-28 12:00:00",
      "Version": 3
    },
    {
      "IsCertificateAuthority": true,
      "SerialNumber": "0400000000012f4ee1355c",
      "Signature": "225cc5dd3df40b70d8e3f5e7c58e0901bbb196365c5a07adc7a8444951257aae0da4193b929ccfb94226bb3b6c97e7c7ce116d6891da8d6df1534d54388c61f3c8827669be81320b31c36cc99e200a582ff048fe7e4807aad743589473540431a9780d3b8cb070c13d7ed7bd2f2ac3e2f58f0c90dc6ba5c8be685e5d6df878d2be49951e15780891fb34c8be84adbce0c6dd18dbf3caf07bc2143c18b803ba953e211e3f60697a7f6a039e8d4af9f0282c30845eec267242b16dcb64c3128cd6844b67417cb103177809e3ada8b6962da47e80034f88f7c16b5a4615cd2c198bd8709ce52d49886072a8a4195270435edad64603b0680e24ef4af60b2524ef24",
      "SignatureAlgorithmOID": "1.2.840.113549.1.1.5",
      "Subject": "C=BE, O=GlobalSign nv,sa, CN=GlobalSign CodeSigning CA , G2",
      "TBS": {
        "MD5": "f6a9e8eb8784f3f694b4e353c08a0ff5",
        "SHA1": "589a7d4df869395601ba7538a65afae8c4616385",
        "SHA256": "cbdc9a0ad785d0c2013211746b42234e18bdc7d54a7a260647badc1c9e712ed4"
      },
      "ValidFrom": "2011-04-13 10:00:00",
      "ValidTo": "2019-04-13 10:00:00",
      "Version": 3
    },
    {
      "IsCertificateAuthority": false,
      "SerialNumber": "1121d699a764973ef1f8427ee919cc534114",
      "Signature": "8fa91a916d04a637200e8396de23d36b6e1f6edd643d682122b5f84736698ee1a545c724a222b72909cc545aaec6bccd638eb33d5048e5b4ccaecd928d9e288b134a11aabda3efd3b236fcb4a172bf6d9763798c44bc702f7ef3bcdd8253ab1af6ebfa1c97bcb6379ca41c30bcabbc2d4736df922003e871c658f675059a34f00b595a824434aa80e42f84f6475d96c9b6caca9db7a6bae450d3d437b8ba200ed0d3922a5bc459bba16ddb3cce449dc1382aade38dbdcd09771a10be670a02366488b9b31b26eee79e60c446a8bc61336ccf4eb99cb96af09f37feb53d4f9ad34dffde208e4e97a6fd9f09bc4dca1876c9b04d8550f280d21d06f5580407b118",
      "SignatureAlgorithmOID": "1.2.840.113549.1.1.5",
      "Subject": "C=SG, O=GMO GlobalSign Pte Ltd, CN=GlobalSign TSA for MS Authenticode , G2",
      "TBS": {
        "MD5": "acb5170547d76873f1e4ff18ed5de2eb",
        "SHA1": "bd6e261e75b807381bada7287de04d259258a5fa",
        "SHA256": "4783380498acf592286ef2dea0fcc5bdea3f54d5e374d3e3497df9d5f662cfb6"
      },
      "ValidFrom": "2016-05-24 00:00:00",
      "ValidTo": "2027-06-24 00:00:00",
      "Version": 3
    },
    {
      "IsCertificateAuthority": false,
      "SerialNumber": "112158044863e4dc19cf29a85668b7f45842",
      "Signature": "8c35a5b5d3503f50119ab8f99b07a4bb4b71cafaf983206f744545c2997ae1762032fa2d37f4780cfe83bfa999d7bcbd863dc4a51ff39978160e2e191482ae6d7f08e8ffa337c96d8c2d38ddf476a497265a890c1bbf0dee89b1abd32343889a3757732d205ba06525fa8f6e15005405a53e55cef71ac0b6af3a640e4c8aef5e950ab8a8b5c8bcddb2ade96ad9473a3d860ae16fdbe3362cabfd916da089167d906d378dbf4534f7ffb77d87baba29f8f5bbbd9b4b7c127ac170a270dc7a7272d38fdf3bbadbfb448d47e5dd4d310a588666a0d66762e1b3704b1e00e39739190c02f4b981cf2d27ba07d2472ec320edf29e263f26278995d162102968c999b3",
      "SignatureAlgorithmOID": "1.2.840.113549.1.1.5",
      "Subject": "C=TW, ST=Taiwan, L=New Taipei City, O=MICRO,STAR INTERNATIONAL CO., LTD., OU=MICRO,STAR INTERNATIONAL CO., LTD., CN=MICRO,STAR INTERNATIONAL CO., LTD.",
      "TBS": {
        "MD5": "403bb44a62aed1a94bd5df05b3292482",
        "SHA1": "e4a0353e75940ab1e8cbff2f433f186c7f0b0f09",
        "SHA256": "5b81998ed98b343c04134c336e03f3051779eae0e9f882e8339593d18556375d"
      },
      "ValidFrom": "2014-06-03 09:16:15",
      "ValidTo": "2017-09-03 09:16:15",
      "Version": 3
    },
    {
      "IsCertificateAuthority": true,
      "SerialNumber": "610b7f6b000000000019",
      "Signature": "13c56c5e077f3c57ff9b315f3fbd955425c679f92c31034d64694b56d95b976f7cf3f0d024657538639813701613f7a701f1c623e085866c0bf080945a75e87ce41e92b473bfc1b3a7b00bd31884cbcc09a35c9c4f3eb03a9c2d1bc404ef9737966fe5ecbaac6ab3d4e23cdf8b25e7acbc624531dda40a72e41bf8784301ccba3914de5d90aed85acf5eca46815133d5a60e5867d3d8665888169beeb11acaad91138421da9a6e20efda007428bac95ff34d5dc3da25692554ea44bcc39b29331cd63c961f8781c553d72a2733d42e197c08586ddb4e1999a9ea5ff39a9d8c513a5a5cbd2fa908359b54a7db351a521633343aa380046afdb4838cad90cf0c3a6596ec334e1826b849bbeb8192ff134d324b23c733e7b6716b15f69c80e6bcb76cbe41d5033a7133150050743b0e5df996aaed903eab134c809926bc38a5eb0236891db620be83ab10f8199ed76379d4aeb12f6136f94a4ba833c70e7241f9f1b1907eae46efde397b75a0411459041d42bc4788b8130e05fa1df0808dff70c677d84bdc460e231a72d5bfdefeaaae69583cfc5c46e4d5819a8b6e6559771a32a590a6b6649364fd0753c9a0de28ad2a6cc638d181ce98f54019e92c1743a4265fd3443053e41d02baa40a2f16dd7a60275242bbad98372897e4b8d27911e3108c48d5305d0a0c52def588ea8d1a2d67c9f4801484b7850cd16628a5c66f2461",
      "SignatureAlgorithmOID": "1.2.840.113549.1.1.5",
      "Subject": "C=BE, O=GlobalSign nv,sa, OU=Root CA, CN=GlobalSign Root CA",
      "TBS": {
        "MD5": "4798d55be7663a75649cda4dedc686ef",
        "SHA1": "0f1ab2937b245d9466ea6f9bf056a5942e3989cf",
        "SHA256": "ef14ea05bb066ee9f4188196dd69cd769b283ac4d7555db52f5e76922d3456e1"
      },
      "ValidFrom": "2006-05-23 17:00:51",
      "ValidTo": "2016-05-23 17:10:51",
      "Version": 3
    }
  ],
  "CertificatesInfo": "",
  "Signer": [
    {
      "Issuer": "C=BE, O=GlobalSign nv,sa, CN=GlobalSign CodeSigning CA , G2",
      "SerialNumber": "112158044863e4dc19cf29a85668b7f45842",
      "Version": 1
    }
  ],
  "SignerInfo": ""
}
```

{{< /details >}}
-----
| Property           | Value |
|:-------------------|:------|
| Filename           | RTCore64.sys |
| MD5                | [0a2ec9e3e236698185978a5fc76e74e6](https://www.virustotal.com/gui/file/0a2ec9e3e236698185978a5fc76e74e6) |
| SHA1               | [4fe873544c34243826489997a5ff14ed39dd090d](https://www.virustotal.com/gui/file/4fe873544c34243826489997a5ff14ed39dd090d) |
| SHA256             | [f1c8ca232789c2f11a511c8cd95a9f3830dd719cad5aa22cb7c3539ab8cb4dc3](https://www.virustotal.com/gui/file/f1c8ca232789c2f11a511c8cd95a9f3830dd719cad5aa22cb7c3539ab8cb4dc3) |
| Authentihash MD5   | [bcd9f192e2f9321ed549c722f30206e5](https://www.virustotal.com/gui/search/authentihash%253Abcd9f192e2f9321ed549c722f30206e5) |
| Authentihash SHA1  | [8498265d4ca81b83ec1454d9ec013d7a9c0c87bf](https://www.virustotal.com/gui/search/authentihash%253A8498265d4ca81b83ec1454d9ec013d7a9c0c87bf) |
| Authentihash SHA256| [606beced7746cdb684d3a44f41e48713c6bbe5bfb1486c52b5cca815e99d31b4](https://www.virustotal.com/gui/search/authentihash%253A606beced7746cdb684d3a44f41e48713c6bbe5bfb1486c52b5cca815e99d31b4) |

#### Certificates

{{< details "Expand" >}}

{{< /details >}}
#### Imports
{{< details "Expand" >}}
* ntoskrnl.exe
* HAL.dll

{{< /details >}}
#### Imports
{{< details "Expand" >}}
* ntoskrnl.exe
* HAL.dll

{{< /details >}}
#### ImportedFunctions
{{< details "Expand" >}}
* MmUnmapIoSpace
* ZwUnmapViewOfSection
* MmMapIoSpace
* ZwClose
* IoDeleteDevice
* ObReferenceObjectByHandle
* IoCreateSymbolicLink
* ZwOpenSection
* KeBugCheckEx
* RtlInitUnicodeString
* ZwMapViewOfSection
* IofCompleteRequest
* IoDeleteSymbolicLink
* MmGetSystemRoutineAddress
* IoCreateDevice
* ObOpenObjectByPointer
* ZwSetSecurityObject
* IoDeviceObjectType
* _snwprintf
* RtlLengthSecurityDescriptor
* SeCaptureSecurityDescriptor
* ExFreePoolWithTag
* RtlCreateSecurityDescriptor
* RtlSetDaclSecurityDescriptor
* RtlAbsoluteToSelfRelativeSD
* IoIsWdmVersionAvailable
* SeExports
* wcschr
* _wcsnicmp
* ExAllocatePoolWithTag
* RtlLengthSid
* RtlAddAccessAllowedAce
* RtlGetSaclSecurityDescriptor
* RtlGetDaclSecurityDescriptor
* RtlGetGroupSecurityDescriptor
* RtlGetOwnerSecurityDescriptor
* ZwOpenKey
* ZwCreateKey
* ZwQueryValueKey
* ZwSetValueKey
* RtlFreeUnicodeString
* __C_specific_handler
* HalGetBusDataByOffset
* HalSetBusDataByOffset
* HalTranslateBusAddress

{{< /details >}}
#### ExportedFunctions
{{< details "Expand" >}}

{{< /details >}}

#### Signature
{{< details "Expand" >}}
```
{
  "Certificates": [
    {
      "IsCertificateAuthority": true,
      "SerialNumber": "0400000000012f4ee152d7",
      "Signature": "4e5e56901e46b4d94931f3bb1739281bc216ddfd41dc0905049b6fb2a29ad6992e40990055b5ea3fa52076d38634d417cc553ac782eeefa8babcd8069f1550dfcd167b523a02d7191afdaff0785ce04bc518df3a241edaacb8a95804020730dbb0125efe31bef00448f4f070f83a5e5683cf3dfb0dbcf4c5ed979db9d4dba52784e3389b8ba735864420a43b6da46a0ba183fd28ebdaef28f6cc885dfb0a3b00abe021ebe22f356c0f8e344597eba2f79933357ecb9a8abb454de73f9fc2d98afa65b26ec77e65ffe892e12c31a2f7b02736488f266f3bee4d761f79c3e57f9635bc2d0ecc01b08e7fff518080a792d4b34446648c874f166307314b63b0dff3",
      "SignatureAlgorithmOID": "1.2.840.113549.1.1.5",
      "Subject": "C=BE, O=GlobalSign nv,sa, CN=GlobalSign Timestamping CA , G2",
      "TBS": {
        "MD5": "e140543fe3256027cfa79fc3c19c1776",
        "SHA1": "c655f94eb1ecc93de319fc0c9a2dc6c5ec063728",
        "SHA256": "3ca71e85908ff67368e4dc00253f5691b9e6d50c966e7784143d75fb92aa3448"
      },
      "ValidFrom": "2011-04-13 10:00:00",
      "ValidTo": "2028-01-28 12:00:00",
      "Version": 3
    },
    {
      "IsCertificateAuthority": true,
      "SerialNumber": "0400000000012f4ee1355c",
      "Signature": "225cc5dd3df40b70d8e3f5e7c58e0901bbb196365c5a07adc7a8444951257aae0da4193b929ccfb94226bb3b6c97e7c7ce116d6891da8d6df1534d54388c61f3c8827669be81320b31c36cc99e200a582ff048fe7e4807aad743589473540431a9780d3b8cb070c13d7ed7bd2f2ac3e2f58f0c90dc6ba5c8be685e5d6df878d2be49951e15780891fb34c8be84adbce0c6dd18dbf3caf07bc2143c18b803ba953e211e3f60697a7f6a039e8d4af9f0282c30845eec267242b16dcb64c3128cd6844b67417cb103177809e3ada8b6962da47e80034f88f7c16b5a4615cd2c198bd8709ce52d49886072a8a4195270435edad64603b0680e24ef4af60b2524ef24",
      "SignatureAlgorithmOID": "1.2.840.113549.1.1.5",
      "Subject": "C=BE, O=GlobalSign nv,sa, CN=GlobalSign CodeSigning CA , G2",
      "TBS": {
        "MD5": "f6a9e8eb8784f3f694b4e353c08a0ff5",
        "SHA1": "589a7d4df869395601ba7538a65afae8c4616385",
        "SHA256": "cbdc9a0ad785d0c2013211746b42234e18bdc7d54a7a260647badc1c9e712ed4"
      },
      "ValidFrom": "2011-04-13 10:00:00",
      "ValidTo": "2019-04-13 10:00:00",
      "Version": 3
    },
    {
      "IsCertificateAuthority": false,
      "SerialNumber": "1121d699a764973ef1f8427ee919cc534114",
      "Signature": "8fa91a916d04a637200e8396de23d36b6e1f6edd643d682122b5f84736698ee1a545c724a222b72909cc545aaec6bccd638eb33d5048e5b4ccaecd928d9e288b134a11aabda3efd3b236fcb4a172bf6d9763798c44bc702f7ef3bcdd8253ab1af6ebfa1c97bcb6379ca41c30bcabbc2d4736df922003e871c658f675059a34f00b595a824434aa80e42f84f6475d96c9b6caca9db7a6bae450d3d437b8ba200ed0d3922a5bc459bba16ddb3cce449dc1382aade38dbdcd09771a10be670a02366488b9b31b26eee79e60c446a8bc61336ccf4eb99cb96af09f37feb53d4f9ad34dffde208e4e97a6fd9f09bc4dca1876c9b04d8550f280d21d06f5580407b118",
      "SignatureAlgorithmOID": "1.2.840.113549.1.1.5",
      "Subject": "C=SG, O=GMO GlobalSign Pte Ltd, CN=GlobalSign TSA for MS Authenticode , G2",
      "TBS": {
        "MD5": "acb5170547d76873f1e4ff18ed5de2eb",
        "SHA1": "bd6e261e75b807381bada7287de04d259258a5fa",
        "SHA256": "4783380498acf592286ef2dea0fcc5bdea3f54d5e374d3e3497df9d5f662cfb6"
      },
      "ValidFrom": "2016-05-24 00:00:00",
      "ValidTo": "2027-06-24 00:00:00",
      "Version": 3
    },
    {
      "IsCertificateAuthority": false,
      "SerialNumber": "112158044863e4dc19cf29a85668b7f45842",
      "Signature": "8c35a5b5d3503f50119ab8f99b07a4bb4b71cafaf983206f744545c2997ae1762032fa2d37f4780cfe83bfa999d7bcbd863dc4a51ff39978160e2e191482ae6d7f08e8ffa337c96d8c2d38ddf476a497265a890c1bbf0dee89b1abd32343889a3757732d205ba06525fa8f6e15005405a53e55cef71ac0b6af3a640e4c8aef5e950ab8a8b5c8bcddb2ade96ad9473a3d860ae16fdbe3362cabfd916da089167d906d378dbf4534f7ffb77d87baba29f8f5bbbd9b4b7c127ac170a270dc7a7272d38fdf3bbadbfb448d47e5dd4d310a588666a0d66762e1b3704b1e00e39739190c02f4b981cf2d27ba07d2472ec320edf29e263f26278995d162102968c999b3",
      "SignatureAlgorithmOID": "1.2.840.113549.1.1.5",
      "Subject": "C=TW, ST=Taiwan, L=New Taipei City, O=MICRO,STAR INTERNATIONAL CO., LTD., OU=MICRO,STAR INTERNATIONAL CO., LTD., CN=MICRO,STAR INTERNATIONAL CO., LTD.",
      "TBS": {
        "MD5": "403bb44a62aed1a94bd5df05b3292482",
        "SHA1": "e4a0353e75940ab1e8cbff2f433f186c7f0b0f09",
        "SHA256": "5b81998ed98b343c04134c336e03f3051779eae0e9f882e8339593d18556375d"
      },
      "ValidFrom": "2014-06-03 09:16:15",
      "ValidTo": "2017-09-03 09:16:15",
      "Version": 3
    },
    {
      "IsCertificateAuthority": true,
      "SerialNumber": "610b7f6b000000000019",
      "Signature": "13c56c5e077f3c57ff9b315f3fbd955425c679f92c31034d64694b56d95b976f7cf3f0d024657538639813701613f7a701f1c623e085866c0bf080945a75e87ce41e92b473bfc1b3a7b00bd31884cbcc09a35c9c4f3eb03a9c2d1bc404ef9737966fe5ecbaac6ab3d4e23cdf8b25e7acbc624531dda40a72e41bf8784301ccba3914de5d90aed85acf5eca46815133d5a60e5867d3d8665888169beeb11acaad91138421da9a6e20efda007428bac95ff34d5dc3da25692554ea44bcc39b29331cd63c961f8781c553d72a2733d42e197c08586ddb4e1999a9ea5ff39a9d8c513a5a5cbd2fa908359b54a7db351a521633343aa380046afdb4838cad90cf0c3a6596ec334e1826b849bbeb8192ff134d324b23c733e7b6716b15f69c80e6bcb76cbe41d5033a7133150050743b0e5df996aaed903eab134c809926bc38a5eb0236891db620be83ab10f8199ed76379d4aeb12f6136f94a4ba833c70e7241f9f1b1907eae46efde397b75a0411459041d42bc4788b8130e05fa1df0808dff70c677d84bdc460e231a72d5bfdefeaaae69583cfc5c46e4d5819a8b6e6559771a32a590a6b6649364fd0753c9a0de28ad2a6cc638d181ce98f54019e92c1743a4265fd3443053e41d02baa40a2f16dd7a60275242bbad98372897e4b8d27911e3108c48d5305d0a0c52def588ea8d1a2d67c9f4801484b7850cd16628a5c66f2461",
      "SignatureAlgorithmOID": "1.2.840.113549.1.1.5",
      "Subject": "C=BE, O=GlobalSign nv,sa, OU=Root CA, CN=GlobalSign Root CA",
      "TBS": {
        "MD5": "4798d55be7663a75649cda4dedc686ef",
        "SHA1": "0f1ab2937b245d9466ea6f9bf056a5942e3989cf",
        "SHA256": "ef14ea05bb066ee9f4188196dd69cd769b283ac4d7555db52f5e76922d3456e1"
      },
      "ValidFrom": "2006-05-23 17:00:51",
      "ValidTo": "2016-05-23 17:10:51",
      "Version": 3
    }
  ],
  "CertificatesInfo": "",
  "Signer": [
    {
      "Issuer": "C=BE, O=GlobalSign nv,sa, CN=GlobalSign CodeSigning CA , G2",
      "SerialNumber": "112158044863e4dc19cf29a85668b7f45842",
      "Version": 1
    }
  ],
  "SignerInfo": ""
}
```

{{< /details >}}
-----



[*source*](https://github.com/magicsword-io/LOLDrivers/tree/main/yaml/e32bc3da-4db1-4858-a62c-6fbe4db6afbd.yaml)

*last_updated:* 2023-06-24








{{< /column >}}
{{< /block >}}
