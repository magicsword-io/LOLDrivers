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

{{< button "https://github.com/magicsword-io/LOLDrivers/raw/main/drivers/2d8e4f38b36c334d0a32a7324832501d.bin" "Download" >}}{{< button "https://www.magicsword.io/premium" "Block" "red" >}}
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

{{< button "https://github.com/magicsword-io/LOLDrivers/tree/main/detections/yara/yara-rules_vuln_drivers_strict_renamed.yar" "Renamed" >}}{{< tip >}}for renamed driver files{{< /tip >}} 


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

{{< button "https://github.com/magicsword-io/LOLDrivers/tree/main/detections/sysmon/sysmon_config_vulnerable_hashes.xml" "Alert" >}}{{< tip >}}on hashes{{< /tip >}} 

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
| Creation Timestamp           | 2016-09-30 06:03:17 |
| MD5                | [2d8e4f38b36c334d0a32a7324832501d](https://www.virustotal.com/gui/file/2d8e4f38b36c334d0a32a7324832501d) |
| SHA1               | [f6f11ad2cd2b0cf95ed42324876bee1d83e01775](https://www.virustotal.com/gui/file/f6f11ad2cd2b0cf95ed42324876bee1d83e01775) |
| SHA256             | [01aa278b07b58dc46c84bd0b1b5c8e9ee4e62ea0bf7a695862444af32e87f1fd](https://www.virustotal.com/gui/file/01aa278b07b58dc46c84bd0b1b5c8e9ee4e62ea0bf7a695862444af32e87f1fd) |
| Authentihash MD5   | [538e5e595c61d2ea8defb7b047784734](https://www.virustotal.com/gui/search/authentihash%253A538e5e595c61d2ea8defb7b047784734) |
| Authentihash SHA1  | [4a68c2d7a4c471e062a32c83a36eedb45a619683](https://www.virustotal.com/gui/search/authentihash%253A4a68c2d7a4c471e062a32c83a36eedb45a619683) |
| Authentihash SHA256| [478c36f8af7844a80e24c1822507beef6314519185717ec7ae224a0e04b2f330](https://www.virustotal.com/gui/search/authentihash%253A478c36f8af7844a80e24c1822507beef6314519185717ec7ae224a0e04b2f330) |
| RichPEHeaderHash MD5   | [ebe2ae976914018e88e9fc480e7b6269](https://www.virustotal.com/gui/search/rich_pe_header_hash%253Aebe2ae976914018e88e9fc480e7b6269) |
| RichPEHeaderHash SHA1  | [960715bfbccb53b6c4eccca3b232b25640e15b52](https://www.virustotal.com/gui/search/rich_pe_header_hash%253A960715bfbccb53b6c4eccca3b232b25640e15b52) |
| RichPEHeaderHash SHA256| [d755e9f3cb861f5227319238f1811265e332e36a922b9a25da38b122a791fdfa](https://www.virustotal.com/gui/search/rich_pe_header_hash%253Ad755e9f3cb861f5227319238f1811265e332e36a922b9a25da38b122a791fdfa) |

{{< button "https://github.com/magicsword-io/LOLDrivers/raw/main/drivers/2d8e4f38b36c334d0a32a7324832501d.bin" "Download" >}} 

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
#### Imported Functions
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
#### Exported Functions
{{< details "Expand" >}}

{{< /details >}}

#### Sections
{{< details "Expand" >}}
* .text
* .rdata
* .data
* .pdata
* INIT

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
        "SHA256": "3ca71e85908ff67368e4dc00253f5691b9e6d50c966e7784143d75fb92aa3448",
        "SHA384": "d9d366f9328f2b55ee19a32cc5fd5148b81d764282fe5dc196c872ae249caa51d2c212ef39f33945dfe0cda81925e326"
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
        "SHA256": "cbdc9a0ad785d0c2013211746b42234e18bdc7d54a7a260647badc1c9e712ed4",
        "SHA384": "dcec542f242317863d0b3d23947e17d6982e381003831777b07ed75b46fb18bd0392a89c9beb6862981cd05f3f2fb77b"
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
        "SHA256": "4783380498acf592286ef2dea0fcc5bdea3f54d5e374d3e3497df9d5f662cfb6",
        "SHA384": "4f428f115cf3d008248f15f32007fc7c54bd454e1b48b765776b4c87c23ab8818d8fbcbb3646d35eca012b025260a3b8"
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
        "SHA256": "5b81998ed98b343c04134c336e03f3051779eae0e9f882e8339593d18556375d",
        "SHA384": "db0076cad41a0ef4ea68754ef6905bd5ff772adcb745b05c0060344e43588abc95952dc3ad272f5a8f17b206e4089aca"
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
        "SHA256": "ef14ea05bb066ee9f4188196dd69cd769b283ac4d7555db52f5e76922d3456e1",
        "SHA384": "6e7450a139856aeda6fa6284ff89b3752a9b646e096b4d33dd7e8e727742a2111481531581c0aa2cda0338e22cfdbad3"
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
| Creation Timestamp           | 2016-09-30 06:03:16 |
| MD5                | [0ec361f2fba49c73260af351c39ff9cb](https://www.virustotal.com/gui/file/0ec361f2fba49c73260af351c39ff9cb) |
| SHA1               | [af50109b112995f8c82be8ef3a88be404510cdde](https://www.virustotal.com/gui/file/af50109b112995f8c82be8ef3a88be404510cdde) |
| SHA256             | [cdd2a4575a46bada4837a6153a79c14d60ee3129830717ef09e0e3efd9d00812](https://www.virustotal.com/gui/file/cdd2a4575a46bada4837a6153a79c14d60ee3129830717ef09e0e3efd9d00812) |
| Authentihash MD5   | [63fd0d800cac53db02638349cea2f8e7](https://www.virustotal.com/gui/search/authentihash%253A63fd0d800cac53db02638349cea2f8e7) |
| Authentihash SHA1  | [3856e573765f090afbbb9e5be4c886653402f755](https://www.virustotal.com/gui/search/authentihash%253A3856e573765f090afbbb9e5be4c886653402f755) |
| Authentihash SHA256| [ff8d17761c1645bdd1f0eccc69024907bbbfbe5c60679402b7d02f95b16310fe](https://www.virustotal.com/gui/search/authentihash%253Aff8d17761c1645bdd1f0eccc69024907bbbfbe5c60679402b7d02f95b16310fe) |
| RichPEHeaderHash MD5   | [ef0782d8ffe1c09386ae12bb2a2ca29c](https://www.virustotal.com/gui/search/rich_pe_header_hash%253Aef0782d8ffe1c09386ae12bb2a2ca29c) |
| RichPEHeaderHash SHA1  | [39449f1e1ca8b17755e87827b9a394a4143d5b07](https://www.virustotal.com/gui/search/rich_pe_header_hash%253A39449f1e1ca8b17755e87827b9a394a4143d5b07) |
| RichPEHeaderHash SHA256| [f56fbdad98db55f8a8a7391c059ec563e0f6754624895ec154a2dd9d1fa350d5](https://www.virustotal.com/gui/search/rich_pe_header_hash%253Af56fbdad98db55f8a8a7391c059ec563e0f6754624895ec154a2dd9d1fa350d5) |

{{< button "https://github.com/magicsword-io/LOLDrivers/raw/main/drivers/0ec361f2fba49c73260af351c39ff9cb.bin" "Download" >}} 


#### Imports
{{< details "Expand" >}}
* ntoskrnl.exe
* HAL.dll

{{< /details >}}
#### Imported Functions
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
#### Exported Functions
{{< details "Expand" >}}

{{< /details >}}

#### Sections
{{< details "Expand" >}}
* .text
* .rdata
* .data
* INIT
* .reloc

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
        "SHA256": "3ca71e85908ff67368e4dc00253f5691b9e6d50c966e7784143d75fb92aa3448",
        "SHA384": "d9d366f9328f2b55ee19a32cc5fd5148b81d764282fe5dc196c872ae249caa51d2c212ef39f33945dfe0cda81925e326"
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
        "SHA256": "cbdc9a0ad785d0c2013211746b42234e18bdc7d54a7a260647badc1c9e712ed4",
        "SHA384": "dcec542f242317863d0b3d23947e17d6982e381003831777b07ed75b46fb18bd0392a89c9beb6862981cd05f3f2fb77b"
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
        "SHA256": "4783380498acf592286ef2dea0fcc5bdea3f54d5e374d3e3497df9d5f662cfb6",
        "SHA384": "4f428f115cf3d008248f15f32007fc7c54bd454e1b48b765776b4c87c23ab8818d8fbcbb3646d35eca012b025260a3b8"
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
        "SHA256": "5b81998ed98b343c04134c336e03f3051779eae0e9f882e8339593d18556375d",
        "SHA384": "db0076cad41a0ef4ea68754ef6905bd5ff772adcb745b05c0060344e43588abc95952dc3ad272f5a8f17b206e4089aca"
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
        "SHA256": "ef14ea05bb066ee9f4188196dd69cd769b283ac4d7555db52f5e76922d3456e1",
        "SHA384": "6e7450a139856aeda6fa6284ff89b3752a9b646e096b4d33dd7e8e727742a2111481531581c0aa2cda0338e22cfdbad3"
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
| Creation Timestamp           |  |
| MD5                | [0a2ec9e3e236698185978a5fc76e74e6](https://www.virustotal.com/gui/file/0a2ec9e3e236698185978a5fc76e74e6) |
| SHA1               | [4fe873544c34243826489997a5ff14ed39dd090d](https://www.virustotal.com/gui/file/4fe873544c34243826489997a5ff14ed39dd090d) |
| SHA256             | [f1c8ca232789c2f11a511c8cd95a9f3830dd719cad5aa22cb7c3539ab8cb4dc3](https://www.virustotal.com/gui/file/f1c8ca232789c2f11a511c8cd95a9f3830dd719cad5aa22cb7c3539ab8cb4dc3) |
| Authentihash MD5   | [bcd9f192e2f9321ed549c722f30206e5](https://www.virustotal.com/gui/search/authentihash%253Abcd9f192e2f9321ed549c722f30206e5) |
| Authentihash SHA1  | [8498265d4ca81b83ec1454d9ec013d7a9c0c87bf](https://www.virustotal.com/gui/search/authentihash%253A8498265d4ca81b83ec1454d9ec013d7a9c0c87bf) |
| Authentihash SHA256| [606beced7746cdb684d3a44f41e48713c6bbe5bfb1486c52b5cca815e99d31b4](https://www.virustotal.com/gui/search/authentihash%253A606beced7746cdb684d3a44f41e48713c6bbe5bfb1486c52b5cca815e99d31b4) |

{{< button "https://github.com/magicsword-io/LOLDrivers/raw/main/drivers/0a2ec9e3e236698185978a5fc76e74e6.bin" "Download" >}} 

#### Certificates

{{< details "Expand" >}}

{{< /details >}}
#### Imports
{{< details "Expand" >}}
* ntoskrnl.exe
* HAL.dll

{{< /details >}}
#### Imported Functions
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
#### Exported Functions
{{< details "Expand" >}}

{{< /details >}}

#### Sections
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
        "SHA256": "3ca71e85908ff67368e4dc00253f5691b9e6d50c966e7784143d75fb92aa3448",
        "SHA384": "d9d366f9328f2b55ee19a32cc5fd5148b81d764282fe5dc196c872ae249caa51d2c212ef39f33945dfe0cda81925e326"
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
        "SHA256": "cbdc9a0ad785d0c2013211746b42234e18bdc7d54a7a260647badc1c9e712ed4",
        "SHA384": "dcec542f242317863d0b3d23947e17d6982e381003831777b07ed75b46fb18bd0392a89c9beb6862981cd05f3f2fb77b"
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
        "SHA256": "4783380498acf592286ef2dea0fcc5bdea3f54d5e374d3e3497df9d5f662cfb6",
        "SHA384": "4f428f115cf3d008248f15f32007fc7c54bd454e1b48b765776b4c87c23ab8818d8fbcbb3646d35eca012b025260a3b8"
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
        "SHA256": "5b81998ed98b343c04134c336e03f3051779eae0e9f882e8339593d18556375d",
        "SHA384": "db0076cad41a0ef4ea68754ef6905bd5ff772adcb745b05c0060344e43588abc95952dc3ad272f5a8f17b206e4089aca"
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
        "SHA256": "ef14ea05bb066ee9f4188196dd69cd769b283ac4d7555db52f5e76922d3456e1",
        "SHA384": "6e7450a139856aeda6fa6284ff89b3752a9b646e096b4d33dd7e8e727742a2111481531581c0aa2cda0338e22cfdbad3"
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
| Filename           |  |
| Creation Timestamp           | 2005-05-25 00:39:12 |
| MD5                | [9a5a35112c4f8016abcc6363b44d3385](https://www.virustotal.com/gui/file/9a5a35112c4f8016abcc6363b44d3385) |
| SHA1               | [8800a33a37c640922ce6a2996cd822ed4603b8bb](https://www.virustotal.com/gui/file/8800a33a37c640922ce6a2996cd822ed4603b8bb) |
| SHA256             | [ad215185dc833c54d523350ef3dbc10b3357a88fc4dde00281d9af81ea0764d5](https://www.virustotal.com/gui/file/ad215185dc833c54d523350ef3dbc10b3357a88fc4dde00281d9af81ea0764d5) |
| Authentihash MD5   | [a17d227444e090ff69e24fcb6d43162b](https://www.virustotal.com/gui/search/authentihash%253Aa17d227444e090ff69e24fcb6d43162b) |
| Authentihash SHA1  | [43d3a3c1f7b14cfcc051cae2534dbbbb4c7fc120](https://www.virustotal.com/gui/search/authentihash%253A43d3a3c1f7b14cfcc051cae2534dbbbb4c7fc120) |
| Authentihash SHA256| [b8eb26b6f79020ae988e4fb752dc06e1b6779749bf4f8df2872fc2b92bab8020](https://www.virustotal.com/gui/search/authentihash%253Ab8eb26b6f79020ae988e4fb752dc06e1b6779749bf4f8df2872fc2b92bab8020) |
| RichPEHeaderHash MD5   | [deb9c1e252f598099d70d2b33a313da3](https://www.virustotal.com/gui/search/rich_pe_header_hash%253Adeb9c1e252f598099d70d2b33a313da3) |
| RichPEHeaderHash SHA1  | [f0c2801e0091ed6f5e10ea7045e911aa90030290](https://www.virustotal.com/gui/search/rich_pe_header_hash%253Af0c2801e0091ed6f5e10ea7045e911aa90030290) |
| RichPEHeaderHash SHA256| [914fb9761d50c3fa2ecf9fbd8af3735f9b8d6c4903e067c8af9546e79b6f22c7](https://www.virustotal.com/gui/search/rich_pe_header_hash%253A914fb9761d50c3fa2ecf9fbd8af3735f9b8d6c4903e067c8af9546e79b6f22c7) |

{{< button "https://github.com/magicsword-io/LOLDrivers/raw/main/drivers/9a5a35112c4f8016abcc6363b44d3385.bin" "Download" >}} 

#### Certificates

{{< details "Expand" >}}
###### Certificate 0400000000012019c19066
| Field                             | Value                      |
|-----------------------------------|----------------------------|
| ToBeSigned (TBS) MD5              | 42023b9487cafe46c1b6a49c369a362e  |
| ToBeSigned (TBS) SHA1             | 7c7b524d269334b9f073c32e888e09544c6acd98 |
| ToBeSigned (TBS) SHA256           | b7126567833f3daa4085ff41e73112daad3d1e3808a942c1936520e2d6c46c78 |
| Subject                           | OU=Timestamping CA, O=GlobalSign, CN=GlobalSign Timestamping CA |
| ValidFrom                         | 2009-03-18 11:00:00 |
| ValidTo                           | 2028-01-28 12:00:00 |
| Signature                         | 5df6cb2b0d0140849f857a43706ae0c5e7aa0600d76713c9089131654f14a8a905dc389e6aa0300abd8dc78028ee4245ca94f3de5845a9803204f5595c6a70003927944df5b44634e81c5331b2b35416e9cc42abd5d959301cfb462725b88723b1e8758824831ec876377b01494548a4ede25dd27c9ca2dc2dba105a126265abae00c710343bcb72bd14240cdcc37627b4a7fee15829f20e169f91391d89a6e60f1c878ce258ac927e243eaaec14e73a33348bc63bac83ab0f14627aba1a2d4d4b1bc530f00b92797d3c78e0f8e6d215965999392b3061e8b8f8c0a1e9221411787dc4dc89bec0bb94e172aeebb540404fef171e585ed0a88996ac9228e9babf |
| SignatureAlgorithmOID             | 1.2.840.113549.1.1.5 |
| IsCertificateAuthority            | True |
| SerialNumber                      | 0400000000012019c19066 |
| Version                           | 3 |
###### Certificate 01000000000125b0b4cc01
| Field                             | Value                      |
|-----------------------------------|----------------------------|
| ToBeSigned (TBS) MD5              | e3369c8e5aec0504b3a50455f615d9f9  |
| ToBeSigned (TBS) SHA1             | 13c244a894b40ecd18aaf97c362f20385bd005a7 |
| ToBeSigned (TBS) SHA256           | 26da721a670c72836926032fee6920118bfb9bff89cc8d0ce30d9452c33f2532 |
| Subject                           | C=BE, O=GlobalSign NV, CN=GlobalSign Time Stamping Authority |
| ValidFrom                         | 2009-12-21 09:32:56 |
| ValidTo                           | 2020-12-22 09:32:56 |
| Signature                         | bc89ecfee63655935c79d4117a86808f17b693b26d9b91a1561811c655eaf608edad9b9ef52b81c8bbdd607b1b47991e6d403e1d80c213d58e04052fdbe7ae529e688472a1e54a603cf89bd52f46d8c3b2b79353ac9b6c432424d1f1fce9562e3411581843eaefff34746ca0c06c7fad031969881e9560cabbbd0cbb76efc724b081c63831cf36ad0c38b89020849b2e8f28b99ff6ca9427cdac396157e0e3955a9c769230f5dea6973d721c2a6032a8334d8635338a5cf3a4fdf7062ce16b4b30f5cbd34362f841b9de7d20cb058c8e2cf65f35fd338d42896508362ca389f45a858bb0b97bdb6ccba1f8d20e1bbb977cd12779be9d7c3be6a75634d8c991a9 |
| SignatureAlgorithmOID             | 1.2.840.113549.1.1.5 |
| IsCertificateAuthority            | False |
| SerialNumber                      | 01000000000125b0b4cc01 |
| Version                           | 3 |
###### Certificate 79c32d7ddd2458cf2eabe5b1b5c5290f
| Field                             | Value                      |
|-----------------------------------|----------------------------|
| ToBeSigned (TBS) MD5              | 5ba772ec00357ae706016510775c7a00  |
| ToBeSigned (TBS) SHA1             | eeb31b244ea14abae1e947ecdca0d6ae4720031b |
| ToBeSigned (TBS) SHA256           | c8e707c2615c26ac78ed06b42dd20bc8ff82bc5e02ddafe2c9af85755097691b |
| Subject                           | C=US, ST=California, L=Brea, O=EVGA, OU=Digital ID Class 3 , Microsoft Software Validation v2, CN=EVGA |
| ValidFrom                         | 2010-04-14 00:00:00 |
| ValidTo                           | 2012-04-15 23:59:59 |
| Signature                         | ba96817224593697c9135d803c5fc87767f2a7ed8fa0aa18eab4030a3daed18c55fb7eda8835d0488d18136c0db39d8edf3224790842cdf8580b35324631de717e9279d28d605285615341aeea10a73005d59cbe3138bebfa5003cbcf2971249423d820d6d252a18bf4dd124a1ac0c2f66015cbb23690e1b0fb9d5ce3f047663f1fb6735e54f09cfb6162da298bdc956490586cfdadee74a5766c187223e19112d22f59c7f3f325449afebc42689ec4c9399bd0d97397c37230804a4e5bc17e904008aa9c5972e2332302e57648006d057c9ed8c6384fb42d138971c86079b155c202733b837b3eef122c866ce3e6d8a8d9f1685e618cc2466d623d212b73df6 |
| SignatureAlgorithmOID             | 1.2.840.113549.1.1.5 |
| IsCertificateAuthority            | False |
| SerialNumber                      | 79c32d7ddd2458cf2eabe5b1b5c5290f |
| Version                           | 3 |
###### Certificate 655226e1b22e18e1590f2985ac22e75c
| Field                             | Value                      |
|-----------------------------------|----------------------------|
| ToBeSigned (TBS) MD5              | 650704c342850095f3288eaf791147d4  |
| ToBeSigned (TBS) SHA1             | 4cdc38c800761463749c3cbd94a12f32e49877bf |
| ToBeSigned (TBS) SHA256           | 07b8f662558ec85b71b43a79c6e94698144f4ced2308af21e7ba1e5d461da214 |
| Subject                           | C=US, O=VeriSign, Inc., OU=VeriSign Trust Network, OU=Terms of use at https://www.verisign.com/rpa (c)09, CN=VeriSign Class 3 Code Signing 2009,2 CA |
| ValidFrom                         | 2009-05-21 00:00:00 |
| ValidTo                           | 2019-05-20 23:59:59 |
| Signature                         | 8b03c0dd94d841a26169b015a878c730c6903c7e42f724b6e4837317047f04109ca1e2fa812febc0ca44e772e050b6551020836e9692e49a516ab43731dca52deb8c00c71d4fe74d32ba85f84ebefa675565f06abe7aca64381a101078457631f3867a030f60c2b35d9df68b6676821b59e183e5bd49a53856e5de41770e580f |
| SignatureAlgorithmOID             | 1.2.840.113549.1.1.5 |
| IsCertificateAuthority            | True |
| SerialNumber                      | 655226e1b22e18e1590f2985ac22e75c |
| Version                           | 3 |
###### Certificate 610c120600000000001b
| Field                             | Value                      |
|-----------------------------------|----------------------------|
| ToBeSigned (TBS) MD5              | 53c41bc1164e09e0cd1617a5bf913efd  |
| ToBeSigned (TBS) SHA1             | 93c03aac8951d494ecd5696b1c08658541b18727 |
| ToBeSigned (TBS) SHA256           | 40bddadac24dc61ca4fb5cab2a2bc5d876bc36808311039a7a3e1a4066f7489b |
| Subject                           | C=US, O=VeriSign, Inc., OU=Class 3 Public Primary Certification Authority |
| ValidFrom                         | 2006-05-23 17:01:29 |
| ValidTo                           | 2016-05-23 17:11:29 |
| Signature                         | 01e446b33b457f7513877e5f43de468ecb8abdb64741bccccc7491d8ce395195a4a6b547c0efd2da7b8f5711f4328c7ccd3fee42da04214af7c843884a6f5cca14fc4bd19f4cbdd4556ecc02be0da6888f8609baa425bde8b0f0fa8b714e67b0cb82a8d78e55f737ebf03e88efe4e08afd1c6e2e61414875b4b02c1d28d8490fd715f02473253ccc880cde284c6554fe5eae8cea19ad2c51b29b3a47f53c80350117e24987d6544afb4bab07bcbf7d79cfbf35005cbb9ecffc82891b39a05197b6dec0b307ff449644c0342a195cabeef03bec294eb513c537857e75d5b4d60d066eb5d26c237167eaf1718eaf4e74aa0cf9ecbf4c58fa5e909b6d39cb86883f8b1ca81632d5fe6db9f1f8b3ead791f6364778c0272a15c768d6f4c5fc4f4ec8673f102d409ff11ec96148e7a703fc31730cf04688fe56da492995ef09daa3e5beef60ecd954a0599c28bd54ef66157f874c84dba60e95672e517b3439b641c28c846826dc240209e7818e0a972defeea7b998a60f818dc710b5e1ed982f486f53854964789bec5dac970b5526c3efba8dc8d1a52f5a7f936b611a339b18b8a26210de24ea76e12f43ebecdd7c12342489da2855aee5754e312b6763b6a8d7ab730a03cec5ea593fc7eb2a45aea8625b2f009939abb45f73c308ec80118f470e8f2a1343e191066255bbffba3da9a93d260faeca7d628b155589d694344dd665 |
| SignatureAlgorithmOID             | 1.2.840.113549.1.1.5 |
| IsCertificateAuthority            | True |
| SerialNumber                      | 610c120600000000001b |
| Version                           | 3 |

{{< /details >}}
#### Imports
{{< details "Expand" >}}
* ntoskrnl.exe
* HAL.dll

{{< /details >}}
#### Imported Functions
{{< details "Expand" >}}
* RtlInitUnicodeString
* ZwClose
* ZwMapViewOfSection
* ObReferenceObjectByHandle
* ZwOpenSection
* IoDeleteSymbolicLink
* IofCompleteRequest
* MmIsAddressValid
* ZwUnmapViewOfSection
* IoCreateSymbolicLink
* IoCreateDevice
* __C_specific_handler
* IoDeleteDevice
* HalTranslateBusAddress

{{< /details >}}
#### Exported Functions
{{< details "Expand" >}}

{{< /details >}}

#### Sections
{{< details "Expand" >}}
* .text
* .rdata
* .data
* .pdata
* INIT

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
        "SHA256": "3ca71e85908ff67368e4dc00253f5691b9e6d50c966e7784143d75fb92aa3448",
        "SHA384": "d9d366f9328f2b55ee19a32cc5fd5148b81d764282fe5dc196c872ae249caa51d2c212ef39f33945dfe0cda81925e326"
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
        "SHA256": "cbdc9a0ad785d0c2013211746b42234e18bdc7d54a7a260647badc1c9e712ed4",
        "SHA384": "dcec542f242317863d0b3d23947e17d6982e381003831777b07ed75b46fb18bd0392a89c9beb6862981cd05f3f2fb77b"
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
        "SHA256": "4783380498acf592286ef2dea0fcc5bdea3f54d5e374d3e3497df9d5f662cfb6",
        "SHA384": "4f428f115cf3d008248f15f32007fc7c54bd454e1b48b765776b4c87c23ab8818d8fbcbb3646d35eca012b025260a3b8"
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
        "SHA256": "5b81998ed98b343c04134c336e03f3051779eae0e9f882e8339593d18556375d",
        "SHA384": "db0076cad41a0ef4ea68754ef6905bd5ff772adcb745b05c0060344e43588abc95952dc3ad272f5a8f17b206e4089aca"
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
        "SHA256": "ef14ea05bb066ee9f4188196dd69cd769b283ac4d7555db52f5e76922d3456e1",
        "SHA384": "6e7450a139856aeda6fa6284ff89b3752a9b646e096b4d33dd7e8e727742a2111481531581c0aa2cda0338e22cfdbad3"
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
| Filename           |  |
| Creation Timestamp           | 2005-05-25 00:39:12 |
| MD5                | [a5afd20e34bcd634ebd25b3ab2ff3403](https://www.virustotal.com/gui/file/a5afd20e34bcd634ebd25b3ab2ff3403) |
| SHA1               | [fb349c3cde212ef33a11a9d58a622dc58dff3f74](https://www.virustotal.com/gui/file/fb349c3cde212ef33a11a9d58a622dc58dff3f74) |
| SHA256             | [d9a2bf0f5ba185170441f003dc46fbb570e1c9fdf2132ab7de28b87ba7ad1a0c](https://www.virustotal.com/gui/file/d9a2bf0f5ba185170441f003dc46fbb570e1c9fdf2132ab7de28b87ba7ad1a0c) |
| Authentihash MD5   | [a17d227444e090ff69e24fcb6d43162b](https://www.virustotal.com/gui/search/authentihash%253Aa17d227444e090ff69e24fcb6d43162b) |
| Authentihash SHA1  | [43d3a3c1f7b14cfcc051cae2534dbbbb4c7fc120](https://www.virustotal.com/gui/search/authentihash%253A43d3a3c1f7b14cfcc051cae2534dbbbb4c7fc120) |
| Authentihash SHA256| [b8eb26b6f79020ae988e4fb752dc06e1b6779749bf4f8df2872fc2b92bab8020](https://www.virustotal.com/gui/search/authentihash%253Ab8eb26b6f79020ae988e4fb752dc06e1b6779749bf4f8df2872fc2b92bab8020) |
| RichPEHeaderHash MD5   | [deb9c1e252f598099d70d2b33a313da3](https://www.virustotal.com/gui/search/rich_pe_header_hash%253Adeb9c1e252f598099d70d2b33a313da3) |
| RichPEHeaderHash SHA1  | [f0c2801e0091ed6f5e10ea7045e911aa90030290](https://www.virustotal.com/gui/search/rich_pe_header_hash%253Af0c2801e0091ed6f5e10ea7045e911aa90030290) |
| RichPEHeaderHash SHA256| [914fb9761d50c3fa2ecf9fbd8af3735f9b8d6c4903e067c8af9546e79b6f22c7](https://www.virustotal.com/gui/search/rich_pe_header_hash%253A914fb9761d50c3fa2ecf9fbd8af3735f9b8d6c4903e067c8af9546e79b6f22c7) |

{{< button "https://github.com/magicsword-io/LOLDrivers/raw/main/drivers/a5afd20e34bcd634ebd25b3ab2ff3403.bin" "Download" >}} 

#### Certificates

{{< details "Expand" >}}
###### Certificate 040000000000f97faa2e1e
| Field                             | Value                      |
|-----------------------------------|----------------------------|
| ToBeSigned (TBS) MD5              | 59466cb0c1788b2f251fce3495837102  |
| ToBeSigned (TBS) SHA1             | c5cfc5f6a131a3a77c3905c9893c99bb1b2baa0b |
| ToBeSigned (TBS) SHA256           | eedda02668f7636eeec69429a7164cc47ca3de0539122d37f5b8078df7ee56db |
| Subject                           | CN=GlobalSign RootSign Partners CA, OU=RootSign Partners CA, O=GlobalSign nv,sa, C=BE |
| ValidFrom                         | 2003-12-16 13:00:00 |
| ValidTo                           | 2014-01-27 11:00:00 |
| Signature                         | 5c2f2e674a26b3e7b53f353cdda003ed569af9443752163065c7d14ea20f8db7b6b6678ee74cec8d95bee6cea7227874acd7f87499b3f7ce8b1338d596cc8d76c52f38b23aae61be0b8799e321626423398d84f6858df777ffb03806f07ec1485fb5ee582606660522749283a7dbb5f992e3e8c3192c2e63efbb1fdff9f70747660d0789977ef8332c9ecbae143df11cdfa3f179afc8928f9471c4d144c554db1eb50b0aa942a3afd643391dee8f9398585bbe6e9c0bf563ec5e99c2f954fa010746da0db06424cf8ed1061d4f3ca26377455ba4bc5fb080bb31e00b54015c161d724ed52a6947d11b667e5f016ef135916be02efeb045d81627b5c58bc2da53 |
| SignatureAlgorithmOID             | 1.2.840.113549.1.1.5 |
| IsCertificateAuthority            | True |
| SerialNumber                      | 040000000000f97faa2e1e |
| Version                           | 3 |
###### Certificate 0400000000011092eb8295
| Field                             | Value                      |
|-----------------------------------|----------------------------|
| ToBeSigned (TBS) MD5              | 11d73a3638fc78e0bac6c459feadcc42  |
| ToBeSigned (TBS) SHA1             | 6636f7dcf81b370b919966f9063295ec84422f91 |
| ToBeSigned (TBS) SHA256           | 1eb5fc1d2e3254b1e3c4587a6efed87ee65306525e684b4cfa4b51893cfe86a3 |
| Subject                           | O=GlobalSign, CN=GlobalSign Time Stamping Authority, emailAddress=timestampinfo@globalsign.com |
| ValidFrom                         | 2007-02-05 09:00:00 |
| ValidTo                           | 2014-01-27 09:00:00 |
| Signature                         | 649b07caaccc411e37ef6f349cb5e8ca48f9daeafaf7172e5cad193b7311ec5adbfd7b213161c092515bb166b07c64d8fe10b471a8bc9e75379c5f6ff2da0437b8ecc003e256b7785995581d7a7c3e18d74c32bdf91ee723457fdee08d65825b45fd64c66fc3d7ea12411d0c395ef696f8c3cd9e1fff51886976988b8eb42788821ad63c7aabb04eb73ee8d434d2c1a439533cb2747b15373054a6ebb924cc2f084b4364f14aaf8d9ce8546cb2dbdc3bb1c722849f558e72a8b2a8f6f0ff03c996ebab8273dabe45561936fdba6cbc71f0d3c7c376d7e4bce2a1a67200cfbdb200ed92aa39ab09d16e3953862ad43b517398b754e9972d9977ee123e3642257f |
| SignatureAlgorithmOID             | 1.2.840.113549.1.1.5 |
| IsCertificateAuthority            | True |
| SerialNumber                      | 0400000000011092eb8295 |
| Version                           | 3 |
###### Certificate 4191a15a3978dfcf496566381d4c75c2
| Field                             | Value                      |
|-----------------------------------|----------------------------|
| ToBeSigned (TBS) MD5              | 41011f8d0e7c7a6408334ca387914c61  |
| ToBeSigned (TBS) SHA1             | c7fc1727f5b75a6421a1f95c73bbdb23580c48e5 |
| ToBeSigned (TBS) SHA256           | 88dd3952638ee82738c03168e6fd863fe4eab1059ee5e2926ad8cb587c255dc0 |
| Subject                           | C=US, O=VeriSign, Inc., OU=VeriSign Trust Network, OU=Terms of use at https://www.verisign.com/rpa (c)04, CN=VeriSign Class 3 Code Signing 2004 CA |
| ValidFrom                         | 2004-07-16 00:00:00 |
| ValidTo                           | 2014-07-15 23:59:59 |
| Signature                         | ae3a17b84a7b55fa6455ec40a4ed494190999c89bcaf2e1dca7823f91c190f7feb68bc32d98838dedc3fd389b43fb18296f1a45abaed2e26d3de7c016e000a00a4069211480940f91c1879672324e0bbd5e150ae1bf50edde02e81cd80a36c524f9175558aba22f2d2ea4175882f63557d1e545a9559cad93481c05f5ef67ab5 |
| SignatureAlgorithmOID             | 1.2.840.113549.1.1.5 |
| IsCertificateAuthority            | True |
| SerialNumber                      | 4191a15a3978dfcf496566381d4c75c2 |
| Version                           | 3 |
###### Certificate 546ea040bf5075ce0a5c01d4c6ded19d
| Field                             | Value                      |
|-----------------------------------|----------------------------|
| ToBeSigned (TBS) MD5              | 8f51b4e16b87e1cc89b9d0c997227546  |
| ToBeSigned (TBS) SHA1             | 8f3cdd2b86ae03653f0612911a2f01a9dca49a22 |
| ToBeSigned (TBS) SHA256           | c7f57b7287c808d2713aba9e368fe387b5825bfbda1bd1824f374beaa8e30be9 |
| Subject                           | C=US, ST=California, L=Brea, O=EVGA, OU=Digital ID Class 3 , Microsoft Software Validation v2, CN=EVGA |
| ValidFrom                         | 2008-04-16 00:00:00 |
| ValidTo                           | 2010-04-16 23:59:59 |
| Signature                         | 13a3b8caa6bd8d63308898b0c92b79574e5d122a3ecba9758ec450b7c8c848ee5bc486db6370a8dfeb4c96c2c25512f7a3e759cc57a4d92f1a44fba15ca0c1156d22c49251b4e6a01bb93e4a62522ee5af4286c759c01c66fa5ce4452a4f112d03560bfa9737a3d0f3008b3cc48f2042b4428643f1efb4b99a34d0545c9934f1a6f35819e469430b74ba475a2135660948131cf24c9b1fb84580a1fd63eb3218d282e4f7caf77f4adbecb51e4b8237937eda0b7fcc20fc2273bf38282ee69ae6730b21c5314bcdc3f2e3a1e6f6c3ccb2139800f69d3f2fadc235080214f1c9b11e6a8f2165a45e15cca3c3542c2bac7225208a84828456d2e93cfe8315b092a1 |
| SignatureAlgorithmOID             | 1.2.840.113549.1.1.5 |
| IsCertificateAuthority            | False |
| SerialNumber                      | 546ea040bf5075ce0a5c01d4c6ded19d |
| Version                           | 3 |
###### Certificate 610c120600000000001b
| Field                             | Value                      |
|-----------------------------------|----------------------------|
| ToBeSigned (TBS) MD5              | 53c41bc1164e09e0cd1617a5bf913efd  |
| ToBeSigned (TBS) SHA1             | 93c03aac8951d494ecd5696b1c08658541b18727 |
| ToBeSigned (TBS) SHA256           | 40bddadac24dc61ca4fb5cab2a2bc5d876bc36808311039a7a3e1a4066f7489b |
| Subject                           | C=US, O=VeriSign, Inc., OU=Class 3 Public Primary Certification Authority |
| ValidFrom                         | 2006-05-23 17:01:29 |
| ValidTo                           | 2016-05-23 17:11:29 |
| Signature                         | 01e446b33b457f7513877e5f43de468ecb8abdb64741bccccc7491d8ce395195a4a6b547c0efd2da7b8f5711f4328c7ccd3fee42da04214af7c843884a6f5cca14fc4bd19f4cbdd4556ecc02be0da6888f8609baa425bde8b0f0fa8b714e67b0cb82a8d78e55f737ebf03e88efe4e08afd1c6e2e61414875b4b02c1d28d8490fd715f02473253ccc880cde284c6554fe5eae8cea19ad2c51b29b3a47f53c80350117e24987d6544afb4bab07bcbf7d79cfbf35005cbb9ecffc82891b39a05197b6dec0b307ff449644c0342a195cabeef03bec294eb513c537857e75d5b4d60d066eb5d26c237167eaf1718eaf4e74aa0cf9ecbf4c58fa5e909b6d39cb86883f8b1ca81632d5fe6db9f1f8b3ead791f6364778c0272a15c768d6f4c5fc4f4ec8673f102d409ff11ec96148e7a703fc31730cf04688fe56da492995ef09daa3e5beef60ecd954a0599c28bd54ef66157f874c84dba60e95672e517b3439b641c28c846826dc240209e7818e0a972defeea7b998a60f818dc710b5e1ed982f486f53854964789bec5dac970b5526c3efba8dc8d1a52f5a7f936b611a339b18b8a26210de24ea76e12f43ebecdd7c12342489da2855aee5754e312b6763b6a8d7ab730a03cec5ea593fc7eb2a45aea8625b2f009939abb45f73c308ec80118f470e8f2a1343e191066255bbffba3da9a93d260faeca7d628b155589d694344dd665 |
| SignatureAlgorithmOID             | 1.2.840.113549.1.1.5 |
| IsCertificateAuthority            | True |
| SerialNumber                      | 610c120600000000001b |
| Version                           | 3 |

{{< /details >}}
#### Imports
{{< details "Expand" >}}
* ntoskrnl.exe
* HAL.dll

{{< /details >}}
#### Imported Functions
{{< details "Expand" >}}
* RtlInitUnicodeString
* ZwClose
* ZwMapViewOfSection
* ObReferenceObjectByHandle
* ZwOpenSection
* IoDeleteSymbolicLink
* IofCompleteRequest
* MmIsAddressValid
* ZwUnmapViewOfSection
* IoCreateSymbolicLink
* IoCreateDevice
* __C_specific_handler
* IoDeleteDevice
* HalTranslateBusAddress

{{< /details >}}
#### Exported Functions
{{< details "Expand" >}}

{{< /details >}}

#### Sections
{{< details "Expand" >}}
* .text
* .rdata
* .data
* .pdata
* INIT

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
        "SHA256": "3ca71e85908ff67368e4dc00253f5691b9e6d50c966e7784143d75fb92aa3448",
        "SHA384": "d9d366f9328f2b55ee19a32cc5fd5148b81d764282fe5dc196c872ae249caa51d2c212ef39f33945dfe0cda81925e326"
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
        "SHA256": "cbdc9a0ad785d0c2013211746b42234e18bdc7d54a7a260647badc1c9e712ed4",
        "SHA384": "dcec542f242317863d0b3d23947e17d6982e381003831777b07ed75b46fb18bd0392a89c9beb6862981cd05f3f2fb77b"
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
        "SHA256": "4783380498acf592286ef2dea0fcc5bdea3f54d5e374d3e3497df9d5f662cfb6",
        "SHA384": "4f428f115cf3d008248f15f32007fc7c54bd454e1b48b765776b4c87c23ab8818d8fbcbb3646d35eca012b025260a3b8"
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
        "SHA256": "5b81998ed98b343c04134c336e03f3051779eae0e9f882e8339593d18556375d",
        "SHA384": "db0076cad41a0ef4ea68754ef6905bd5ff772adcb745b05c0060344e43588abc95952dc3ad272f5a8f17b206e4089aca"
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
        "SHA256": "ef14ea05bb066ee9f4188196dd69cd769b283ac4d7555db52f5e76922d3456e1",
        "SHA384": "6e7450a139856aeda6fa6284ff89b3752a9b646e096b4d33dd7e8e727742a2111481531581c0aa2cda0338e22cfdbad3"
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
| Filename           |  |
| Creation Timestamp           | 2011-09-06 06:24:50 |
| MD5                | [6691e873354f1914692df104718eebad](https://www.virustotal.com/gui/file/6691e873354f1914692df104718eebad) |
| SHA1               | [d3d2fe8080f0b18465520785f3a955e1a24ae462](https://www.virustotal.com/gui/file/d3d2fe8080f0b18465520785f3a955e1a24ae462) |
| SHA256             | [22e125c284a55eb730f03ec27b87ab84cf897f9d046b91c76bea2b5809fd51c5](https://www.virustotal.com/gui/file/22e125c284a55eb730f03ec27b87ab84cf897f9d046b91c76bea2b5809fd51c5) |
| Authentihash MD5   | [55466195f0b2f4afc4243b43a806e6d9](https://www.virustotal.com/gui/search/authentihash%253A55466195f0b2f4afc4243b43a806e6d9) |
| Authentihash SHA1  | [38b353d8480885de5dcf299deca99ce4f26a1d20](https://www.virustotal.com/gui/search/authentihash%253A38b353d8480885de5dcf299deca99ce4f26a1d20) |
| Authentihash SHA256| [5182caf10de9cec0740ecde5a081c21cdc100d7eb328ffe6f3f63183889fec6b](https://www.virustotal.com/gui/search/authentihash%253A5182caf10de9cec0740ecde5a081c21cdc100d7eb328ffe6f3f63183889fec6b) |
| RichPEHeaderHash MD5   | [59080883b71fd56bbf10ec0ae4b6bdd4](https://www.virustotal.com/gui/search/rich_pe_header_hash%253A59080883b71fd56bbf10ec0ae4b6bdd4) |
| RichPEHeaderHash SHA1  | [503a36a225568553cc9b05f63b3506c6ff21e12e](https://www.virustotal.com/gui/search/rich_pe_header_hash%253A503a36a225568553cc9b05f63b3506c6ff21e12e) |
| RichPEHeaderHash SHA256| [bc812d4ddc3ecfbf38c4d0d185e368fc58bac6e07f722db032bf6303daa7c946](https://www.virustotal.com/gui/search/rich_pe_header_hash%253Abc812d4ddc3ecfbf38c4d0d185e368fc58bac6e07f722db032bf6303daa7c946) |

{{< button "https://github.com/magicsword-io/LOLDrivers/raw/main/drivers/6691e873354f1914692df104718eebad.bin" "Download" >}} 

#### Certificates

{{< details "Expand" >}}
###### Certificate 0400000000012019c19066
| Field                             | Value                      |
|-----------------------------------|----------------------------|
| ToBeSigned (TBS) MD5              | 42023b9487cafe46c1b6a49c369a362e  |
| ToBeSigned (TBS) SHA1             | 7c7b524d269334b9f073c32e888e09544c6acd98 |
| ToBeSigned (TBS) SHA256           | b7126567833f3daa4085ff41e73112daad3d1e3808a942c1936520e2d6c46c78 |
| Subject                           | OU=Timestamping CA, O=GlobalSign, CN=GlobalSign Timestamping CA |
| ValidFrom                         | 2009-03-18 11:00:00 |
| ValidTo                           | 2028-01-28 12:00:00 |
| Signature                         | 5df6cb2b0d0140849f857a43706ae0c5e7aa0600d76713c9089131654f14a8a905dc389e6aa0300abd8dc78028ee4245ca94f3de5845a9803204f5595c6a70003927944df5b44634e81c5331b2b35416e9cc42abd5d959301cfb462725b88723b1e8758824831ec876377b01494548a4ede25dd27c9ca2dc2dba105a126265abae00c710343bcb72bd14240cdcc37627b4a7fee15829f20e169f91391d89a6e60f1c878ce258ac927e243eaaec14e73a33348bc63bac83ab0f14627aba1a2d4d4b1bc530f00b92797d3c78e0f8e6d215965999392b3061e8b8f8c0a1e9221411787dc4dc89bec0bb94e172aeebb540404fef171e585ed0a88996ac9228e9babf |
| SignatureAlgorithmOID             | 1.2.840.113549.1.1.5 |
| IsCertificateAuthority            | True |
| SerialNumber                      | 0400000000012019c19066 |
| Version                           | 3 |
###### Certificate 01000000000125b0b4cc01
| Field                             | Value                      |
|-----------------------------------|----------------------------|
| ToBeSigned (TBS) MD5              | e3369c8e5aec0504b3a50455f615d9f9  |
| ToBeSigned (TBS) SHA1             | 13c244a894b40ecd18aaf97c362f20385bd005a7 |
| ToBeSigned (TBS) SHA256           | 26da721a670c72836926032fee6920118bfb9bff89cc8d0ce30d9452c33f2532 |
| Subject                           | C=BE, O=GlobalSign NV, CN=GlobalSign Time Stamping Authority |
| ValidFrom                         | 2009-12-21 09:32:56 |
| ValidTo                           | 2020-12-22 09:32:56 |
| Signature                         | bc89ecfee63655935c79d4117a86808f17b693b26d9b91a1561811c655eaf608edad9b9ef52b81c8bbdd607b1b47991e6d403e1d80c213d58e04052fdbe7ae529e688472a1e54a603cf89bd52f46d8c3b2b79353ac9b6c432424d1f1fce9562e3411581843eaefff34746ca0c06c7fad031969881e9560cabbbd0cbb76efc724b081c63831cf36ad0c38b89020849b2e8f28b99ff6ca9427cdac396157e0e3955a9c769230f5dea6973d721c2a6032a8334d8635338a5cf3a4fdf7062ce16b4b30f5cbd34362f841b9de7d20cb058c8e2cf65f35fd338d42896508362ca389f45a858bb0b97bdb6ccba1f8d20e1bbb977cd12779be9d7c3be6a75634d8c991a9 |
| SignatureAlgorithmOID             | 1.2.840.113549.1.1.5 |
| IsCertificateAuthority            | False |
| SerialNumber                      | 01000000000125b0b4cc01 |
| Version                           | 3 |
###### Certificate 250ce8e030612e9f2b89f7054d7cf8fd
| Field                             | Value                      |
|-----------------------------------|----------------------------|
| ToBeSigned (TBS) MD5              | 918d9eb6a6cd36c531eceb926170a7e1  |
| ToBeSigned (TBS) SHA1             | 0ae95700d65e6f59715aa47048993ca7858e676a |
| ToBeSigned (TBS) SHA256           | 47c46e6eaa3780eace3d0d891346cd373359d246b21a957219dbab4c8f37c166 |
| Subject                           | C=US, O=VeriSign, Inc., OU=VeriSign Trust Network, OU=(c) 2006 VeriSign, Inc. , For authorized use only, CN=VeriSign Class 3 Public Primary Certification Authority , G5 |
| ValidFrom                         | 2006-11-08 00:00:00 |
| ValidTo                           | 2021-11-07 23:59:59 |
| Signature                         | 1302ddf8e88600f25af8f8200c59886207cecef74ef9bb59a198e5e138dd4ebc6618d3adeb18f20dc96d3e4a9420c33cbabd6554c6af44b310ad2c6b3eabd707b6b88163c5f95e2ee52a67cecd330c2ad7895603231fb3bee83a0859b4ec4535f78a5bff66cf50afc66d578d1978b7b9a2d157ea1f9a4bafbac98e127ec6bdff |
| SignatureAlgorithmOID             | 1.2.840.113549.1.1.5 |
| IsCertificateAuthority            | True |
| SerialNumber                      | 250ce8e030612e9f2b89f7054d7cf8fd |
| Version                           | 3 |
###### Certificate 610c120600000000001b
| Field                             | Value                      |
|-----------------------------------|----------------------------|
| ToBeSigned (TBS) MD5              | 53c41bc1164e09e0cd1617a5bf913efd  |
| ToBeSigned (TBS) SHA1             | 93c03aac8951d494ecd5696b1c08658541b18727 |
| ToBeSigned (TBS) SHA256           | 40bddadac24dc61ca4fb5cab2a2bc5d876bc36808311039a7a3e1a4066f7489b |
| Subject                           | C=US, O=VeriSign, Inc., OU=Class 3 Public Primary Certification Authority |
| ValidFrom                         | 2006-05-23 17:01:29 |
| ValidTo                           | 2016-05-23 17:11:29 |
| Signature                         | 01e446b33b457f7513877e5f43de468ecb8abdb64741bccccc7491d8ce395195a4a6b547c0efd2da7b8f5711f4328c7ccd3fee42da04214af7c843884a6f5cca14fc4bd19f4cbdd4556ecc02be0da6888f8609baa425bde8b0f0fa8b714e67b0cb82a8d78e55f737ebf03e88efe4e08afd1c6e2e61414875b4b02c1d28d8490fd715f02473253ccc880cde284c6554fe5eae8cea19ad2c51b29b3a47f53c80350117e24987d6544afb4bab07bcbf7d79cfbf35005cbb9ecffc82891b39a05197b6dec0b307ff449644c0342a195cabeef03bec294eb513c537857e75d5b4d60d066eb5d26c237167eaf1718eaf4e74aa0cf9ecbf4c58fa5e909b6d39cb86883f8b1ca81632d5fe6db9f1f8b3ead791f6364778c0272a15c768d6f4c5fc4f4ec8673f102d409ff11ec96148e7a703fc31730cf04688fe56da492995ef09daa3e5beef60ecd954a0599c28bd54ef66157f874c84dba60e95672e517b3439b641c28c846826dc240209e7818e0a972defeea7b998a60f818dc710b5e1ed982f486f53854964789bec5dac970b5526c3efba8dc8d1a52f5a7f936b611a339b18b8a26210de24ea76e12f43ebecdd7c12342489da2855aee5754e312b6763b6a8d7ab730a03cec5ea593fc7eb2a45aea8625b2f009939abb45f73c308ec80118f470e8f2a1343e191066255bbffba3da9a93d260faeca7d628b155589d694344dd665 |
| SignatureAlgorithmOID             | 1.2.840.113549.1.1.5 |
| IsCertificateAuthority            | True |
| SerialNumber                      | 610c120600000000001b |
| Version                           | 3 |
###### Certificate 26d7f5563eb3e42a81f7c715fcd2799d
| Field                             | Value                      |
|-----------------------------------|----------------------------|
| ToBeSigned (TBS) MD5              | e994671d8d440b7739cdd9775bbca72f  |
| ToBeSigned (TBS) SHA1             | ea9446b39b968aa6953e1bf74a36435759b3d2e3 |
| ToBeSigned (TBS) SHA256           | 37a9886a67c19d644c74505801f947d3b2756a5540cbd89a0c8d500511cb838d |
| Subject                           | C=US, ST=California, L=Brea, O=EVGA, OU=Digital ID Class 3 , Microsoft Software Validation v2, CN=EVGA |
| ValidFrom                         | 2012-02-29 00:00:00 |
| ValidTo                           | 2014-04-15 23:59:59 |
| Signature                         | d77d9dbdeea6d42d15335f0b16117963e49d39b89af081160a467824968e611f0947648a83375d1380acca6cbe1117f488b428bcab943b20dad29e72dd48e7d01b080b12c444727bba415a098799abd5e5673dd7eda91787920c3cc53aac068e0a3d1faef713c14f7ec6f68f69a33340b70e81083db2ce1daf45592063235d05232a1d3d8052fc3f102b2b71e1c46275eff3d4a2dc5ee0d5d727d180da205055a3709a32ad6bd11317b1f109e7c5eca18c8293c937ba6f76278bc306c10f0f1bc865cedcf2c2331e7a7f5c0bcfab91786b8ff848d8ef9c59937ddb94f6369884162148f882e7d0c4343538ad23aeb6ab3db0f6d125a8e2fe3889e40ed66bc66a |
| SignatureAlgorithmOID             | 1.2.840.113549.1.1.5 |
| IsCertificateAuthority            | False |
| SerialNumber                      | 26d7f5563eb3e42a81f7c715fcd2799d |
| Version                           | 3 |
###### Certificate 5200e5aa2556fc1a86ed96c9d44b33c7
| Field                             | Value                      |
|-----------------------------------|----------------------------|
| ToBeSigned (TBS) MD5              | b30c31a572b0409383ed3fbe17e56e81  |
| ToBeSigned (TBS) SHA1             | 4843a82ed3b1f2bfbee9671960e1940c942f688d |
| ToBeSigned (TBS) SHA256           | 03cda47a6e654ed85d932714fc09ce4874600eda29ec6628cfbaeb155cab78c9 |
| Subject                           | C=US, O=VeriSign, Inc., OU=VeriSign Trust Network, OU=Terms of use at https://www.verisign.com/rpa (c)10, CN=VeriSign Class 3 Code Signing 2010 CA |
| ValidFrom                         | 2010-02-08 00:00:00 |
| ValidTo                           | 2020-02-07 23:59:59 |
| Signature                         | 5622e634a4c461cb48b901ad56a8640fd98c91c4bbcc0ce5ad7aa0227fdf47384a2d6cd17f711a7cec70a9b1f04fe40f0c53fa155efe749849248581261c911447b04c638cbba134d4c645e80d85267303d0a98c646ddc7192e645056015595139fc58146bfed4a4ed796b080c4172e737220609be23e93f449a1ee9619dccb1905cfc3dd28dac423d6536d4b43d40288f9b10cf2326cc4b20cb901f5d8c4c34ca3cd8e537d66fa520bd34eb26d9ae0de7c59af7a1b42191336f86e858bb257c740e58fe751b633fce317c9b8f1b969ec55376845b9cad91faaced93ba5dc82153c2825363af120d5087111b3d5452968a2c9c3d921a089a052ec793a54891d3 |
| SignatureAlgorithmOID             | 1.2.840.113549.1.1.5 |
| IsCertificateAuthority            | True |
| SerialNumber                      | 5200e5aa2556fc1a86ed96c9d44b33c7 |
| Version                           | 3 |

{{< /details >}}
#### Imports
{{< details "Expand" >}}
* ntoskrnl.exe
* HAL.dll

{{< /details >}}
#### Imported Functions
{{< details "Expand" >}}
* RtlInitUnicodeString
* ZwClose
* ZwMapViewOfSection
* ObReferenceObjectByHandle
* ZwOpenSection
* MmMapIoSpace
* IoDeleteSymbolicLink
* IofCompleteRequest
* ZwUnmapViewOfSection
* MmUnmapIoSpace
* IoCreateSymbolicLink
* IoCreateDevice
* __C_specific_handler
* IoDeleteDevice
* HalTranslateBusAddress

{{< /details >}}
#### Exported Functions
{{< details "Expand" >}}

{{< /details >}}

#### Sections
{{< details "Expand" >}}
* .text
* .rdata
* .data
* .pdata
* INIT

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
        "SHA256": "3ca71e85908ff67368e4dc00253f5691b9e6d50c966e7784143d75fb92aa3448",
        "SHA384": "d9d366f9328f2b55ee19a32cc5fd5148b81d764282fe5dc196c872ae249caa51d2c212ef39f33945dfe0cda81925e326"
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
        "SHA256": "cbdc9a0ad785d0c2013211746b42234e18bdc7d54a7a260647badc1c9e712ed4",
        "SHA384": "dcec542f242317863d0b3d23947e17d6982e381003831777b07ed75b46fb18bd0392a89c9beb6862981cd05f3f2fb77b"
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
        "SHA256": "4783380498acf592286ef2dea0fcc5bdea3f54d5e374d3e3497df9d5f662cfb6",
        "SHA384": "4f428f115cf3d008248f15f32007fc7c54bd454e1b48b765776b4c87c23ab8818d8fbcbb3646d35eca012b025260a3b8"
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
        "SHA256": "5b81998ed98b343c04134c336e03f3051779eae0e9f882e8339593d18556375d",
        "SHA384": "db0076cad41a0ef4ea68754ef6905bd5ff772adcb745b05c0060344e43588abc95952dc3ad272f5a8f17b206e4089aca"
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
        "SHA256": "ef14ea05bb066ee9f4188196dd69cd769b283ac4d7555db52f5e76922d3456e1",
        "SHA384": "6e7450a139856aeda6fa6284ff89b3752a9b646e096b4d33dd7e8e727742a2111481531581c0aa2cda0338e22cfdbad3"
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
| Filename           |  |
| Creation Timestamp           | 2005-05-25 00:39:12 |
| MD5                | [b994110f069d197222508a724d8afdac](https://www.virustotal.com/gui/file/b994110f069d197222508a724d8afdac) |
| SHA1               | [47df454cb030c1f4f7002d46b1308a32b03148e7](https://www.virustotal.com/gui/file/47df454cb030c1f4f7002d46b1308a32b03148e7) |
| SHA256             | [dd2c1aa4e14c825f3715891bfa2b6264650a794f366d5f73ed1ef1d79ff0dbf9](https://www.virustotal.com/gui/file/dd2c1aa4e14c825f3715891bfa2b6264650a794f366d5f73ed1ef1d79ff0dbf9) |
| Authentihash MD5   | [a17d227444e090ff69e24fcb6d43162b](https://www.virustotal.com/gui/search/authentihash%253Aa17d227444e090ff69e24fcb6d43162b) |
| Authentihash SHA1  | [43d3a3c1f7b14cfcc051cae2534dbbbb4c7fc120](https://www.virustotal.com/gui/search/authentihash%253A43d3a3c1f7b14cfcc051cae2534dbbbb4c7fc120) |
| Authentihash SHA256| [b8eb26b6f79020ae988e4fb752dc06e1b6779749bf4f8df2872fc2b92bab8020](https://www.virustotal.com/gui/search/authentihash%253Ab8eb26b6f79020ae988e4fb752dc06e1b6779749bf4f8df2872fc2b92bab8020) |
| RichPEHeaderHash MD5   | [deb9c1e252f598099d70d2b33a313da3](https://www.virustotal.com/gui/search/rich_pe_header_hash%253Adeb9c1e252f598099d70d2b33a313da3) |
| RichPEHeaderHash SHA1  | [f0c2801e0091ed6f5e10ea7045e911aa90030290](https://www.virustotal.com/gui/search/rich_pe_header_hash%253Af0c2801e0091ed6f5e10ea7045e911aa90030290) |
| RichPEHeaderHash SHA256| [914fb9761d50c3fa2ecf9fbd8af3735f9b8d6c4903e067c8af9546e79b6f22c7](https://www.virustotal.com/gui/search/rich_pe_header_hash%253A914fb9761d50c3fa2ecf9fbd8af3735f9b8d6c4903e067c8af9546e79b6f22c7) |

{{< button "https://github.com/magicsword-io/LOLDrivers/raw/main/drivers/b994110f069d197222508a724d8afdac.bin" "Download" >}} 

#### Certificates

{{< details "Expand" >}}
###### Certificate 0400000000012019c19066
| Field                             | Value                      |
|-----------------------------------|----------------------------|
| ToBeSigned (TBS) MD5              | 42023b9487cafe46c1b6a49c369a362e  |
| ToBeSigned (TBS) SHA1             | 7c7b524d269334b9f073c32e888e09544c6acd98 |
| ToBeSigned (TBS) SHA256           | b7126567833f3daa4085ff41e73112daad3d1e3808a942c1936520e2d6c46c78 |
| Subject                           | OU=Timestamping CA, O=GlobalSign, CN=GlobalSign Timestamping CA |
| ValidFrom                         | 2009-03-18 11:00:00 |
| ValidTo                           | 2028-01-28 12:00:00 |
| Signature                         | 5df6cb2b0d0140849f857a43706ae0c5e7aa0600d76713c9089131654f14a8a905dc389e6aa0300abd8dc78028ee4245ca94f3de5845a9803204f5595c6a70003927944df5b44634e81c5331b2b35416e9cc42abd5d959301cfb462725b88723b1e8758824831ec876377b01494548a4ede25dd27c9ca2dc2dba105a126265abae00c710343bcb72bd14240cdcc37627b4a7fee15829f20e169f91391d89a6e60f1c878ce258ac927e243eaaec14e73a33348bc63bac83ab0f14627aba1a2d4d4b1bc530f00b92797d3c78e0f8e6d215965999392b3061e8b8f8c0a1e9221411787dc4dc89bec0bb94e172aeebb540404fef171e585ed0a88996ac9228e9babf |
| SignatureAlgorithmOID             | 1.2.840.113549.1.1.5 |
| IsCertificateAuthority            | True |
| SerialNumber                      | 0400000000012019c19066 |
| Version                           | 3 |
###### Certificate 01000000000125b0b4cc01
| Field                             | Value                      |
|-----------------------------------|----------------------------|
| ToBeSigned (TBS) MD5              | e3369c8e5aec0504b3a50455f615d9f9  |
| ToBeSigned (TBS) SHA1             | 13c244a894b40ecd18aaf97c362f20385bd005a7 |
| ToBeSigned (TBS) SHA256           | 26da721a670c72836926032fee6920118bfb9bff89cc8d0ce30d9452c33f2532 |
| Subject                           | C=BE, O=GlobalSign NV, CN=GlobalSign Time Stamping Authority |
| ValidFrom                         | 2009-12-21 09:32:56 |
| ValidTo                           | 2020-12-22 09:32:56 |
| Signature                         | bc89ecfee63655935c79d4117a86808f17b693b26d9b91a1561811c655eaf608edad9b9ef52b81c8bbdd607b1b47991e6d403e1d80c213d58e04052fdbe7ae529e688472a1e54a603cf89bd52f46d8c3b2b79353ac9b6c432424d1f1fce9562e3411581843eaefff34746ca0c06c7fad031969881e9560cabbbd0cbb76efc724b081c63831cf36ad0c38b89020849b2e8f28b99ff6ca9427cdac396157e0e3955a9c769230f5dea6973d721c2a6032a8334d8635338a5cf3a4fdf7062ce16b4b30f5cbd34362f841b9de7d20cb058c8e2cf65f35fd338d42896508362ca389f45a858bb0b97bdb6ccba1f8d20e1bbb977cd12779be9d7c3be6a75634d8c991a9 |
| SignatureAlgorithmOID             | 1.2.840.113549.1.1.5 |
| IsCertificateAuthority            | False |
| SerialNumber                      | 01000000000125b0b4cc01 |
| Version                           | 3 |
###### Certificate 79c32d7ddd2458cf2eabe5b1b5c5290f
| Field                             | Value                      |
|-----------------------------------|----------------------------|
| ToBeSigned (TBS) MD5              | 5ba772ec00357ae706016510775c7a00  |
| ToBeSigned (TBS) SHA1             | eeb31b244ea14abae1e947ecdca0d6ae4720031b |
| ToBeSigned (TBS) SHA256           | c8e707c2615c26ac78ed06b42dd20bc8ff82bc5e02ddafe2c9af85755097691b |
| Subject                           | C=US, ST=California, L=Brea, O=EVGA, OU=Digital ID Class 3 , Microsoft Software Validation v2, CN=EVGA |
| ValidFrom                         | 2010-04-14 00:00:00 |
| ValidTo                           | 2012-04-15 23:59:59 |
| Signature                         | ba96817224593697c9135d803c5fc87767f2a7ed8fa0aa18eab4030a3daed18c55fb7eda8835d0488d18136c0db39d8edf3224790842cdf8580b35324631de717e9279d28d605285615341aeea10a73005d59cbe3138bebfa5003cbcf2971249423d820d6d252a18bf4dd124a1ac0c2f66015cbb23690e1b0fb9d5ce3f047663f1fb6735e54f09cfb6162da298bdc956490586cfdadee74a5766c187223e19112d22f59c7f3f325449afebc42689ec4c9399bd0d97397c37230804a4e5bc17e904008aa9c5972e2332302e57648006d057c9ed8c6384fb42d138971c86079b155c202733b837b3eef122c866ce3e6d8a8d9f1685e618cc2466d623d212b73df6 |
| SignatureAlgorithmOID             | 1.2.840.113549.1.1.5 |
| IsCertificateAuthority            | False |
| SerialNumber                      | 79c32d7ddd2458cf2eabe5b1b5c5290f |
| Version                           | 3 |
###### Certificate 655226e1b22e18e1590f2985ac22e75c
| Field                             | Value                      |
|-----------------------------------|----------------------------|
| ToBeSigned (TBS) MD5              | 650704c342850095f3288eaf791147d4  |
| ToBeSigned (TBS) SHA1             | 4cdc38c800761463749c3cbd94a12f32e49877bf |
| ToBeSigned (TBS) SHA256           | 07b8f662558ec85b71b43a79c6e94698144f4ced2308af21e7ba1e5d461da214 |
| Subject                           | C=US, O=VeriSign, Inc., OU=VeriSign Trust Network, OU=Terms of use at https://www.verisign.com/rpa (c)09, CN=VeriSign Class 3 Code Signing 2009,2 CA |
| ValidFrom                         | 2009-05-21 00:00:00 |
| ValidTo                           | 2019-05-20 23:59:59 |
| Signature                         | 8b03c0dd94d841a26169b015a878c730c6903c7e42f724b6e4837317047f04109ca1e2fa812febc0ca44e772e050b6551020836e9692e49a516ab43731dca52deb8c00c71d4fe74d32ba85f84ebefa675565f06abe7aca64381a101078457631f3867a030f60c2b35d9df68b6676821b59e183e5bd49a53856e5de41770e580f |
| SignatureAlgorithmOID             | 1.2.840.113549.1.1.5 |
| IsCertificateAuthority            | True |
| SerialNumber                      | 655226e1b22e18e1590f2985ac22e75c |
| Version                           | 3 |
###### Certificate 610c120600000000001b
| Field                             | Value                      |
|-----------------------------------|----------------------------|
| ToBeSigned (TBS) MD5              | 53c41bc1164e09e0cd1617a5bf913efd  |
| ToBeSigned (TBS) SHA1             | 93c03aac8951d494ecd5696b1c08658541b18727 |
| ToBeSigned (TBS) SHA256           | 40bddadac24dc61ca4fb5cab2a2bc5d876bc36808311039a7a3e1a4066f7489b |
| Subject                           | C=US, O=VeriSign, Inc., OU=Class 3 Public Primary Certification Authority |
| ValidFrom                         | 2006-05-23 17:01:29 |
| ValidTo                           | 2016-05-23 17:11:29 |
| Signature                         | 01e446b33b457f7513877e5f43de468ecb8abdb64741bccccc7491d8ce395195a4a6b547c0efd2da7b8f5711f4328c7ccd3fee42da04214af7c843884a6f5cca14fc4bd19f4cbdd4556ecc02be0da6888f8609baa425bde8b0f0fa8b714e67b0cb82a8d78e55f737ebf03e88efe4e08afd1c6e2e61414875b4b02c1d28d8490fd715f02473253ccc880cde284c6554fe5eae8cea19ad2c51b29b3a47f53c80350117e24987d6544afb4bab07bcbf7d79cfbf35005cbb9ecffc82891b39a05197b6dec0b307ff449644c0342a195cabeef03bec294eb513c537857e75d5b4d60d066eb5d26c237167eaf1718eaf4e74aa0cf9ecbf4c58fa5e909b6d39cb86883f8b1ca81632d5fe6db9f1f8b3ead791f6364778c0272a15c768d6f4c5fc4f4ec8673f102d409ff11ec96148e7a703fc31730cf04688fe56da492995ef09daa3e5beef60ecd954a0599c28bd54ef66157f874c84dba60e95672e517b3439b641c28c846826dc240209e7818e0a972defeea7b998a60f818dc710b5e1ed982f486f53854964789bec5dac970b5526c3efba8dc8d1a52f5a7f936b611a339b18b8a26210de24ea76e12f43ebecdd7c12342489da2855aee5754e312b6763b6a8d7ab730a03cec5ea593fc7eb2a45aea8625b2f009939abb45f73c308ec80118f470e8f2a1343e191066255bbffba3da9a93d260faeca7d628b155589d694344dd665 |
| SignatureAlgorithmOID             | 1.2.840.113549.1.1.5 |
| IsCertificateAuthority            | True |
| SerialNumber                      | 610c120600000000001b |
| Version                           | 3 |

{{< /details >}}
#### Imports
{{< details "Expand" >}}
* ntoskrnl.exe
* HAL.dll

{{< /details >}}
#### Imported Functions
{{< details "Expand" >}}
* RtlInitUnicodeString
* ZwClose
* ZwMapViewOfSection
* ObReferenceObjectByHandle
* ZwOpenSection
* IoDeleteSymbolicLink
* IofCompleteRequest
* MmIsAddressValid
* ZwUnmapViewOfSection
* IoCreateSymbolicLink
* IoCreateDevice
* __C_specific_handler
* IoDeleteDevice
* HalTranslateBusAddress

{{< /details >}}
#### Exported Functions
{{< details "Expand" >}}

{{< /details >}}

#### Sections
{{< details "Expand" >}}
* .text
* .rdata
* .data
* .pdata
* INIT

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
        "SHA256": "3ca71e85908ff67368e4dc00253f5691b9e6d50c966e7784143d75fb92aa3448",
        "SHA384": "d9d366f9328f2b55ee19a32cc5fd5148b81d764282fe5dc196c872ae249caa51d2c212ef39f33945dfe0cda81925e326"
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
        "SHA256": "cbdc9a0ad785d0c2013211746b42234e18bdc7d54a7a260647badc1c9e712ed4",
        "SHA384": "dcec542f242317863d0b3d23947e17d6982e381003831777b07ed75b46fb18bd0392a89c9beb6862981cd05f3f2fb77b"
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
        "SHA256": "4783380498acf592286ef2dea0fcc5bdea3f54d5e374d3e3497df9d5f662cfb6",
        "SHA384": "4f428f115cf3d008248f15f32007fc7c54bd454e1b48b765776b4c87c23ab8818d8fbcbb3646d35eca012b025260a3b8"
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
        "SHA256": "5b81998ed98b343c04134c336e03f3051779eae0e9f882e8339593d18556375d",
        "SHA384": "db0076cad41a0ef4ea68754ef6905bd5ff772adcb745b05c0060344e43588abc95952dc3ad272f5a8f17b206e4089aca"
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
        "SHA256": "ef14ea05bb066ee9f4188196dd69cd769b283ac4d7555db52f5e76922d3456e1",
        "SHA384": "6e7450a139856aeda6fa6284ff89b3752a9b646e096b4d33dd7e8e727742a2111481531581c0aa2cda0338e22cfdbad3"
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
| Filename           |  |
| Creation Timestamp           | 2005-05-25 00:39:12 |
| MD5                | [4b194021d6bd6650cbd1aed9370b2329](https://www.virustotal.com/gui/file/4b194021d6bd6650cbd1aed9370b2329) |
| SHA1               | [c8a4a64b412fd8ef079661db4a4a7cd7394514ca](https://www.virustotal.com/gui/file/c8a4a64b412fd8ef079661db4a4a7cd7394514ca) |
| SHA256             | [96df0b01eeba3e6e50759d400df380db27f0d0e34812d0374d22ac1758230452](https://www.virustotal.com/gui/file/96df0b01eeba3e6e50759d400df380db27f0d0e34812d0374d22ac1758230452) |
| Authentihash MD5   | [a17d227444e090ff69e24fcb6d43162b](https://www.virustotal.com/gui/search/authentihash%253Aa17d227444e090ff69e24fcb6d43162b) |
| Authentihash SHA1  | [43d3a3c1f7b14cfcc051cae2534dbbbb4c7fc120](https://www.virustotal.com/gui/search/authentihash%253A43d3a3c1f7b14cfcc051cae2534dbbbb4c7fc120) |
| Authentihash SHA256| [b8eb26b6f79020ae988e4fb752dc06e1b6779749bf4f8df2872fc2b92bab8020](https://www.virustotal.com/gui/search/authentihash%253Ab8eb26b6f79020ae988e4fb752dc06e1b6779749bf4f8df2872fc2b92bab8020) |
| RichPEHeaderHash MD5   | [deb9c1e252f598099d70d2b33a313da3](https://www.virustotal.com/gui/search/rich_pe_header_hash%253Adeb9c1e252f598099d70d2b33a313da3) |
| RichPEHeaderHash SHA1  | [f0c2801e0091ed6f5e10ea7045e911aa90030290](https://www.virustotal.com/gui/search/rich_pe_header_hash%253Af0c2801e0091ed6f5e10ea7045e911aa90030290) |
| RichPEHeaderHash SHA256| [914fb9761d50c3fa2ecf9fbd8af3735f9b8d6c4903e067c8af9546e79b6f22c7](https://www.virustotal.com/gui/search/rich_pe_header_hash%253A914fb9761d50c3fa2ecf9fbd8af3735f9b8d6c4903e067c8af9546e79b6f22c7) |

{{< button "https://github.com/magicsword-io/LOLDrivers/raw/main/drivers/4b194021d6bd6650cbd1aed9370b2329.bin" "Download" >}} 

#### Certificates

{{< details "Expand" >}}
###### Certificate 040000000000f97faa2e1e
| Field                             | Value                      |
|-----------------------------------|----------------------------|
| ToBeSigned (TBS) MD5              | 59466cb0c1788b2f251fce3495837102  |
| ToBeSigned (TBS) SHA1             | c5cfc5f6a131a3a77c3905c9893c99bb1b2baa0b |
| ToBeSigned (TBS) SHA256           | eedda02668f7636eeec69429a7164cc47ca3de0539122d37f5b8078df7ee56db |
| Subject                           | CN=GlobalSign RootSign Partners CA, OU=RootSign Partners CA, O=GlobalSign nv,sa, C=BE |
| ValidFrom                         | 2003-12-16 13:00:00 |
| ValidTo                           | 2014-01-27 11:00:00 |
| Signature                         | 5c2f2e674a26b3e7b53f353cdda003ed569af9443752163065c7d14ea20f8db7b6b6678ee74cec8d95bee6cea7227874acd7f87499b3f7ce8b1338d596cc8d76c52f38b23aae61be0b8799e321626423398d84f6858df777ffb03806f07ec1485fb5ee582606660522749283a7dbb5f992e3e8c3192c2e63efbb1fdff9f70747660d0789977ef8332c9ecbae143df11cdfa3f179afc8928f9471c4d144c554db1eb50b0aa942a3afd643391dee8f9398585bbe6e9c0bf563ec5e99c2f954fa010746da0db06424cf8ed1061d4f3ca26377455ba4bc5fb080bb31e00b54015c161d724ed52a6947d11b667e5f016ef135916be02efeb045d81627b5c58bc2da53 |
| SignatureAlgorithmOID             | 1.2.840.113549.1.1.5 |
| IsCertificateAuthority            | True |
| SerialNumber                      | 040000000000f97faa2e1e |
| Version                           | 3 |
###### Certificate 0400000000011092eb8295
| Field                             | Value                      |
|-----------------------------------|----------------------------|
| ToBeSigned (TBS) MD5              | 11d73a3638fc78e0bac6c459feadcc42  |
| ToBeSigned (TBS) SHA1             | 6636f7dcf81b370b919966f9063295ec84422f91 |
| ToBeSigned (TBS) SHA256           | 1eb5fc1d2e3254b1e3c4587a6efed87ee65306525e684b4cfa4b51893cfe86a3 |
| Subject                           | O=GlobalSign, CN=GlobalSign Time Stamping Authority, emailAddress=timestampinfo@globalsign.com |
| ValidFrom                         | 2007-02-05 09:00:00 |
| ValidTo                           | 2014-01-27 09:00:00 |
| Signature                         | 649b07caaccc411e37ef6f349cb5e8ca48f9daeafaf7172e5cad193b7311ec5adbfd7b213161c092515bb166b07c64d8fe10b471a8bc9e75379c5f6ff2da0437b8ecc003e256b7785995581d7a7c3e18d74c32bdf91ee723457fdee08d65825b45fd64c66fc3d7ea12411d0c395ef696f8c3cd9e1fff51886976988b8eb42788821ad63c7aabb04eb73ee8d434d2c1a439533cb2747b15373054a6ebb924cc2f084b4364f14aaf8d9ce8546cb2dbdc3bb1c722849f558e72a8b2a8f6f0ff03c996ebab8273dabe45561936fdba6cbc71f0d3c7c376d7e4bce2a1a67200cfbdb200ed92aa39ab09d16e3953862ad43b517398b754e9972d9977ee123e3642257f |
| SignatureAlgorithmOID             | 1.2.840.113549.1.1.5 |
| IsCertificateAuthority            | True |
| SerialNumber                      | 0400000000011092eb8295 |
| Version                           | 3 |
###### Certificate 4191a15a3978dfcf496566381d4c75c2
| Field                             | Value                      |
|-----------------------------------|----------------------------|
| ToBeSigned (TBS) MD5              | 41011f8d0e7c7a6408334ca387914c61  |
| ToBeSigned (TBS) SHA1             | c7fc1727f5b75a6421a1f95c73bbdb23580c48e5 |
| ToBeSigned (TBS) SHA256           | 88dd3952638ee82738c03168e6fd863fe4eab1059ee5e2926ad8cb587c255dc0 |
| Subject                           | C=US, O=VeriSign, Inc., OU=VeriSign Trust Network, OU=Terms of use at https://www.verisign.com/rpa (c)04, CN=VeriSign Class 3 Code Signing 2004 CA |
| ValidFrom                         | 2004-07-16 00:00:00 |
| ValidTo                           | 2014-07-15 23:59:59 |
| Signature                         | ae3a17b84a7b55fa6455ec40a4ed494190999c89bcaf2e1dca7823f91c190f7feb68bc32d98838dedc3fd389b43fb18296f1a45abaed2e26d3de7c016e000a00a4069211480940f91c1879672324e0bbd5e150ae1bf50edde02e81cd80a36c524f9175558aba22f2d2ea4175882f63557d1e545a9559cad93481c05f5ef67ab5 |
| SignatureAlgorithmOID             | 1.2.840.113549.1.1.5 |
| IsCertificateAuthority            | True |
| SerialNumber                      | 4191a15a3978dfcf496566381d4c75c2 |
| Version                           | 3 |
###### Certificate 546ea040bf5075ce0a5c01d4c6ded19d
| Field                             | Value                      |
|-----------------------------------|----------------------------|
| ToBeSigned (TBS) MD5              | 8f51b4e16b87e1cc89b9d0c997227546  |
| ToBeSigned (TBS) SHA1             | 8f3cdd2b86ae03653f0612911a2f01a9dca49a22 |
| ToBeSigned (TBS) SHA256           | c7f57b7287c808d2713aba9e368fe387b5825bfbda1bd1824f374beaa8e30be9 |
| Subject                           | C=US, ST=California, L=Brea, O=EVGA, OU=Digital ID Class 3 , Microsoft Software Validation v2, CN=EVGA |
| ValidFrom                         | 2008-04-16 00:00:00 |
| ValidTo                           | 2010-04-16 23:59:59 |
| Signature                         | 13a3b8caa6bd8d63308898b0c92b79574e5d122a3ecba9758ec450b7c8c848ee5bc486db6370a8dfeb4c96c2c25512f7a3e759cc57a4d92f1a44fba15ca0c1156d22c49251b4e6a01bb93e4a62522ee5af4286c759c01c66fa5ce4452a4f112d03560bfa9737a3d0f3008b3cc48f2042b4428643f1efb4b99a34d0545c9934f1a6f35819e469430b74ba475a2135660948131cf24c9b1fb84580a1fd63eb3218d282e4f7caf77f4adbecb51e4b8237937eda0b7fcc20fc2273bf38282ee69ae6730b21c5314bcdc3f2e3a1e6f6c3ccb2139800f69d3f2fadc235080214f1c9b11e6a8f2165a45e15cca3c3542c2bac7225208a84828456d2e93cfe8315b092a1 |
| SignatureAlgorithmOID             | 1.2.840.113549.1.1.5 |
| IsCertificateAuthority            | False |
| SerialNumber                      | 546ea040bf5075ce0a5c01d4c6ded19d |
| Version                           | 3 |
###### Certificate 610c120600000000001b
| Field                             | Value                      |
|-----------------------------------|----------------------------|
| ToBeSigned (TBS) MD5              | 53c41bc1164e09e0cd1617a5bf913efd  |
| ToBeSigned (TBS) SHA1             | 93c03aac8951d494ecd5696b1c08658541b18727 |
| ToBeSigned (TBS) SHA256           | 40bddadac24dc61ca4fb5cab2a2bc5d876bc36808311039a7a3e1a4066f7489b |
| Subject                           | C=US, O=VeriSign, Inc., OU=Class 3 Public Primary Certification Authority |
| ValidFrom                         | 2006-05-23 17:01:29 |
| ValidTo                           | 2016-05-23 17:11:29 |
| Signature                         | 01e446b33b457f7513877e5f43de468ecb8abdb64741bccccc7491d8ce395195a4a6b547c0efd2da7b8f5711f4328c7ccd3fee42da04214af7c843884a6f5cca14fc4bd19f4cbdd4556ecc02be0da6888f8609baa425bde8b0f0fa8b714e67b0cb82a8d78e55f737ebf03e88efe4e08afd1c6e2e61414875b4b02c1d28d8490fd715f02473253ccc880cde284c6554fe5eae8cea19ad2c51b29b3a47f53c80350117e24987d6544afb4bab07bcbf7d79cfbf35005cbb9ecffc82891b39a05197b6dec0b307ff449644c0342a195cabeef03bec294eb513c537857e75d5b4d60d066eb5d26c237167eaf1718eaf4e74aa0cf9ecbf4c58fa5e909b6d39cb86883f8b1ca81632d5fe6db9f1f8b3ead791f6364778c0272a15c768d6f4c5fc4f4ec8673f102d409ff11ec96148e7a703fc31730cf04688fe56da492995ef09daa3e5beef60ecd954a0599c28bd54ef66157f874c84dba60e95672e517b3439b641c28c846826dc240209e7818e0a972defeea7b998a60f818dc710b5e1ed982f486f53854964789bec5dac970b5526c3efba8dc8d1a52f5a7f936b611a339b18b8a26210de24ea76e12f43ebecdd7c12342489da2855aee5754e312b6763b6a8d7ab730a03cec5ea593fc7eb2a45aea8625b2f009939abb45f73c308ec80118f470e8f2a1343e191066255bbffba3da9a93d260faeca7d628b155589d694344dd665 |
| SignatureAlgorithmOID             | 1.2.840.113549.1.1.5 |
| IsCertificateAuthority            | True |
| SerialNumber                      | 610c120600000000001b |
| Version                           | 3 |

{{< /details >}}
#### Imports
{{< details "Expand" >}}
* ntoskrnl.exe
* HAL.dll

{{< /details >}}
#### Imported Functions
{{< details "Expand" >}}
* RtlInitUnicodeString
* ZwClose
* ZwMapViewOfSection
* ObReferenceObjectByHandle
* ZwOpenSection
* IoDeleteSymbolicLink
* IofCompleteRequest
* MmIsAddressValid
* ZwUnmapViewOfSection
* IoCreateSymbolicLink
* IoCreateDevice
* __C_specific_handler
* IoDeleteDevice
* HalTranslateBusAddress

{{< /details >}}
#### Exported Functions
{{< details "Expand" >}}

{{< /details >}}

#### Sections
{{< details "Expand" >}}
* .text
* .rdata
* .data
* .pdata
* INIT

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
        "SHA256": "3ca71e85908ff67368e4dc00253f5691b9e6d50c966e7784143d75fb92aa3448",
        "SHA384": "d9d366f9328f2b55ee19a32cc5fd5148b81d764282fe5dc196c872ae249caa51d2c212ef39f33945dfe0cda81925e326"
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
        "SHA256": "cbdc9a0ad785d0c2013211746b42234e18bdc7d54a7a260647badc1c9e712ed4",
        "SHA384": "dcec542f242317863d0b3d23947e17d6982e381003831777b07ed75b46fb18bd0392a89c9beb6862981cd05f3f2fb77b"
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
        "SHA256": "4783380498acf592286ef2dea0fcc5bdea3f54d5e374d3e3497df9d5f662cfb6",
        "SHA384": "4f428f115cf3d008248f15f32007fc7c54bd454e1b48b765776b4c87c23ab8818d8fbcbb3646d35eca012b025260a3b8"
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
        "SHA256": "5b81998ed98b343c04134c336e03f3051779eae0e9f882e8339593d18556375d",
        "SHA384": "db0076cad41a0ef4ea68754ef6905bd5ff772adcb745b05c0060344e43588abc95952dc3ad272f5a8f17b206e4089aca"
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
        "SHA256": "ef14ea05bb066ee9f4188196dd69cd769b283ac4d7555db52f5e76922d3456e1",
        "SHA384": "6e7450a139856aeda6fa6284ff89b3752a9b646e096b4d33dd7e8e727742a2111481531581c0aa2cda0338e22cfdbad3"
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
| Filename           |  |
| Creation Timestamp           | 2013-03-10 23:32:06 |
| MD5                | [6b16512bffe88146a7915f749bd81641](https://www.virustotal.com/gui/file/6b16512bffe88146a7915f749bd81641) |
| SHA1               | [fad014ec98529644b5db5388d96bc4f9b77dcdc3](https://www.virustotal.com/gui/file/fad014ec98529644b5db5388d96bc4f9b77dcdc3) |
| SHA256             | [5fe5a6f88fbbc85be9efe81204eee11dff1a683b426019d330b1276a3b5424f4](https://www.virustotal.com/gui/file/5fe5a6f88fbbc85be9efe81204eee11dff1a683b426019d330b1276a3b5424f4) |
| Authentihash MD5   | [936e49d3eec0a2f433e9d0115a38a2b6](https://www.virustotal.com/gui/search/authentihash%253A936e49d3eec0a2f433e9d0115a38a2b6) |
| Authentihash SHA1  | [5717bf3e520accfff5ad9943e53a3b118fb67f2e](https://www.virustotal.com/gui/search/authentihash%253A5717bf3e520accfff5ad9943e53a3b118fb67f2e) |
| Authentihash SHA256| [918d2e68a724b58d37443aea159e70bf8b1b5ebb089c395cad1d62745ecdaa19](https://www.virustotal.com/gui/search/authentihash%253A918d2e68a724b58d37443aea159e70bf8b1b5ebb089c395cad1d62745ecdaa19) |
| RichPEHeaderHash MD5   | [59080883b71fd56bbf10ec0ae4b6bdd4](https://www.virustotal.com/gui/search/rich_pe_header_hash%253A59080883b71fd56bbf10ec0ae4b6bdd4) |
| RichPEHeaderHash SHA1  | [503a36a225568553cc9b05f63b3506c6ff21e12e](https://www.virustotal.com/gui/search/rich_pe_header_hash%253A503a36a225568553cc9b05f63b3506c6ff21e12e) |
| RichPEHeaderHash SHA256| [bc812d4ddc3ecfbf38c4d0d185e368fc58bac6e07f722db032bf6303daa7c946](https://www.virustotal.com/gui/search/rich_pe_header_hash%253Abc812d4ddc3ecfbf38c4d0d185e368fc58bac6e07f722db032bf6303daa7c946) |

{{< button "https://github.com/magicsword-io/LOLDrivers/raw/main/drivers/6b16512bffe88146a7915f749bd81641.bin" "Download" >}} 

#### Certificates

{{< details "Expand" >}}
###### Certificate 0400000000012019c19066
| Field                             | Value                      |
|-----------------------------------|----------------------------|
| ToBeSigned (TBS) MD5              | 42023b9487cafe46c1b6a49c369a362e  |
| ToBeSigned (TBS) SHA1             | 7c7b524d269334b9f073c32e888e09544c6acd98 |
| ToBeSigned (TBS) SHA256           | b7126567833f3daa4085ff41e73112daad3d1e3808a942c1936520e2d6c46c78 |
| Subject                           | OU=Timestamping CA, O=GlobalSign, CN=GlobalSign Timestamping CA |
| ValidFrom                         | 2009-03-18 11:00:00 |
| ValidTo                           | 2028-01-28 12:00:00 |
| Signature                         | 5df6cb2b0d0140849f857a43706ae0c5e7aa0600d76713c9089131654f14a8a905dc389e6aa0300abd8dc78028ee4245ca94f3de5845a9803204f5595c6a70003927944df5b44634e81c5331b2b35416e9cc42abd5d959301cfb462725b88723b1e8758824831ec876377b01494548a4ede25dd27c9ca2dc2dba105a126265abae00c710343bcb72bd14240cdcc37627b4a7fee15829f20e169f91391d89a6e60f1c878ce258ac927e243eaaec14e73a33348bc63bac83ab0f14627aba1a2d4d4b1bc530f00b92797d3c78e0f8e6d215965999392b3061e8b8f8c0a1e9221411787dc4dc89bec0bb94e172aeebb540404fef171e585ed0a88996ac9228e9babf |
| SignatureAlgorithmOID             | 1.2.840.113549.1.1.5 |
| IsCertificateAuthority            | True |
| SerialNumber                      | 0400000000012019c19066 |
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
###### Certificate 01000000000125b0b4cc01
| Field                             | Value                      |
|-----------------------------------|----------------------------|
| ToBeSigned (TBS) MD5              | e3369c8e5aec0504b3a50455f615d9f9  |
| ToBeSigned (TBS) SHA1             | 13c244a894b40ecd18aaf97c362f20385bd005a7 |
| ToBeSigned (TBS) SHA256           | 26da721a670c72836926032fee6920118bfb9bff89cc8d0ce30d9452c33f2532 |
| Subject                           | C=BE, O=GlobalSign NV, CN=GlobalSign Time Stamping Authority |
| ValidFrom                         | 2009-12-21 09:32:56 |
| ValidTo                           | 2020-12-22 09:32:56 |
| Signature                         | bc89ecfee63655935c79d4117a86808f17b693b26d9b91a1561811c655eaf608edad9b9ef52b81c8bbdd607b1b47991e6d403e1d80c213d58e04052fdbe7ae529e688472a1e54a603cf89bd52f46d8c3b2b79353ac9b6c432424d1f1fce9562e3411581843eaefff34746ca0c06c7fad031969881e9560cabbbd0cbb76efc724b081c63831cf36ad0c38b89020849b2e8f28b99ff6ca9427cdac396157e0e3955a9c769230f5dea6973d721c2a6032a8334d8635338a5cf3a4fdf7062ce16b4b30f5cbd34362f841b9de7d20cb058c8e2cf65f35fd338d42896508362ca389f45a858bb0b97bdb6ccba1f8d20e1bbb977cd12779be9d7c3be6a75634d8c991a9 |
| SignatureAlgorithmOID             | 1.2.840.113549.1.1.5 |
| IsCertificateAuthority            | False |
| SerialNumber                      | 01000000000125b0b4cc01 |
| Version                           | 3 |
###### Certificate 1121a559b50ef9848661f0faeb7421bbdd2c
| Field                             | Value                      |
|-----------------------------------|----------------------------|
| ToBeSigned (TBS) MD5              | 3a98a18e8636f2a01e49e2a6d116c360  |
| ToBeSigned (TBS) SHA1             | a2938150e46525adcec2e3a2348824bc1cf532b2 |
| ToBeSigned (TBS) SHA256           | 01a2e2d31d0a4f3005753cce5972b5da2a7c08b0750fb6947e0fd231e64ae7ec |
| Subject                           | C=TW, ST=Taiwan, L=New Taipei City, O=MICRO,STAR INTERNATIONAL CO., LTD., OU=MICRO,STAR INTERNATIONAL CO., LTD., CN=MICRO,STAR INTERNATIONAL CO., LTD. |
| ValidFrom                         | 2011-08-30 06:46:09 |
| ValidTo                           | 2014-08-30 06:46:09 |
| Signature                         | 87bf57ab7ffd7e005076b34b14ddd924045ec7e389871661794f1ece1bef10e050893b28236cb650af1415f8cd95e86c2052d93311d73e0bbe6fb1c22ddea438a93c8b18bd4b8c0f81ad07032efb46d406bbaa730dd3ac92cbf0d9cc711a397a0e0320b213a5161e6be83ec69967a712b463129ea56d5a8ecd3ff8901be09dfaa0a0f10e879b307863e1b1c3a3149ac73bc3f3160db7012229b57bced6d47b875878663642a8cddd03da1e7f236b8cf16713a5e0f4c892aaca77a8c7dab41d84567e2bbf09b336a2824e0e18d54d199e6e024d2630bb210cd24a9ef4b377be0429e2ecc9bf8478a8c6a78c686e26f29c95925baee85e4bbb97b6eecffe44a25e |
| SignatureAlgorithmOID             | 1.2.840.113549.1.1.5 |
| IsCertificateAuthority            | False |
| SerialNumber                      | 1121a559b50ef9848661f0faeb7421bbdd2c |
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
#### Imported Functions
{{< details "Expand" >}}
* RtlInitUnicodeString
* ZwClose
* ZwMapViewOfSection
* ObReferenceObjectByHandle
* ZwOpenSection
* MmMapIoSpace
* IoDeleteSymbolicLink
* IofCompleteRequest
* ZwUnmapViewOfSection
* MmUnmapIoSpace
* IoCreateSymbolicLink
* IoCreateDevice
* __C_specific_handler
* IoDeleteDevice
* HalTranslateBusAddress

{{< /details >}}
#### Exported Functions
{{< details "Expand" >}}

{{< /details >}}

#### Sections
{{< details "Expand" >}}
* .text
* .rdata
* .data
* .pdata
* INIT

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
        "SHA256": "3ca71e85908ff67368e4dc00253f5691b9e6d50c966e7784143d75fb92aa3448",
        "SHA384": "d9d366f9328f2b55ee19a32cc5fd5148b81d764282fe5dc196c872ae249caa51d2c212ef39f33945dfe0cda81925e326"
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
        "SHA256": "cbdc9a0ad785d0c2013211746b42234e18bdc7d54a7a260647badc1c9e712ed4",
        "SHA384": "dcec542f242317863d0b3d23947e17d6982e381003831777b07ed75b46fb18bd0392a89c9beb6862981cd05f3f2fb77b"
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
        "SHA256": "4783380498acf592286ef2dea0fcc5bdea3f54d5e374d3e3497df9d5f662cfb6",
        "SHA384": "4f428f115cf3d008248f15f32007fc7c54bd454e1b48b765776b4c87c23ab8818d8fbcbb3646d35eca012b025260a3b8"
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
        "SHA256": "5b81998ed98b343c04134c336e03f3051779eae0e9f882e8339593d18556375d",
        "SHA384": "db0076cad41a0ef4ea68754ef6905bd5ff772adcb745b05c0060344e43588abc95952dc3ad272f5a8f17b206e4089aca"
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
        "SHA256": "ef14ea05bb066ee9f4188196dd69cd769b283ac4d7555db52f5e76922d3456e1",
        "SHA384": "6e7450a139856aeda6fa6284ff89b3752a9b646e096b4d33dd7e8e727742a2111481531581c0aa2cda0338e22cfdbad3"
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
| Filename           |  |
| Creation Timestamp           | 2005-05-25 00:39:12 |
| MD5                | [0be80db5d9368fdb29fe9d9bfdd02e7c](https://www.virustotal.com/gui/file/0be80db5d9368fdb29fe9d9bfdd02e7c) |
| SHA1               | [6cc28df318a9420b49a252d6e8aaeda0330dc67d](https://www.virustotal.com/gui/file/6cc28df318a9420b49a252d6e8aaeda0330dc67d) |
| SHA256             | [5de78cf5f0b1b09e7145db84e91a2223c3ed4d83cceb3ef073c068cf88b9d444](https://www.virustotal.com/gui/file/5de78cf5f0b1b09e7145db84e91a2223c3ed4d83cceb3ef073c068cf88b9d444) |
| Authentihash MD5   | [a17d227444e090ff69e24fcb6d43162b](https://www.virustotal.com/gui/search/authentihash%253Aa17d227444e090ff69e24fcb6d43162b) |
| Authentihash SHA1  | [43d3a3c1f7b14cfcc051cae2534dbbbb4c7fc120](https://www.virustotal.com/gui/search/authentihash%253A43d3a3c1f7b14cfcc051cae2534dbbbb4c7fc120) |
| Authentihash SHA256| [b8eb26b6f79020ae988e4fb752dc06e1b6779749bf4f8df2872fc2b92bab8020](https://www.virustotal.com/gui/search/authentihash%253Ab8eb26b6f79020ae988e4fb752dc06e1b6779749bf4f8df2872fc2b92bab8020) |
| RichPEHeaderHash MD5   | [deb9c1e252f598099d70d2b33a313da3](https://www.virustotal.com/gui/search/rich_pe_header_hash%253Adeb9c1e252f598099d70d2b33a313da3) |
| RichPEHeaderHash SHA1  | [f0c2801e0091ed6f5e10ea7045e911aa90030290](https://www.virustotal.com/gui/search/rich_pe_header_hash%253Af0c2801e0091ed6f5e10ea7045e911aa90030290) |
| RichPEHeaderHash SHA256| [914fb9761d50c3fa2ecf9fbd8af3735f9b8d6c4903e067c8af9546e79b6f22c7](https://www.virustotal.com/gui/search/rich_pe_header_hash%253A914fb9761d50c3fa2ecf9fbd8af3735f9b8d6c4903e067c8af9546e79b6f22c7) |

{{< button "https://github.com/magicsword-io/LOLDrivers/raw/main/drivers/0be80db5d9368fdb29fe9d9bfdd02e7c.bin" "Download" >}} 


#### Imports
{{< details "Expand" >}}
* ntoskrnl.exe
* HAL.dll

{{< /details >}}
#### Imported Functions
{{< details "Expand" >}}
* RtlInitUnicodeString
* ZwClose
* ZwMapViewOfSection
* ObReferenceObjectByHandle
* ZwOpenSection
* IoDeleteSymbolicLink
* IofCompleteRequest
* MmIsAddressValid
* ZwUnmapViewOfSection
* IoCreateSymbolicLink
* IoCreateDevice
* __C_specific_handler
* IoDeleteDevice
* HalTranslateBusAddress

{{< /details >}}
#### Exported Functions
{{< details "Expand" >}}

{{< /details >}}

#### Sections
{{< details "Expand" >}}
* .text
* .rdata
* .data
* .pdata
* INIT

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
        "SHA256": "3ca71e85908ff67368e4dc00253f5691b9e6d50c966e7784143d75fb92aa3448",
        "SHA384": "d9d366f9328f2b55ee19a32cc5fd5148b81d764282fe5dc196c872ae249caa51d2c212ef39f33945dfe0cda81925e326"
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
        "SHA256": "cbdc9a0ad785d0c2013211746b42234e18bdc7d54a7a260647badc1c9e712ed4",
        "SHA384": "dcec542f242317863d0b3d23947e17d6982e381003831777b07ed75b46fb18bd0392a89c9beb6862981cd05f3f2fb77b"
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
        "SHA256": "4783380498acf592286ef2dea0fcc5bdea3f54d5e374d3e3497df9d5f662cfb6",
        "SHA384": "4f428f115cf3d008248f15f32007fc7c54bd454e1b48b765776b4c87c23ab8818d8fbcbb3646d35eca012b025260a3b8"
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
        "SHA256": "5b81998ed98b343c04134c336e03f3051779eae0e9f882e8339593d18556375d",
        "SHA384": "db0076cad41a0ef4ea68754ef6905bd5ff772adcb745b05c0060344e43588abc95952dc3ad272f5a8f17b206e4089aca"
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
        "SHA256": "ef14ea05bb066ee9f4188196dd69cd769b283ac4d7555db52f5e76922d3456e1",
        "SHA384": "6e7450a139856aeda6fa6284ff89b3752a9b646e096b4d33dd7e8e727742a2111481531581c0aa2cda0338e22cfdbad3"
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
| Filename           |  |
| Creation Timestamp           | 2005-05-25 00:39:12 |
| MD5                | [61e8367fb57297a949c9a80c2e0e5a38](https://www.virustotal.com/gui/file/61e8367fb57297a949c9a80c2e0e5a38) |
| SHA1               | [a37616f0575a683bd81a0f49fadbbc87e1525eba](https://www.virustotal.com/gui/file/a37616f0575a683bd81a0f49fadbbc87e1525eba) |
| SHA256             | [d3eaf041ce5f3fd59885ead2cb4ce5c61ac9d83d41f626512942a50e3da7b75a](https://www.virustotal.com/gui/file/d3eaf041ce5f3fd59885ead2cb4ce5c61ac9d83d41f626512942a50e3da7b75a) |
| Authentihash MD5   | [a17d227444e090ff69e24fcb6d43162b](https://www.virustotal.com/gui/search/authentihash%253Aa17d227444e090ff69e24fcb6d43162b) |
| Authentihash SHA1  | [43d3a3c1f7b14cfcc051cae2534dbbbb4c7fc120](https://www.virustotal.com/gui/search/authentihash%253A43d3a3c1f7b14cfcc051cae2534dbbbb4c7fc120) |
| Authentihash SHA256| [b8eb26b6f79020ae988e4fb752dc06e1b6779749bf4f8df2872fc2b92bab8020](https://www.virustotal.com/gui/search/authentihash%253Ab8eb26b6f79020ae988e4fb752dc06e1b6779749bf4f8df2872fc2b92bab8020) |
| RichPEHeaderHash MD5   | [deb9c1e252f598099d70d2b33a313da3](https://www.virustotal.com/gui/search/rich_pe_header_hash%253Adeb9c1e252f598099d70d2b33a313da3) |
| RichPEHeaderHash SHA1  | [f0c2801e0091ed6f5e10ea7045e911aa90030290](https://www.virustotal.com/gui/search/rich_pe_header_hash%253Af0c2801e0091ed6f5e10ea7045e911aa90030290) |
| RichPEHeaderHash SHA256| [914fb9761d50c3fa2ecf9fbd8af3735f9b8d6c4903e067c8af9546e79b6f22c7](https://www.virustotal.com/gui/search/rich_pe_header_hash%253A914fb9761d50c3fa2ecf9fbd8af3735f9b8d6c4903e067c8af9546e79b6f22c7) |

{{< button "https://github.com/magicsword-io/LOLDrivers/raw/main/drivers/61e8367fb57297a949c9a80c2e0e5a38.bin" "Download" >}} 

#### Certificates

{{< details "Expand" >}}
###### Certificate 0400000000012019c19066
| Field                             | Value                      |
|-----------------------------------|----------------------------|
| ToBeSigned (TBS) MD5              | 42023b9487cafe46c1b6a49c369a362e  |
| ToBeSigned (TBS) SHA1             | 7c7b524d269334b9f073c32e888e09544c6acd98 |
| ToBeSigned (TBS) SHA256           | b7126567833f3daa4085ff41e73112daad3d1e3808a942c1936520e2d6c46c78 |
| Subject                           | OU=Timestamping CA, O=GlobalSign, CN=GlobalSign Timestamping CA |
| ValidFrom                         | 2009-03-18 11:00:00 |
| ValidTo                           | 2028-01-28 12:00:00 |
| Signature                         | 5df6cb2b0d0140849f857a43706ae0c5e7aa0600d76713c9089131654f14a8a905dc389e6aa0300abd8dc78028ee4245ca94f3de5845a9803204f5595c6a70003927944df5b44634e81c5331b2b35416e9cc42abd5d959301cfb462725b88723b1e8758824831ec876377b01494548a4ede25dd27c9ca2dc2dba105a126265abae00c710343bcb72bd14240cdcc37627b4a7fee15829f20e169f91391d89a6e60f1c878ce258ac927e243eaaec14e73a33348bc63bac83ab0f14627aba1a2d4d4b1bc530f00b92797d3c78e0f8e6d215965999392b3061e8b8f8c0a1e9221411787dc4dc89bec0bb94e172aeebb540404fef171e585ed0a88996ac9228e9babf |
| SignatureAlgorithmOID             | 1.2.840.113549.1.1.5 |
| IsCertificateAuthority            | True |
| SerialNumber                      | 0400000000012019c19066 |
| Version                           | 3 |
###### Certificate 01000000000125b0b4cc01
| Field                             | Value                      |
|-----------------------------------|----------------------------|
| ToBeSigned (TBS) MD5              | e3369c8e5aec0504b3a50455f615d9f9  |
| ToBeSigned (TBS) SHA1             | 13c244a894b40ecd18aaf97c362f20385bd005a7 |
| ToBeSigned (TBS) SHA256           | 26da721a670c72836926032fee6920118bfb9bff89cc8d0ce30d9452c33f2532 |
| Subject                           | C=BE, O=GlobalSign NV, CN=GlobalSign Time Stamping Authority |
| ValidFrom                         | 2009-12-21 09:32:56 |
| ValidTo                           | 2020-12-22 09:32:56 |
| Signature                         | bc89ecfee63655935c79d4117a86808f17b693b26d9b91a1561811c655eaf608edad9b9ef52b81c8bbdd607b1b47991e6d403e1d80c213d58e04052fdbe7ae529e688472a1e54a603cf89bd52f46d8c3b2b79353ac9b6c432424d1f1fce9562e3411581843eaefff34746ca0c06c7fad031969881e9560cabbbd0cbb76efc724b081c63831cf36ad0c38b89020849b2e8f28b99ff6ca9427cdac396157e0e3955a9c769230f5dea6973d721c2a6032a8334d8635338a5cf3a4fdf7062ce16b4b30f5cbd34362f841b9de7d20cb058c8e2cf65f35fd338d42896508362ca389f45a858bb0b97bdb6ccba1f8d20e1bbb977cd12779be9d7c3be6a75634d8c991a9 |
| SignatureAlgorithmOID             | 1.2.840.113549.1.1.5 |
| IsCertificateAuthority            | False |
| SerialNumber                      | 01000000000125b0b4cc01 |
| Version                           | 3 |
###### Certificate 79c32d7ddd2458cf2eabe5b1b5c5290f
| Field                             | Value                      |
|-----------------------------------|----------------------------|
| ToBeSigned (TBS) MD5              | 5ba772ec00357ae706016510775c7a00  |
| ToBeSigned (TBS) SHA1             | eeb31b244ea14abae1e947ecdca0d6ae4720031b |
| ToBeSigned (TBS) SHA256           | c8e707c2615c26ac78ed06b42dd20bc8ff82bc5e02ddafe2c9af85755097691b |
| Subject                           | C=US, ST=California, L=Brea, O=EVGA, OU=Digital ID Class 3 , Microsoft Software Validation v2, CN=EVGA |
| ValidFrom                         | 2010-04-14 00:00:00 |
| ValidTo                           | 2012-04-15 23:59:59 |
| Signature                         | ba96817224593697c9135d803c5fc87767f2a7ed8fa0aa18eab4030a3daed18c55fb7eda8835d0488d18136c0db39d8edf3224790842cdf8580b35324631de717e9279d28d605285615341aeea10a73005d59cbe3138bebfa5003cbcf2971249423d820d6d252a18bf4dd124a1ac0c2f66015cbb23690e1b0fb9d5ce3f047663f1fb6735e54f09cfb6162da298bdc956490586cfdadee74a5766c187223e19112d22f59c7f3f325449afebc42689ec4c9399bd0d97397c37230804a4e5bc17e904008aa9c5972e2332302e57648006d057c9ed8c6384fb42d138971c86079b155c202733b837b3eef122c866ce3e6d8a8d9f1685e618cc2466d623d212b73df6 |
| SignatureAlgorithmOID             | 1.2.840.113549.1.1.5 |
| IsCertificateAuthority            | False |
| SerialNumber                      | 79c32d7ddd2458cf2eabe5b1b5c5290f |
| Version                           | 3 |
###### Certificate 655226e1b22e18e1590f2985ac22e75c
| Field                             | Value                      |
|-----------------------------------|----------------------------|
| ToBeSigned (TBS) MD5              | 650704c342850095f3288eaf791147d4  |
| ToBeSigned (TBS) SHA1             | 4cdc38c800761463749c3cbd94a12f32e49877bf |
| ToBeSigned (TBS) SHA256           | 07b8f662558ec85b71b43a79c6e94698144f4ced2308af21e7ba1e5d461da214 |
| Subject                           | C=US, O=VeriSign, Inc., OU=VeriSign Trust Network, OU=Terms of use at https://www.verisign.com/rpa (c)09, CN=VeriSign Class 3 Code Signing 2009,2 CA |
| ValidFrom                         | 2009-05-21 00:00:00 |
| ValidTo                           | 2019-05-20 23:59:59 |
| Signature                         | 8b03c0dd94d841a26169b015a878c730c6903c7e42f724b6e4837317047f04109ca1e2fa812febc0ca44e772e050b6551020836e9692e49a516ab43731dca52deb8c00c71d4fe74d32ba85f84ebefa675565f06abe7aca64381a101078457631f3867a030f60c2b35d9df68b6676821b59e183e5bd49a53856e5de41770e580f |
| SignatureAlgorithmOID             | 1.2.840.113549.1.1.5 |
| IsCertificateAuthority            | True |
| SerialNumber                      | 655226e1b22e18e1590f2985ac22e75c |
| Version                           | 3 |
###### Certificate 610c120600000000001b
| Field                             | Value                      |
|-----------------------------------|----------------------------|
| ToBeSigned (TBS) MD5              | 53c41bc1164e09e0cd1617a5bf913efd  |
| ToBeSigned (TBS) SHA1             | 93c03aac8951d494ecd5696b1c08658541b18727 |
| ToBeSigned (TBS) SHA256           | 40bddadac24dc61ca4fb5cab2a2bc5d876bc36808311039a7a3e1a4066f7489b |
| Subject                           | C=US, O=VeriSign, Inc., OU=Class 3 Public Primary Certification Authority |
| ValidFrom                         | 2006-05-23 17:01:29 |
| ValidTo                           | 2016-05-23 17:11:29 |
| Signature                         | 01e446b33b457f7513877e5f43de468ecb8abdb64741bccccc7491d8ce395195a4a6b547c0efd2da7b8f5711f4328c7ccd3fee42da04214af7c843884a6f5cca14fc4bd19f4cbdd4556ecc02be0da6888f8609baa425bde8b0f0fa8b714e67b0cb82a8d78e55f737ebf03e88efe4e08afd1c6e2e61414875b4b02c1d28d8490fd715f02473253ccc880cde284c6554fe5eae8cea19ad2c51b29b3a47f53c80350117e24987d6544afb4bab07bcbf7d79cfbf35005cbb9ecffc82891b39a05197b6dec0b307ff449644c0342a195cabeef03bec294eb513c537857e75d5b4d60d066eb5d26c237167eaf1718eaf4e74aa0cf9ecbf4c58fa5e909b6d39cb86883f8b1ca81632d5fe6db9f1f8b3ead791f6364778c0272a15c768d6f4c5fc4f4ec8673f102d409ff11ec96148e7a703fc31730cf04688fe56da492995ef09daa3e5beef60ecd954a0599c28bd54ef66157f874c84dba60e95672e517b3439b641c28c846826dc240209e7818e0a972defeea7b998a60f818dc710b5e1ed982f486f53854964789bec5dac970b5526c3efba8dc8d1a52f5a7f936b611a339b18b8a26210de24ea76e12f43ebecdd7c12342489da2855aee5754e312b6763b6a8d7ab730a03cec5ea593fc7eb2a45aea8625b2f009939abb45f73c308ec80118f470e8f2a1343e191066255bbffba3da9a93d260faeca7d628b155589d694344dd665 |
| SignatureAlgorithmOID             | 1.2.840.113549.1.1.5 |
| IsCertificateAuthority            | True |
| SerialNumber                      | 610c120600000000001b |
| Version                           | 3 |

{{< /details >}}
#### Imports
{{< details "Expand" >}}
* ntoskrnl.exe
* HAL.dll

{{< /details >}}
#### Imported Functions
{{< details "Expand" >}}
* RtlInitUnicodeString
* ZwClose
* ZwMapViewOfSection
* ObReferenceObjectByHandle
* ZwOpenSection
* IoDeleteSymbolicLink
* IofCompleteRequest
* MmIsAddressValid
* ZwUnmapViewOfSection
* IoCreateSymbolicLink
* IoCreateDevice
* __C_specific_handler
* IoDeleteDevice
* HalTranslateBusAddress

{{< /details >}}
#### Exported Functions
{{< details "Expand" >}}

{{< /details >}}

#### Sections
{{< details "Expand" >}}
* .text
* .rdata
* .data
* .pdata
* INIT

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
        "SHA256": "3ca71e85908ff67368e4dc00253f5691b9e6d50c966e7784143d75fb92aa3448",
        "SHA384": "d9d366f9328f2b55ee19a32cc5fd5148b81d764282fe5dc196c872ae249caa51d2c212ef39f33945dfe0cda81925e326"
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
        "SHA256": "cbdc9a0ad785d0c2013211746b42234e18bdc7d54a7a260647badc1c9e712ed4",
        "SHA384": "dcec542f242317863d0b3d23947e17d6982e381003831777b07ed75b46fb18bd0392a89c9beb6862981cd05f3f2fb77b"
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
        "SHA256": "4783380498acf592286ef2dea0fcc5bdea3f54d5e374d3e3497df9d5f662cfb6",
        "SHA384": "4f428f115cf3d008248f15f32007fc7c54bd454e1b48b765776b4c87c23ab8818d8fbcbb3646d35eca012b025260a3b8"
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
        "SHA256": "5b81998ed98b343c04134c336e03f3051779eae0e9f882e8339593d18556375d",
        "SHA384": "db0076cad41a0ef4ea68754ef6905bd5ff772adcb745b05c0060344e43588abc95952dc3ad272f5a8f17b206e4089aca"
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
        "SHA256": "ef14ea05bb066ee9f4188196dd69cd769b283ac4d7555db52f5e76922d3456e1",
        "SHA384": "6e7450a139856aeda6fa6284ff89b3752a9b646e096b4d33dd7e8e727742a2111481531581c0aa2cda0338e22cfdbad3"
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
| Filename           |  |
| Creation Timestamp           | 2005-05-25 00:39:12 |
| MD5                | [98583b2f2efe12d2a167217a3838c498](https://www.virustotal.com/gui/file/98583b2f2efe12d2a167217a3838c498) |
| SHA1               | [8f266edf9f536c7fc5bb3797a1cf9039fde8e97c](https://www.virustotal.com/gui/file/8f266edf9f536c7fc5bb3797a1cf9039fde8e97c) |
| SHA256             | [5ab48bf8c099611b217cc9f78af2f92e9aaeedf1cea4c95d5dd562f51e9f0d09](https://www.virustotal.com/gui/file/5ab48bf8c099611b217cc9f78af2f92e9aaeedf1cea4c95d5dd562f51e9f0d09) |
| Authentihash MD5   | [a17d227444e090ff69e24fcb6d43162b](https://www.virustotal.com/gui/search/authentihash%253Aa17d227444e090ff69e24fcb6d43162b) |
| Authentihash SHA1  | [43d3a3c1f7b14cfcc051cae2534dbbbb4c7fc120](https://www.virustotal.com/gui/search/authentihash%253A43d3a3c1f7b14cfcc051cae2534dbbbb4c7fc120) |
| Authentihash SHA256| [b8eb26b6f79020ae988e4fb752dc06e1b6779749bf4f8df2872fc2b92bab8020](https://www.virustotal.com/gui/search/authentihash%253Ab8eb26b6f79020ae988e4fb752dc06e1b6779749bf4f8df2872fc2b92bab8020) |
| RichPEHeaderHash MD5   | [deb9c1e252f598099d70d2b33a313da3](https://www.virustotal.com/gui/search/rich_pe_header_hash%253Adeb9c1e252f598099d70d2b33a313da3) |
| RichPEHeaderHash SHA1  | [f0c2801e0091ed6f5e10ea7045e911aa90030290](https://www.virustotal.com/gui/search/rich_pe_header_hash%253Af0c2801e0091ed6f5e10ea7045e911aa90030290) |
| RichPEHeaderHash SHA256| [914fb9761d50c3fa2ecf9fbd8af3735f9b8d6c4903e067c8af9546e79b6f22c7](https://www.virustotal.com/gui/search/rich_pe_header_hash%253A914fb9761d50c3fa2ecf9fbd8af3735f9b8d6c4903e067c8af9546e79b6f22c7) |

{{< button "https://github.com/magicsword-io/LOLDrivers/raw/main/drivers/98583b2f2efe12d2a167217a3838c498.bin" "Download" >}} 

#### Certificates

{{< details "Expand" >}}
###### Certificate 0400000000012019c19066
| Field                             | Value                      |
|-----------------------------------|----------------------------|
| ToBeSigned (TBS) MD5              | 42023b9487cafe46c1b6a49c369a362e  |
| ToBeSigned (TBS) SHA1             | 7c7b524d269334b9f073c32e888e09544c6acd98 |
| ToBeSigned (TBS) SHA256           | b7126567833f3daa4085ff41e73112daad3d1e3808a942c1936520e2d6c46c78 |
| Subject                           | OU=Timestamping CA, O=GlobalSign, CN=GlobalSign Timestamping CA |
| ValidFrom                         | 2009-03-18 11:00:00 |
| ValidTo                           | 2028-01-28 12:00:00 |
| Signature                         | 5df6cb2b0d0140849f857a43706ae0c5e7aa0600d76713c9089131654f14a8a905dc389e6aa0300abd8dc78028ee4245ca94f3de5845a9803204f5595c6a70003927944df5b44634e81c5331b2b35416e9cc42abd5d959301cfb462725b88723b1e8758824831ec876377b01494548a4ede25dd27c9ca2dc2dba105a126265abae00c710343bcb72bd14240cdcc37627b4a7fee15829f20e169f91391d89a6e60f1c878ce258ac927e243eaaec14e73a33348bc63bac83ab0f14627aba1a2d4d4b1bc530f00b92797d3c78e0f8e6d215965999392b3061e8b8f8c0a1e9221411787dc4dc89bec0bb94e172aeebb540404fef171e585ed0a88996ac9228e9babf |
| SignatureAlgorithmOID             | 1.2.840.113549.1.1.5 |
| IsCertificateAuthority            | True |
| SerialNumber                      | 0400000000012019c19066 |
| Version                           | 3 |
###### Certificate 01000000000125b0b4cc01
| Field                             | Value                      |
|-----------------------------------|----------------------------|
| ToBeSigned (TBS) MD5              | e3369c8e5aec0504b3a50455f615d9f9  |
| ToBeSigned (TBS) SHA1             | 13c244a894b40ecd18aaf97c362f20385bd005a7 |
| ToBeSigned (TBS) SHA256           | 26da721a670c72836926032fee6920118bfb9bff89cc8d0ce30d9452c33f2532 |
| Subject                           | C=BE, O=GlobalSign NV, CN=GlobalSign Time Stamping Authority |
| ValidFrom                         | 2009-12-21 09:32:56 |
| ValidTo                           | 2020-12-22 09:32:56 |
| Signature                         | bc89ecfee63655935c79d4117a86808f17b693b26d9b91a1561811c655eaf608edad9b9ef52b81c8bbdd607b1b47991e6d403e1d80c213d58e04052fdbe7ae529e688472a1e54a603cf89bd52f46d8c3b2b79353ac9b6c432424d1f1fce9562e3411581843eaefff34746ca0c06c7fad031969881e9560cabbbd0cbb76efc724b081c63831cf36ad0c38b89020849b2e8f28b99ff6ca9427cdac396157e0e3955a9c769230f5dea6973d721c2a6032a8334d8635338a5cf3a4fdf7062ce16b4b30f5cbd34362f841b9de7d20cb058c8e2cf65f35fd338d42896508362ca389f45a858bb0b97bdb6ccba1f8d20e1bbb977cd12779be9d7c3be6a75634d8c991a9 |
| SignatureAlgorithmOID             | 1.2.840.113549.1.1.5 |
| IsCertificateAuthority            | False |
| SerialNumber                      | 01000000000125b0b4cc01 |
| Version                           | 3 |
###### Certificate 79c32d7ddd2458cf2eabe5b1b5c5290f
| Field                             | Value                      |
|-----------------------------------|----------------------------|
| ToBeSigned (TBS) MD5              | 5ba772ec00357ae706016510775c7a00  |
| ToBeSigned (TBS) SHA1             | eeb31b244ea14abae1e947ecdca0d6ae4720031b |
| ToBeSigned (TBS) SHA256           | c8e707c2615c26ac78ed06b42dd20bc8ff82bc5e02ddafe2c9af85755097691b |
| Subject                           | C=US, ST=California, L=Brea, O=EVGA, OU=Digital ID Class 3 , Microsoft Software Validation v2, CN=EVGA |
| ValidFrom                         | 2010-04-14 00:00:00 |
| ValidTo                           | 2012-04-15 23:59:59 |
| Signature                         | ba96817224593697c9135d803c5fc87767f2a7ed8fa0aa18eab4030a3daed18c55fb7eda8835d0488d18136c0db39d8edf3224790842cdf8580b35324631de717e9279d28d605285615341aeea10a73005d59cbe3138bebfa5003cbcf2971249423d820d6d252a18bf4dd124a1ac0c2f66015cbb23690e1b0fb9d5ce3f047663f1fb6735e54f09cfb6162da298bdc956490586cfdadee74a5766c187223e19112d22f59c7f3f325449afebc42689ec4c9399bd0d97397c37230804a4e5bc17e904008aa9c5972e2332302e57648006d057c9ed8c6384fb42d138971c86079b155c202733b837b3eef122c866ce3e6d8a8d9f1685e618cc2466d623d212b73df6 |
| SignatureAlgorithmOID             | 1.2.840.113549.1.1.5 |
| IsCertificateAuthority            | False |
| SerialNumber                      | 79c32d7ddd2458cf2eabe5b1b5c5290f |
| Version                           | 3 |
###### Certificate 655226e1b22e18e1590f2985ac22e75c
| Field                             | Value                      |
|-----------------------------------|----------------------------|
| ToBeSigned (TBS) MD5              | 650704c342850095f3288eaf791147d4  |
| ToBeSigned (TBS) SHA1             | 4cdc38c800761463749c3cbd94a12f32e49877bf |
| ToBeSigned (TBS) SHA256           | 07b8f662558ec85b71b43a79c6e94698144f4ced2308af21e7ba1e5d461da214 |
| Subject                           | C=US, O=VeriSign, Inc., OU=VeriSign Trust Network, OU=Terms of use at https://www.verisign.com/rpa (c)09, CN=VeriSign Class 3 Code Signing 2009,2 CA |
| ValidFrom                         | 2009-05-21 00:00:00 |
| ValidTo                           | 2019-05-20 23:59:59 |
| Signature                         | 8b03c0dd94d841a26169b015a878c730c6903c7e42f724b6e4837317047f04109ca1e2fa812febc0ca44e772e050b6551020836e9692e49a516ab43731dca52deb8c00c71d4fe74d32ba85f84ebefa675565f06abe7aca64381a101078457631f3867a030f60c2b35d9df68b6676821b59e183e5bd49a53856e5de41770e580f |
| SignatureAlgorithmOID             | 1.2.840.113549.1.1.5 |
| IsCertificateAuthority            | True |
| SerialNumber                      | 655226e1b22e18e1590f2985ac22e75c |
| Version                           | 3 |
###### Certificate 610c120600000000001b
| Field                             | Value                      |
|-----------------------------------|----------------------------|
| ToBeSigned (TBS) MD5              | 53c41bc1164e09e0cd1617a5bf913efd  |
| ToBeSigned (TBS) SHA1             | 93c03aac8951d494ecd5696b1c08658541b18727 |
| ToBeSigned (TBS) SHA256           | 40bddadac24dc61ca4fb5cab2a2bc5d876bc36808311039a7a3e1a4066f7489b |
| Subject                           | C=US, O=VeriSign, Inc., OU=Class 3 Public Primary Certification Authority |
| ValidFrom                         | 2006-05-23 17:01:29 |
| ValidTo                           | 2016-05-23 17:11:29 |
| Signature                         | 01e446b33b457f7513877e5f43de468ecb8abdb64741bccccc7491d8ce395195a4a6b547c0efd2da7b8f5711f4328c7ccd3fee42da04214af7c843884a6f5cca14fc4bd19f4cbdd4556ecc02be0da6888f8609baa425bde8b0f0fa8b714e67b0cb82a8d78e55f737ebf03e88efe4e08afd1c6e2e61414875b4b02c1d28d8490fd715f02473253ccc880cde284c6554fe5eae8cea19ad2c51b29b3a47f53c80350117e24987d6544afb4bab07bcbf7d79cfbf35005cbb9ecffc82891b39a05197b6dec0b307ff449644c0342a195cabeef03bec294eb513c537857e75d5b4d60d066eb5d26c237167eaf1718eaf4e74aa0cf9ecbf4c58fa5e909b6d39cb86883f8b1ca81632d5fe6db9f1f8b3ead791f6364778c0272a15c768d6f4c5fc4f4ec8673f102d409ff11ec96148e7a703fc31730cf04688fe56da492995ef09daa3e5beef60ecd954a0599c28bd54ef66157f874c84dba60e95672e517b3439b641c28c846826dc240209e7818e0a972defeea7b998a60f818dc710b5e1ed982f486f53854964789bec5dac970b5526c3efba8dc8d1a52f5a7f936b611a339b18b8a26210de24ea76e12f43ebecdd7c12342489da2855aee5754e312b6763b6a8d7ab730a03cec5ea593fc7eb2a45aea8625b2f009939abb45f73c308ec80118f470e8f2a1343e191066255bbffba3da9a93d260faeca7d628b155589d694344dd665 |
| SignatureAlgorithmOID             | 1.2.840.113549.1.1.5 |
| IsCertificateAuthority            | True |
| SerialNumber                      | 610c120600000000001b |
| Version                           | 3 |

{{< /details >}}
#### Imports
{{< details "Expand" >}}
* ntoskrnl.exe
* HAL.dll

{{< /details >}}
#### Imported Functions
{{< details "Expand" >}}
* RtlInitUnicodeString
* ZwClose
* ZwMapViewOfSection
* ObReferenceObjectByHandle
* ZwOpenSection
* IoDeleteSymbolicLink
* IofCompleteRequest
* MmIsAddressValid
* ZwUnmapViewOfSection
* IoCreateSymbolicLink
* IoCreateDevice
* __C_specific_handler
* IoDeleteDevice
* HalTranslateBusAddress

{{< /details >}}
#### Exported Functions
{{< details "Expand" >}}

{{< /details >}}

#### Sections
{{< details "Expand" >}}
* .text
* .rdata
* .data
* .pdata
* INIT

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
        "SHA256": "3ca71e85908ff67368e4dc00253f5691b9e6d50c966e7784143d75fb92aa3448",
        "SHA384": "d9d366f9328f2b55ee19a32cc5fd5148b81d764282fe5dc196c872ae249caa51d2c212ef39f33945dfe0cda81925e326"
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
        "SHA256": "cbdc9a0ad785d0c2013211746b42234e18bdc7d54a7a260647badc1c9e712ed4",
        "SHA384": "dcec542f242317863d0b3d23947e17d6982e381003831777b07ed75b46fb18bd0392a89c9beb6862981cd05f3f2fb77b"
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
        "SHA256": "4783380498acf592286ef2dea0fcc5bdea3f54d5e374d3e3497df9d5f662cfb6",
        "SHA384": "4f428f115cf3d008248f15f32007fc7c54bd454e1b48b765776b4c87c23ab8818d8fbcbb3646d35eca012b025260a3b8"
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
        "SHA256": "5b81998ed98b343c04134c336e03f3051779eae0e9f882e8339593d18556375d",
        "SHA384": "db0076cad41a0ef4ea68754ef6905bd5ff772adcb745b05c0060344e43588abc95952dc3ad272f5a8f17b206e4089aca"
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
        "SHA256": "ef14ea05bb066ee9f4188196dd69cd769b283ac4d7555db52f5e76922d3456e1",
        "SHA384": "6e7450a139856aeda6fa6284ff89b3752a9b646e096b4d33dd7e8e727742a2111481531581c0aa2cda0338e22cfdbad3"
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
| Filename           |  |
| Creation Timestamp           | 2011-09-06 06:24:50 |
| MD5                | [dca1c62c793f84bb2d8e41ca50efbff1](https://www.virustotal.com/gui/file/dca1c62c793f84bb2d8e41ca50efbff1) |
| SHA1               | [7cf7644e38746c9be4537b395285888d5572ae1b](https://www.virustotal.com/gui/file/7cf7644e38746c9be4537b395285888d5572ae1b) |
| SHA256             | [fded693528f7e6ac1af253e0bd2726607308fdaa904f1e7242ed44e1c0b29ae8](https://www.virustotal.com/gui/file/fded693528f7e6ac1af253e0bd2726607308fdaa904f1e7242ed44e1c0b29ae8) |
| Authentihash MD5   | [55466195f0b2f4afc4243b43a806e6d9](https://www.virustotal.com/gui/search/authentihash%253A55466195f0b2f4afc4243b43a806e6d9) |
| Authentihash SHA1  | [38b353d8480885de5dcf299deca99ce4f26a1d20](https://www.virustotal.com/gui/search/authentihash%253A38b353d8480885de5dcf299deca99ce4f26a1d20) |
| Authentihash SHA256| [5182caf10de9cec0740ecde5a081c21cdc100d7eb328ffe6f3f63183889fec6b](https://www.virustotal.com/gui/search/authentihash%253A5182caf10de9cec0740ecde5a081c21cdc100d7eb328ffe6f3f63183889fec6b) |
| RichPEHeaderHash MD5   | [59080883b71fd56bbf10ec0ae4b6bdd4](https://www.virustotal.com/gui/search/rich_pe_header_hash%253A59080883b71fd56bbf10ec0ae4b6bdd4) |
| RichPEHeaderHash SHA1  | [503a36a225568553cc9b05f63b3506c6ff21e12e](https://www.virustotal.com/gui/search/rich_pe_header_hash%253A503a36a225568553cc9b05f63b3506c6ff21e12e) |
| RichPEHeaderHash SHA256| [bc812d4ddc3ecfbf38c4d0d185e368fc58bac6e07f722db032bf6303daa7c946](https://www.virustotal.com/gui/search/rich_pe_header_hash%253Abc812d4ddc3ecfbf38c4d0d185e368fc58bac6e07f722db032bf6303daa7c946) |

{{< button "https://github.com/magicsword-io/LOLDrivers/raw/main/drivers/dca1c62c793f84bb2d8e41ca50efbff1.bin" "Download" >}} 

#### Certificates

{{< details "Expand" >}}
###### Certificate 0400000000012019c19066
| Field                             | Value                      |
|-----------------------------------|----------------------------|
| ToBeSigned (TBS) MD5              | 42023b9487cafe46c1b6a49c369a362e  |
| ToBeSigned (TBS) SHA1             | 7c7b524d269334b9f073c32e888e09544c6acd98 |
| ToBeSigned (TBS) SHA256           | b7126567833f3daa4085ff41e73112daad3d1e3808a942c1936520e2d6c46c78 |
| Subject                           | OU=Timestamping CA, O=GlobalSign, CN=GlobalSign Timestamping CA |
| ValidFrom                         | 2009-03-18 11:00:00 |
| ValidTo                           | 2028-01-28 12:00:00 |
| Signature                         | 5df6cb2b0d0140849f857a43706ae0c5e7aa0600d76713c9089131654f14a8a905dc389e6aa0300abd8dc78028ee4245ca94f3de5845a9803204f5595c6a70003927944df5b44634e81c5331b2b35416e9cc42abd5d959301cfb462725b88723b1e8758824831ec876377b01494548a4ede25dd27c9ca2dc2dba105a126265abae00c710343bcb72bd14240cdcc37627b4a7fee15829f20e169f91391d89a6e60f1c878ce258ac927e243eaaec14e73a33348bc63bac83ab0f14627aba1a2d4d4b1bc530f00b92797d3c78e0f8e6d215965999392b3061e8b8f8c0a1e9221411787dc4dc89bec0bb94e172aeebb540404fef171e585ed0a88996ac9228e9babf |
| SignatureAlgorithmOID             | 1.2.840.113549.1.1.5 |
| IsCertificateAuthority            | True |
| SerialNumber                      | 0400000000012019c19066 |
| Version                           | 3 |
###### Certificate 01000000000125b0b4cc01
| Field                             | Value                      |
|-----------------------------------|----------------------------|
| ToBeSigned (TBS) MD5              | e3369c8e5aec0504b3a50455f615d9f9  |
| ToBeSigned (TBS) SHA1             | 13c244a894b40ecd18aaf97c362f20385bd005a7 |
| ToBeSigned (TBS) SHA256           | 26da721a670c72836926032fee6920118bfb9bff89cc8d0ce30d9452c33f2532 |
| Subject                           | C=BE, O=GlobalSign NV, CN=GlobalSign Time Stamping Authority |
| ValidFrom                         | 2009-12-21 09:32:56 |
| ValidTo                           | 2020-12-22 09:32:56 |
| Signature                         | bc89ecfee63655935c79d4117a86808f17b693b26d9b91a1561811c655eaf608edad9b9ef52b81c8bbdd607b1b47991e6d403e1d80c213d58e04052fdbe7ae529e688472a1e54a603cf89bd52f46d8c3b2b79353ac9b6c432424d1f1fce9562e3411581843eaefff34746ca0c06c7fad031969881e9560cabbbd0cbb76efc724b081c63831cf36ad0c38b89020849b2e8f28b99ff6ca9427cdac396157e0e3955a9c769230f5dea6973d721c2a6032a8334d8635338a5cf3a4fdf7062ce16b4b30f5cbd34362f841b9de7d20cb058c8e2cf65f35fd338d42896508362ca389f45a858bb0b97bdb6ccba1f8d20e1bbb977cd12779be9d7c3be6a75634d8c991a9 |
| SignatureAlgorithmOID             | 1.2.840.113549.1.1.5 |
| IsCertificateAuthority            | False |
| SerialNumber                      | 01000000000125b0b4cc01 |
| Version                           | 3 |
###### Certificate 79c32d7ddd2458cf2eabe5b1b5c5290f
| Field                             | Value                      |
|-----------------------------------|----------------------------|
| ToBeSigned (TBS) MD5              | 5ba772ec00357ae706016510775c7a00  |
| ToBeSigned (TBS) SHA1             | eeb31b244ea14abae1e947ecdca0d6ae4720031b |
| ToBeSigned (TBS) SHA256           | c8e707c2615c26ac78ed06b42dd20bc8ff82bc5e02ddafe2c9af85755097691b |
| Subject                           | C=US, ST=California, L=Brea, O=EVGA, OU=Digital ID Class 3 , Microsoft Software Validation v2, CN=EVGA |
| ValidFrom                         | 2010-04-14 00:00:00 |
| ValidTo                           | 2012-04-15 23:59:59 |
| Signature                         | ba96817224593697c9135d803c5fc87767f2a7ed8fa0aa18eab4030a3daed18c55fb7eda8835d0488d18136c0db39d8edf3224790842cdf8580b35324631de717e9279d28d605285615341aeea10a73005d59cbe3138bebfa5003cbcf2971249423d820d6d252a18bf4dd124a1ac0c2f66015cbb23690e1b0fb9d5ce3f047663f1fb6735e54f09cfb6162da298bdc956490586cfdadee74a5766c187223e19112d22f59c7f3f325449afebc42689ec4c9399bd0d97397c37230804a4e5bc17e904008aa9c5972e2332302e57648006d057c9ed8c6384fb42d138971c86079b155c202733b837b3eef122c866ce3e6d8a8d9f1685e618cc2466d623d212b73df6 |
| SignatureAlgorithmOID             | 1.2.840.113549.1.1.5 |
| IsCertificateAuthority            | False |
| SerialNumber                      | 79c32d7ddd2458cf2eabe5b1b5c5290f |
| Version                           | 3 |
###### Certificate 655226e1b22e18e1590f2985ac22e75c
| Field                             | Value                      |
|-----------------------------------|----------------------------|
| ToBeSigned (TBS) MD5              | 650704c342850095f3288eaf791147d4  |
| ToBeSigned (TBS) SHA1             | 4cdc38c800761463749c3cbd94a12f32e49877bf |
| ToBeSigned (TBS) SHA256           | 07b8f662558ec85b71b43a79c6e94698144f4ced2308af21e7ba1e5d461da214 |
| Subject                           | C=US, O=VeriSign, Inc., OU=VeriSign Trust Network, OU=Terms of use at https://www.verisign.com/rpa (c)09, CN=VeriSign Class 3 Code Signing 2009,2 CA |
| ValidFrom                         | 2009-05-21 00:00:00 |
| ValidTo                           | 2019-05-20 23:59:59 |
| Signature                         | 8b03c0dd94d841a26169b015a878c730c6903c7e42f724b6e4837317047f04109ca1e2fa812febc0ca44e772e050b6551020836e9692e49a516ab43731dca52deb8c00c71d4fe74d32ba85f84ebefa675565f06abe7aca64381a101078457631f3867a030f60c2b35d9df68b6676821b59e183e5bd49a53856e5de41770e580f |
| SignatureAlgorithmOID             | 1.2.840.113549.1.1.5 |
| IsCertificateAuthority            | True |
| SerialNumber                      | 655226e1b22e18e1590f2985ac22e75c |
| Version                           | 3 |
###### Certificate 610c120600000000001b
| Field                             | Value                      |
|-----------------------------------|----------------------------|
| ToBeSigned (TBS) MD5              | 53c41bc1164e09e0cd1617a5bf913efd  |
| ToBeSigned (TBS) SHA1             | 93c03aac8951d494ecd5696b1c08658541b18727 |
| ToBeSigned (TBS) SHA256           | 40bddadac24dc61ca4fb5cab2a2bc5d876bc36808311039a7a3e1a4066f7489b |
| Subject                           | C=US, O=VeriSign, Inc., OU=Class 3 Public Primary Certification Authority |
| ValidFrom                         | 2006-05-23 17:01:29 |
| ValidTo                           | 2016-05-23 17:11:29 |
| Signature                         | 01e446b33b457f7513877e5f43de468ecb8abdb64741bccccc7491d8ce395195a4a6b547c0efd2da7b8f5711f4328c7ccd3fee42da04214af7c843884a6f5cca14fc4bd19f4cbdd4556ecc02be0da6888f8609baa425bde8b0f0fa8b714e67b0cb82a8d78e55f737ebf03e88efe4e08afd1c6e2e61414875b4b02c1d28d8490fd715f02473253ccc880cde284c6554fe5eae8cea19ad2c51b29b3a47f53c80350117e24987d6544afb4bab07bcbf7d79cfbf35005cbb9ecffc82891b39a05197b6dec0b307ff449644c0342a195cabeef03bec294eb513c537857e75d5b4d60d066eb5d26c237167eaf1718eaf4e74aa0cf9ecbf4c58fa5e909b6d39cb86883f8b1ca81632d5fe6db9f1f8b3ead791f6364778c0272a15c768d6f4c5fc4f4ec8673f102d409ff11ec96148e7a703fc31730cf04688fe56da492995ef09daa3e5beef60ecd954a0599c28bd54ef66157f874c84dba60e95672e517b3439b641c28c846826dc240209e7818e0a972defeea7b998a60f818dc710b5e1ed982f486f53854964789bec5dac970b5526c3efba8dc8d1a52f5a7f936b611a339b18b8a26210de24ea76e12f43ebecdd7c12342489da2855aee5754e312b6763b6a8d7ab730a03cec5ea593fc7eb2a45aea8625b2f009939abb45f73c308ec80118f470e8f2a1343e191066255bbffba3da9a93d260faeca7d628b155589d694344dd665 |
| SignatureAlgorithmOID             | 1.2.840.113549.1.1.5 |
| IsCertificateAuthority            | True |
| SerialNumber                      | 610c120600000000001b |
| Version                           | 3 |

{{< /details >}}
#### Imports
{{< details "Expand" >}}
* ntoskrnl.exe
* HAL.dll

{{< /details >}}
#### Imported Functions
{{< details "Expand" >}}
* RtlInitUnicodeString
* ZwClose
* ZwMapViewOfSection
* ObReferenceObjectByHandle
* ZwOpenSection
* MmMapIoSpace
* IoDeleteSymbolicLink
* IofCompleteRequest
* ZwUnmapViewOfSection
* MmUnmapIoSpace
* IoCreateSymbolicLink
* IoCreateDevice
* __C_specific_handler
* IoDeleteDevice
* HalTranslateBusAddress

{{< /details >}}
#### Exported Functions
{{< details "Expand" >}}

{{< /details >}}

#### Sections
{{< details "Expand" >}}
* .text
* .rdata
* .data
* .pdata
* INIT

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
        "SHA256": "3ca71e85908ff67368e4dc00253f5691b9e6d50c966e7784143d75fb92aa3448",
        "SHA384": "d9d366f9328f2b55ee19a32cc5fd5148b81d764282fe5dc196c872ae249caa51d2c212ef39f33945dfe0cda81925e326"
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
        "SHA256": "cbdc9a0ad785d0c2013211746b42234e18bdc7d54a7a260647badc1c9e712ed4",
        "SHA384": "dcec542f242317863d0b3d23947e17d6982e381003831777b07ed75b46fb18bd0392a89c9beb6862981cd05f3f2fb77b"
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
        "SHA256": "4783380498acf592286ef2dea0fcc5bdea3f54d5e374d3e3497df9d5f662cfb6",
        "SHA384": "4f428f115cf3d008248f15f32007fc7c54bd454e1b48b765776b4c87c23ab8818d8fbcbb3646d35eca012b025260a3b8"
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
        "SHA256": "5b81998ed98b343c04134c336e03f3051779eae0e9f882e8339593d18556375d",
        "SHA384": "db0076cad41a0ef4ea68754ef6905bd5ff772adcb745b05c0060344e43588abc95952dc3ad272f5a8f17b206e4089aca"
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
        "SHA256": "ef14ea05bb066ee9f4188196dd69cd769b283ac4d7555db52f5e76922d3456e1",
        "SHA384": "6e7450a139856aeda6fa6284ff89b3752a9b646e096b4d33dd7e8e727742a2111481531581c0aa2cda0338e22cfdbad3"
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
| Filename           |  |
| Creation Timestamp           | 2015-04-24 01:01:47 |
| MD5                | [027e10a5048b135862d638b9085d1402](https://www.virustotal.com/gui/file/027e10a5048b135862d638b9085d1402) |
| SHA1               | [a528cdeed550844ca7d31c9e231a700b4185d0da](https://www.virustotal.com/gui/file/a528cdeed550844ca7d31c9e231a700b4185d0da) |
| SHA256             | [bac1cd96ba242cdf29f8feac501110739f1524f0db1c8fcad59409e77b8928ba](https://www.virustotal.com/gui/file/bac1cd96ba242cdf29f8feac501110739f1524f0db1c8fcad59409e77b8928ba) |
| Authentihash MD5   | [cfe667280acf69d4b5d0e2dbc76510e4](https://www.virustotal.com/gui/search/authentihash%253Acfe667280acf69d4b5d0e2dbc76510e4) |
| Authentihash SHA1  | [b3249bacda6e43aa2c46c2af802c9ee0b7e2fd7b](https://www.virustotal.com/gui/search/authentihash%253Ab3249bacda6e43aa2c46c2af802c9ee0b7e2fd7b) |
| Authentihash SHA256| [3c9829a16eb85272b0e1a2917feffaab8ddb23e633b168b389669339a0cee0b5](https://www.virustotal.com/gui/search/authentihash%253A3c9829a16eb85272b0e1a2917feffaab8ddb23e633b168b389669339a0cee0b5) |
| RichPEHeaderHash MD5   | [ebe2ae976914018e88e9fc480e7b6269](https://www.virustotal.com/gui/search/rich_pe_header_hash%253Aebe2ae976914018e88e9fc480e7b6269) |
| RichPEHeaderHash SHA1  | [960715bfbccb53b6c4eccca3b232b25640e15b52](https://www.virustotal.com/gui/search/rich_pe_header_hash%253A960715bfbccb53b6c4eccca3b232b25640e15b52) |
| RichPEHeaderHash SHA256| [d755e9f3cb861f5227319238f1811265e332e36a922b9a25da38b122a791fdfa](https://www.virustotal.com/gui/search/rich_pe_header_hash%253Ad755e9f3cb861f5227319238f1811265e332e36a922b9a25da38b122a791fdfa) |

{{< button "https://github.com/magicsword-io/LOLDrivers/raw/main/drivers/027e10a5048b135862d638b9085d1402.bin" "Download" >}} 

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
###### Certificate 112106a081d33fd87ae5824cc16b52094e03
| Field                             | Value                      |
|-----------------------------------|----------------------------|
| ToBeSigned (TBS) MD5              | a0ac4d48fe852f7b3ed4e623d59a825f  |
| ToBeSigned (TBS) SHA1             | d4db9846bc4d7db142eeb364286f6de7c102420c |
| ToBeSigned (TBS) SHA256           | 78d2e41a13eb4e9171bae2d2adb192cf39210b5231f77cda936bcfbe8c003bdf |
| Subject                           | C=SG, O=GMO GlobalSign Pte Ltd, CN=GlobalSign TSA for MS Authenticode , G2 |
| ValidFrom                         | 2015-02-03 00:00:00 |
| ValidTo                           | 2026-03-03 00:00:00 |
| Signature                         | 8032dc078d1ca09c9d3c2ae83d218b59a14d7ecc44ce03be7eaabcc4e67b73bb4bf188da904e7537283863b9d72b0f54a956ce7739973073cd9bd9d905451c8da4b8035d4fd91c2e98e0e988e6ecd7057e562a7bf7165ba3ad8f972512841bb25c634a0ad2ef10544782843569289c0ce41f141624fa75dc74726e4ecae36a43afcf7d3648d1bde906912c2fa6c871fdcfbdd89d2198fcafdbde228cafa7f377ef9ddca3704b441af078851ef2a58c39b5dc881c37edad14f5070b26bdbe6d025eb1b8b0586c853a0df6ff5a270cc5de53e7543c564cc94e4c30f6f25cfb1a8cc282bead5991f61b4d557bcf5b01dcfd7ad36f235c32479b01f3c15114468a9b |
| SignatureAlgorithmOID             | 1.2.840.113549.1.1.5 |
| IsCertificateAuthority            | False |
| SerialNumber                      | 112106a081d33fd87ae5824cc16b52094e03 |
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
#### Imported Functions
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
* HalSetBusDataByOffset
* HalTranslateBusAddress
* HalGetBusDataByOffset

{{< /details >}}
#### Exported Functions
{{< details "Expand" >}}

{{< /details >}}

#### Sections
{{< details "Expand" >}}
* .text
* .rdata
* .data
* .pdata
* INIT

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
        "SHA256": "3ca71e85908ff67368e4dc00253f5691b9e6d50c966e7784143d75fb92aa3448",
        "SHA384": "d9d366f9328f2b55ee19a32cc5fd5148b81d764282fe5dc196c872ae249caa51d2c212ef39f33945dfe0cda81925e326"
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
        "SHA256": "cbdc9a0ad785d0c2013211746b42234e18bdc7d54a7a260647badc1c9e712ed4",
        "SHA384": "dcec542f242317863d0b3d23947e17d6982e381003831777b07ed75b46fb18bd0392a89c9beb6862981cd05f3f2fb77b"
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
        "SHA256": "4783380498acf592286ef2dea0fcc5bdea3f54d5e374d3e3497df9d5f662cfb6",
        "SHA384": "4f428f115cf3d008248f15f32007fc7c54bd454e1b48b765776b4c87c23ab8818d8fbcbb3646d35eca012b025260a3b8"
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
        "SHA256": "5b81998ed98b343c04134c336e03f3051779eae0e9f882e8339593d18556375d",
        "SHA384": "db0076cad41a0ef4ea68754ef6905bd5ff772adcb745b05c0060344e43588abc95952dc3ad272f5a8f17b206e4089aca"
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
        "SHA256": "ef14ea05bb066ee9f4188196dd69cd769b283ac4d7555db52f5e76922d3456e1",
        "SHA384": "6e7450a139856aeda6fa6284ff89b3752a9b646e096b4d33dd7e8e727742a2111481531581c0aa2cda0338e22cfdbad3"
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
| Filename           |  |
| Creation Timestamp           | 2005-05-25 00:39:12 |
| MD5                | [592065b29131af32aa18a9e546be9617](https://www.virustotal.com/gui/file/592065b29131af32aa18a9e546be9617) |
| SHA1               | [079627e0f5b1ad1fb3fe64038a09bc6e8b8d289d](https://www.virustotal.com/gui/file/079627e0f5b1ad1fb3fe64038a09bc6e8b8d289d) |
| SHA256             | [f9bc6b2d5822c5b3a7b1023adceb25b47b41e664347860be4603ee81b644590e](https://www.virustotal.com/gui/file/f9bc6b2d5822c5b3a7b1023adceb25b47b41e664347860be4603ee81b644590e) |
| Authentihash MD5   | [a17d227444e090ff69e24fcb6d43162b](https://www.virustotal.com/gui/search/authentihash%253Aa17d227444e090ff69e24fcb6d43162b) |
| Authentihash SHA1  | [43d3a3c1f7b14cfcc051cae2534dbbbb4c7fc120](https://www.virustotal.com/gui/search/authentihash%253A43d3a3c1f7b14cfcc051cae2534dbbbb4c7fc120) |
| Authentihash SHA256| [b8eb26b6f79020ae988e4fb752dc06e1b6779749bf4f8df2872fc2b92bab8020](https://www.virustotal.com/gui/search/authentihash%253Ab8eb26b6f79020ae988e4fb752dc06e1b6779749bf4f8df2872fc2b92bab8020) |
| RichPEHeaderHash MD5   | [deb9c1e252f598099d70d2b33a313da3](https://www.virustotal.com/gui/search/rich_pe_header_hash%253Adeb9c1e252f598099d70d2b33a313da3) |
| RichPEHeaderHash SHA1  | [f0c2801e0091ed6f5e10ea7045e911aa90030290](https://www.virustotal.com/gui/search/rich_pe_header_hash%253Af0c2801e0091ed6f5e10ea7045e911aa90030290) |
| RichPEHeaderHash SHA256| [914fb9761d50c3fa2ecf9fbd8af3735f9b8d6c4903e067c8af9546e79b6f22c7](https://www.virustotal.com/gui/search/rich_pe_header_hash%253A914fb9761d50c3fa2ecf9fbd8af3735f9b8d6c4903e067c8af9546e79b6f22c7) |

{{< button "https://github.com/magicsword-io/LOLDrivers/raw/main/drivers/592065b29131af32aa18a9e546be9617.bin" "Download" >}} 


#### Imports
{{< details "Expand" >}}
* ntoskrnl.exe
* HAL.dll

{{< /details >}}
#### Imported Functions
{{< details "Expand" >}}
* RtlInitUnicodeString
* ZwClose
* ZwMapViewOfSection
* ObReferenceObjectByHandle
* ZwOpenSection
* IoDeleteSymbolicLink
* IofCompleteRequest
* MmIsAddressValid
* ZwUnmapViewOfSection
* IoCreateSymbolicLink
* IoCreateDevice
* __C_specific_handler
* IoDeleteDevice
* HalTranslateBusAddress

{{< /details >}}
#### Exported Functions
{{< details "Expand" >}}

{{< /details >}}

#### Sections
{{< details "Expand" >}}
* .text
* .rdata
* .data
* .pdata
* INIT

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
        "SHA256": "3ca71e85908ff67368e4dc00253f5691b9e6d50c966e7784143d75fb92aa3448",
        "SHA384": "d9d366f9328f2b55ee19a32cc5fd5148b81d764282fe5dc196c872ae249caa51d2c212ef39f33945dfe0cda81925e326"
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
        "SHA256": "cbdc9a0ad785d0c2013211746b42234e18bdc7d54a7a260647badc1c9e712ed4",
        "SHA384": "dcec542f242317863d0b3d23947e17d6982e381003831777b07ed75b46fb18bd0392a89c9beb6862981cd05f3f2fb77b"
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
        "SHA256": "4783380498acf592286ef2dea0fcc5bdea3f54d5e374d3e3497df9d5f662cfb6",
        "SHA384": "4f428f115cf3d008248f15f32007fc7c54bd454e1b48b765776b4c87c23ab8818d8fbcbb3646d35eca012b025260a3b8"
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
        "SHA256": "5b81998ed98b343c04134c336e03f3051779eae0e9f882e8339593d18556375d",
        "SHA384": "db0076cad41a0ef4ea68754ef6905bd5ff772adcb745b05c0060344e43588abc95952dc3ad272f5a8f17b206e4089aca"
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
        "SHA256": "ef14ea05bb066ee9f4188196dd69cd769b283ac4d7555db52f5e76922d3456e1",
        "SHA384": "6e7450a139856aeda6fa6284ff89b3752a9b646e096b4d33dd7e8e727742a2111481531581c0aa2cda0338e22cfdbad3"
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
| Filename           |  |
| Creation Timestamp           | 2005-05-25 00:39:12 |
| MD5                | [ada5f19423f91795c0372ff39d745acf](https://www.virustotal.com/gui/file/ada5f19423f91795c0372ff39d745acf) |
| SHA1               | [dd893cd3520b2015790f7f48023d833f8fe81374](https://www.virustotal.com/gui/file/dd893cd3520b2015790f7f48023d833f8fe81374) |
| SHA256             | [613d6cc154586c21b330018142a89eac4504e185f0be7f86af975e5b6c046c55](https://www.virustotal.com/gui/file/613d6cc154586c21b330018142a89eac4504e185f0be7f86af975e5b6c046c55) |
| Authentihash MD5   | [a17d227444e090ff69e24fcb6d43162b](https://www.virustotal.com/gui/search/authentihash%253Aa17d227444e090ff69e24fcb6d43162b) |
| Authentihash SHA1  | [43d3a3c1f7b14cfcc051cae2534dbbbb4c7fc120](https://www.virustotal.com/gui/search/authentihash%253A43d3a3c1f7b14cfcc051cae2534dbbbb4c7fc120) |
| Authentihash SHA256| [b8eb26b6f79020ae988e4fb752dc06e1b6779749bf4f8df2872fc2b92bab8020](https://www.virustotal.com/gui/search/authentihash%253Ab8eb26b6f79020ae988e4fb752dc06e1b6779749bf4f8df2872fc2b92bab8020) |
| RichPEHeaderHash MD5   | [deb9c1e252f598099d70d2b33a313da3](https://www.virustotal.com/gui/search/rich_pe_header_hash%253Adeb9c1e252f598099d70d2b33a313da3) |
| RichPEHeaderHash SHA1  | [f0c2801e0091ed6f5e10ea7045e911aa90030290](https://www.virustotal.com/gui/search/rich_pe_header_hash%253Af0c2801e0091ed6f5e10ea7045e911aa90030290) |
| RichPEHeaderHash SHA256| [914fb9761d50c3fa2ecf9fbd8af3735f9b8d6c4903e067c8af9546e79b6f22c7](https://www.virustotal.com/gui/search/rich_pe_header_hash%253A914fb9761d50c3fa2ecf9fbd8af3735f9b8d6c4903e067c8af9546e79b6f22c7) |

{{< button "https://github.com/magicsword-io/LOLDrivers/raw/main/drivers/ada5f19423f91795c0372ff39d745acf.bin" "Download" >}} 

#### Certificates

{{< details "Expand" >}}
###### Certificate 040000000000f97faa2e1e
| Field                             | Value                      |
|-----------------------------------|----------------------------|
| ToBeSigned (TBS) MD5              | 59466cb0c1788b2f251fce3495837102  |
| ToBeSigned (TBS) SHA1             | c5cfc5f6a131a3a77c3905c9893c99bb1b2baa0b |
| ToBeSigned (TBS) SHA256           | eedda02668f7636eeec69429a7164cc47ca3de0539122d37f5b8078df7ee56db |
| Subject                           | CN=GlobalSign RootSign Partners CA, OU=RootSign Partners CA, O=GlobalSign nv,sa, C=BE |
| ValidFrom                         | 2003-12-16 13:00:00 |
| ValidTo                           | 2014-01-27 11:00:00 |
| Signature                         | 5c2f2e674a26b3e7b53f353cdda003ed569af9443752163065c7d14ea20f8db7b6b6678ee74cec8d95bee6cea7227874acd7f87499b3f7ce8b1338d596cc8d76c52f38b23aae61be0b8799e321626423398d84f6858df777ffb03806f07ec1485fb5ee582606660522749283a7dbb5f992e3e8c3192c2e63efbb1fdff9f70747660d0789977ef8332c9ecbae143df11cdfa3f179afc8928f9471c4d144c554db1eb50b0aa942a3afd643391dee8f9398585bbe6e9c0bf563ec5e99c2f954fa010746da0db06424cf8ed1061d4f3ca26377455ba4bc5fb080bb31e00b54015c161d724ed52a6947d11b667e5f016ef135916be02efeb045d81627b5c58bc2da53 |
| SignatureAlgorithmOID             | 1.2.840.113549.1.1.5 |
| IsCertificateAuthority            | True |
| SerialNumber                      | 040000000000f97faa2e1e |
| Version                           | 3 |
###### Certificate 0400000000011092eb8295
| Field                             | Value                      |
|-----------------------------------|----------------------------|
| ToBeSigned (TBS) MD5              | 11d73a3638fc78e0bac6c459feadcc42  |
| ToBeSigned (TBS) SHA1             | 6636f7dcf81b370b919966f9063295ec84422f91 |
| ToBeSigned (TBS) SHA256           | 1eb5fc1d2e3254b1e3c4587a6efed87ee65306525e684b4cfa4b51893cfe86a3 |
| Subject                           | O=GlobalSign, CN=GlobalSign Time Stamping Authority, emailAddress=timestampinfo@globalsign.com |
| ValidFrom                         | 2007-02-05 09:00:00 |
| ValidTo                           | 2014-01-27 09:00:00 |
| Signature                         | 649b07caaccc411e37ef6f349cb5e8ca48f9daeafaf7172e5cad193b7311ec5adbfd7b213161c092515bb166b07c64d8fe10b471a8bc9e75379c5f6ff2da0437b8ecc003e256b7785995581d7a7c3e18d74c32bdf91ee723457fdee08d65825b45fd64c66fc3d7ea12411d0c395ef696f8c3cd9e1fff51886976988b8eb42788821ad63c7aabb04eb73ee8d434d2c1a439533cb2747b15373054a6ebb924cc2f084b4364f14aaf8d9ce8546cb2dbdc3bb1c722849f558e72a8b2a8f6f0ff03c996ebab8273dabe45561936fdba6cbc71f0d3c7c376d7e4bce2a1a67200cfbdb200ed92aa39ab09d16e3953862ad43b517398b754e9972d9977ee123e3642257f |
| SignatureAlgorithmOID             | 1.2.840.113549.1.1.5 |
| IsCertificateAuthority            | True |
| SerialNumber                      | 0400000000011092eb8295 |
| Version                           | 3 |
###### Certificate 4191a15a3978dfcf496566381d4c75c2
| Field                             | Value                      |
|-----------------------------------|----------------------------|
| ToBeSigned (TBS) MD5              | 41011f8d0e7c7a6408334ca387914c61  |
| ToBeSigned (TBS) SHA1             | c7fc1727f5b75a6421a1f95c73bbdb23580c48e5 |
| ToBeSigned (TBS) SHA256           | 88dd3952638ee82738c03168e6fd863fe4eab1059ee5e2926ad8cb587c255dc0 |
| Subject                           | C=US, O=VeriSign, Inc., OU=VeriSign Trust Network, OU=Terms of use at https://www.verisign.com/rpa (c)04, CN=VeriSign Class 3 Code Signing 2004 CA |
| ValidFrom                         | 2004-07-16 00:00:00 |
| ValidTo                           | 2014-07-15 23:59:59 |
| Signature                         | ae3a17b84a7b55fa6455ec40a4ed494190999c89bcaf2e1dca7823f91c190f7feb68bc32d98838dedc3fd389b43fb18296f1a45abaed2e26d3de7c016e000a00a4069211480940f91c1879672324e0bbd5e150ae1bf50edde02e81cd80a36c524f9175558aba22f2d2ea4175882f63557d1e545a9559cad93481c05f5ef67ab5 |
| SignatureAlgorithmOID             | 1.2.840.113549.1.1.5 |
| IsCertificateAuthority            | True |
| SerialNumber                      | 4191a15a3978dfcf496566381d4c75c2 |
| Version                           | 3 |
###### Certificate 546ea040bf5075ce0a5c01d4c6ded19d
| Field                             | Value                      |
|-----------------------------------|----------------------------|
| ToBeSigned (TBS) MD5              | 8f51b4e16b87e1cc89b9d0c997227546  |
| ToBeSigned (TBS) SHA1             | 8f3cdd2b86ae03653f0612911a2f01a9dca49a22 |
| ToBeSigned (TBS) SHA256           | c7f57b7287c808d2713aba9e368fe387b5825bfbda1bd1824f374beaa8e30be9 |
| Subject                           | C=US, ST=California, L=Brea, O=EVGA, OU=Digital ID Class 3 , Microsoft Software Validation v2, CN=EVGA |
| ValidFrom                         | 2008-04-16 00:00:00 |
| ValidTo                           | 2010-04-16 23:59:59 |
| Signature                         | 13a3b8caa6bd8d63308898b0c92b79574e5d122a3ecba9758ec450b7c8c848ee5bc486db6370a8dfeb4c96c2c25512f7a3e759cc57a4d92f1a44fba15ca0c1156d22c49251b4e6a01bb93e4a62522ee5af4286c759c01c66fa5ce4452a4f112d03560bfa9737a3d0f3008b3cc48f2042b4428643f1efb4b99a34d0545c9934f1a6f35819e469430b74ba475a2135660948131cf24c9b1fb84580a1fd63eb3218d282e4f7caf77f4adbecb51e4b8237937eda0b7fcc20fc2273bf38282ee69ae6730b21c5314bcdc3f2e3a1e6f6c3ccb2139800f69d3f2fadc235080214f1c9b11e6a8f2165a45e15cca3c3542c2bac7225208a84828456d2e93cfe8315b092a1 |
| SignatureAlgorithmOID             | 1.2.840.113549.1.1.5 |
| IsCertificateAuthority            | False |
| SerialNumber                      | 546ea040bf5075ce0a5c01d4c6ded19d |
| Version                           | 3 |
###### Certificate 610c120600000000001b
| Field                             | Value                      |
|-----------------------------------|----------------------------|
| ToBeSigned (TBS) MD5              | 53c41bc1164e09e0cd1617a5bf913efd  |
| ToBeSigned (TBS) SHA1             | 93c03aac8951d494ecd5696b1c08658541b18727 |
| ToBeSigned (TBS) SHA256           | 40bddadac24dc61ca4fb5cab2a2bc5d876bc36808311039a7a3e1a4066f7489b |
| Subject                           | C=US, O=VeriSign, Inc., OU=Class 3 Public Primary Certification Authority |
| ValidFrom                         | 2006-05-23 17:01:29 |
| ValidTo                           | 2016-05-23 17:11:29 |
| Signature                         | 01e446b33b457f7513877e5f43de468ecb8abdb64741bccccc7491d8ce395195a4a6b547c0efd2da7b8f5711f4328c7ccd3fee42da04214af7c843884a6f5cca14fc4bd19f4cbdd4556ecc02be0da6888f8609baa425bde8b0f0fa8b714e67b0cb82a8d78e55f737ebf03e88efe4e08afd1c6e2e61414875b4b02c1d28d8490fd715f02473253ccc880cde284c6554fe5eae8cea19ad2c51b29b3a47f53c80350117e24987d6544afb4bab07bcbf7d79cfbf35005cbb9ecffc82891b39a05197b6dec0b307ff449644c0342a195cabeef03bec294eb513c537857e75d5b4d60d066eb5d26c237167eaf1718eaf4e74aa0cf9ecbf4c58fa5e909b6d39cb86883f8b1ca81632d5fe6db9f1f8b3ead791f6364778c0272a15c768d6f4c5fc4f4ec8673f102d409ff11ec96148e7a703fc31730cf04688fe56da492995ef09daa3e5beef60ecd954a0599c28bd54ef66157f874c84dba60e95672e517b3439b641c28c846826dc240209e7818e0a972defeea7b998a60f818dc710b5e1ed982f486f53854964789bec5dac970b5526c3efba8dc8d1a52f5a7f936b611a339b18b8a26210de24ea76e12f43ebecdd7c12342489da2855aee5754e312b6763b6a8d7ab730a03cec5ea593fc7eb2a45aea8625b2f009939abb45f73c308ec80118f470e8f2a1343e191066255bbffba3da9a93d260faeca7d628b155589d694344dd665 |
| SignatureAlgorithmOID             | 1.2.840.113549.1.1.5 |
| IsCertificateAuthority            | True |
| SerialNumber                      | 610c120600000000001b |
| Version                           | 3 |

{{< /details >}}
#### Imports
{{< details "Expand" >}}
* ntoskrnl.exe
* HAL.dll

{{< /details >}}
#### Imported Functions
{{< details "Expand" >}}
* RtlInitUnicodeString
* ZwClose
* ZwMapViewOfSection
* ObReferenceObjectByHandle
* ZwOpenSection
* IoDeleteSymbolicLink
* IofCompleteRequest
* MmIsAddressValid
* ZwUnmapViewOfSection
* IoCreateSymbolicLink
* IoCreateDevice
* __C_specific_handler
* IoDeleteDevice
* HalTranslateBusAddress

{{< /details >}}
#### Exported Functions
{{< details "Expand" >}}

{{< /details >}}

#### Sections
{{< details "Expand" >}}
* .text
* .rdata
* .data
* .pdata
* INIT

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
        "SHA256": "3ca71e85908ff67368e4dc00253f5691b9e6d50c966e7784143d75fb92aa3448",
        "SHA384": "d9d366f9328f2b55ee19a32cc5fd5148b81d764282fe5dc196c872ae249caa51d2c212ef39f33945dfe0cda81925e326"
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
        "SHA256": "cbdc9a0ad785d0c2013211746b42234e18bdc7d54a7a260647badc1c9e712ed4",
        "SHA384": "dcec542f242317863d0b3d23947e17d6982e381003831777b07ed75b46fb18bd0392a89c9beb6862981cd05f3f2fb77b"
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
        "SHA256": "4783380498acf592286ef2dea0fcc5bdea3f54d5e374d3e3497df9d5f662cfb6",
        "SHA384": "4f428f115cf3d008248f15f32007fc7c54bd454e1b48b765776b4c87c23ab8818d8fbcbb3646d35eca012b025260a3b8"
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
        "SHA256": "5b81998ed98b343c04134c336e03f3051779eae0e9f882e8339593d18556375d",
        "SHA384": "db0076cad41a0ef4ea68754ef6905bd5ff772adcb745b05c0060344e43588abc95952dc3ad272f5a8f17b206e4089aca"
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
        "SHA256": "ef14ea05bb066ee9f4188196dd69cd769b283ac4d7555db52f5e76922d3456e1",
        "SHA384": "6e7450a139856aeda6fa6284ff89b3752a9b646e096b4d33dd7e8e727742a2111481531581c0aa2cda0338e22cfdbad3"
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
| Filename           |  |
| Creation Timestamp           | 2005-05-25 00:39:12 |
| MD5                | [8a108158431e9a7d08e330fd7a46d175](https://www.virustotal.com/gui/file/8a108158431e9a7d08e330fd7a46d175) |
| SHA1               | [27aa3f1b4baccd70d95ea75a0a3e54e735728aa2](https://www.virustotal.com/gui/file/27aa3f1b4baccd70d95ea75a0a3e54e735728aa2) |
| SHA256             | [0e10d3c73596e359462dc6bfcb886768486ff59e158f0f872d23c5e9a2f7c168](https://www.virustotal.com/gui/file/0e10d3c73596e359462dc6bfcb886768486ff59e158f0f872d23c5e9a2f7c168) |
| Authentihash MD5   | [a17d227444e090ff69e24fcb6d43162b](https://www.virustotal.com/gui/search/authentihash%253Aa17d227444e090ff69e24fcb6d43162b) |
| Authentihash SHA1  | [43d3a3c1f7b14cfcc051cae2534dbbbb4c7fc120](https://www.virustotal.com/gui/search/authentihash%253A43d3a3c1f7b14cfcc051cae2534dbbbb4c7fc120) |
| Authentihash SHA256| [b8eb26b6f79020ae988e4fb752dc06e1b6779749bf4f8df2872fc2b92bab8020](https://www.virustotal.com/gui/search/authentihash%253Ab8eb26b6f79020ae988e4fb752dc06e1b6779749bf4f8df2872fc2b92bab8020) |
| RichPEHeaderHash MD5   | [deb9c1e252f598099d70d2b33a313da3](https://www.virustotal.com/gui/search/rich_pe_header_hash%253Adeb9c1e252f598099d70d2b33a313da3) |
| RichPEHeaderHash SHA1  | [f0c2801e0091ed6f5e10ea7045e911aa90030290](https://www.virustotal.com/gui/search/rich_pe_header_hash%253Af0c2801e0091ed6f5e10ea7045e911aa90030290) |
| RichPEHeaderHash SHA256| [914fb9761d50c3fa2ecf9fbd8af3735f9b8d6c4903e067c8af9546e79b6f22c7](https://www.virustotal.com/gui/search/rich_pe_header_hash%253A914fb9761d50c3fa2ecf9fbd8af3735f9b8d6c4903e067c8af9546e79b6f22c7) |

{{< button "https://github.com/magicsword-io/LOLDrivers/raw/main/drivers/8a108158431e9a7d08e330fd7a46d175.bin" "Download" >}} 

#### Certificates

{{< details "Expand" >}}
###### Certificate 0400000000012019c19066
| Field                             | Value                      |
|-----------------------------------|----------------------------|
| ToBeSigned (TBS) MD5              | 42023b9487cafe46c1b6a49c369a362e  |
| ToBeSigned (TBS) SHA1             | 7c7b524d269334b9f073c32e888e09544c6acd98 |
| ToBeSigned (TBS) SHA256           | b7126567833f3daa4085ff41e73112daad3d1e3808a942c1936520e2d6c46c78 |
| Subject                           | OU=Timestamping CA, O=GlobalSign, CN=GlobalSign Timestamping CA |
| ValidFrom                         | 2009-03-18 11:00:00 |
| ValidTo                           | 2028-01-28 12:00:00 |
| Signature                         | 5df6cb2b0d0140849f857a43706ae0c5e7aa0600d76713c9089131654f14a8a905dc389e6aa0300abd8dc78028ee4245ca94f3de5845a9803204f5595c6a70003927944df5b44634e81c5331b2b35416e9cc42abd5d959301cfb462725b88723b1e8758824831ec876377b01494548a4ede25dd27c9ca2dc2dba105a126265abae00c710343bcb72bd14240cdcc37627b4a7fee15829f20e169f91391d89a6e60f1c878ce258ac927e243eaaec14e73a33348bc63bac83ab0f14627aba1a2d4d4b1bc530f00b92797d3c78e0f8e6d215965999392b3061e8b8f8c0a1e9221411787dc4dc89bec0bb94e172aeebb540404fef171e585ed0a88996ac9228e9babf |
| SignatureAlgorithmOID             | 1.2.840.113549.1.1.5 |
| IsCertificateAuthority            | True |
| SerialNumber                      | 0400000000012019c19066 |
| Version                           | 3 |
###### Certificate 01000000000125b0b4cc01
| Field                             | Value                      |
|-----------------------------------|----------------------------|
| ToBeSigned (TBS) MD5              | e3369c8e5aec0504b3a50455f615d9f9  |
| ToBeSigned (TBS) SHA1             | 13c244a894b40ecd18aaf97c362f20385bd005a7 |
| ToBeSigned (TBS) SHA256           | 26da721a670c72836926032fee6920118bfb9bff89cc8d0ce30d9452c33f2532 |
| Subject                           | C=BE, O=GlobalSign NV, CN=GlobalSign Time Stamping Authority |
| ValidFrom                         | 2009-12-21 09:32:56 |
| ValidTo                           | 2020-12-22 09:32:56 |
| Signature                         | bc89ecfee63655935c79d4117a86808f17b693b26d9b91a1561811c655eaf608edad9b9ef52b81c8bbdd607b1b47991e6d403e1d80c213d58e04052fdbe7ae529e688472a1e54a603cf89bd52f46d8c3b2b79353ac9b6c432424d1f1fce9562e3411581843eaefff34746ca0c06c7fad031969881e9560cabbbd0cbb76efc724b081c63831cf36ad0c38b89020849b2e8f28b99ff6ca9427cdac396157e0e3955a9c769230f5dea6973d721c2a6032a8334d8635338a5cf3a4fdf7062ce16b4b30f5cbd34362f841b9de7d20cb058c8e2cf65f35fd338d42896508362ca389f45a858bb0b97bdb6ccba1f8d20e1bbb977cd12779be9d7c3be6a75634d8c991a9 |
| SignatureAlgorithmOID             | 1.2.840.113549.1.1.5 |
| IsCertificateAuthority            | False |
| SerialNumber                      | 01000000000125b0b4cc01 |
| Version                           | 3 |
###### Certificate 79c32d7ddd2458cf2eabe5b1b5c5290f
| Field                             | Value                      |
|-----------------------------------|----------------------------|
| ToBeSigned (TBS) MD5              | 5ba772ec00357ae706016510775c7a00  |
| ToBeSigned (TBS) SHA1             | eeb31b244ea14abae1e947ecdca0d6ae4720031b |
| ToBeSigned (TBS) SHA256           | c8e707c2615c26ac78ed06b42dd20bc8ff82bc5e02ddafe2c9af85755097691b |
| Subject                           | C=US, ST=California, L=Brea, O=EVGA, OU=Digital ID Class 3 , Microsoft Software Validation v2, CN=EVGA |
| ValidFrom                         | 2010-04-14 00:00:00 |
| ValidTo                           | 2012-04-15 23:59:59 |
| Signature                         | ba96817224593697c9135d803c5fc87767f2a7ed8fa0aa18eab4030a3daed18c55fb7eda8835d0488d18136c0db39d8edf3224790842cdf8580b35324631de717e9279d28d605285615341aeea10a73005d59cbe3138bebfa5003cbcf2971249423d820d6d252a18bf4dd124a1ac0c2f66015cbb23690e1b0fb9d5ce3f047663f1fb6735e54f09cfb6162da298bdc956490586cfdadee74a5766c187223e19112d22f59c7f3f325449afebc42689ec4c9399bd0d97397c37230804a4e5bc17e904008aa9c5972e2332302e57648006d057c9ed8c6384fb42d138971c86079b155c202733b837b3eef122c866ce3e6d8a8d9f1685e618cc2466d623d212b73df6 |
| SignatureAlgorithmOID             | 1.2.840.113549.1.1.5 |
| IsCertificateAuthority            | False |
| SerialNumber                      | 79c32d7ddd2458cf2eabe5b1b5c5290f |
| Version                           | 3 |
###### Certificate 655226e1b22e18e1590f2985ac22e75c
| Field                             | Value                      |
|-----------------------------------|----------------------------|
| ToBeSigned (TBS) MD5              | 650704c342850095f3288eaf791147d4  |
| ToBeSigned (TBS) SHA1             | 4cdc38c800761463749c3cbd94a12f32e49877bf |
| ToBeSigned (TBS) SHA256           | 07b8f662558ec85b71b43a79c6e94698144f4ced2308af21e7ba1e5d461da214 |
| Subject                           | C=US, O=VeriSign, Inc., OU=VeriSign Trust Network, OU=Terms of use at https://www.verisign.com/rpa (c)09, CN=VeriSign Class 3 Code Signing 2009,2 CA |
| ValidFrom                         | 2009-05-21 00:00:00 |
| ValidTo                           | 2019-05-20 23:59:59 |
| Signature                         | 8b03c0dd94d841a26169b015a878c730c6903c7e42f724b6e4837317047f04109ca1e2fa812febc0ca44e772e050b6551020836e9692e49a516ab43731dca52deb8c00c71d4fe74d32ba85f84ebefa675565f06abe7aca64381a101078457631f3867a030f60c2b35d9df68b6676821b59e183e5bd49a53856e5de41770e580f |
| SignatureAlgorithmOID             | 1.2.840.113549.1.1.5 |
| IsCertificateAuthority            | True |
| SerialNumber                      | 655226e1b22e18e1590f2985ac22e75c |
| Version                           | 3 |
###### Certificate 610c120600000000001b
| Field                             | Value                      |
|-----------------------------------|----------------------------|
| ToBeSigned (TBS) MD5              | 53c41bc1164e09e0cd1617a5bf913efd  |
| ToBeSigned (TBS) SHA1             | 93c03aac8951d494ecd5696b1c08658541b18727 |
| ToBeSigned (TBS) SHA256           | 40bddadac24dc61ca4fb5cab2a2bc5d876bc36808311039a7a3e1a4066f7489b |
| Subject                           | C=US, O=VeriSign, Inc., OU=Class 3 Public Primary Certification Authority |
| ValidFrom                         | 2006-05-23 17:01:29 |
| ValidTo                           | 2016-05-23 17:11:29 |
| Signature                         | 01e446b33b457f7513877e5f43de468ecb8abdb64741bccccc7491d8ce395195a4a6b547c0efd2da7b8f5711f4328c7ccd3fee42da04214af7c843884a6f5cca14fc4bd19f4cbdd4556ecc02be0da6888f8609baa425bde8b0f0fa8b714e67b0cb82a8d78e55f737ebf03e88efe4e08afd1c6e2e61414875b4b02c1d28d8490fd715f02473253ccc880cde284c6554fe5eae8cea19ad2c51b29b3a47f53c80350117e24987d6544afb4bab07bcbf7d79cfbf35005cbb9ecffc82891b39a05197b6dec0b307ff449644c0342a195cabeef03bec294eb513c537857e75d5b4d60d066eb5d26c237167eaf1718eaf4e74aa0cf9ecbf4c58fa5e909b6d39cb86883f8b1ca81632d5fe6db9f1f8b3ead791f6364778c0272a15c768d6f4c5fc4f4ec8673f102d409ff11ec96148e7a703fc31730cf04688fe56da492995ef09daa3e5beef60ecd954a0599c28bd54ef66157f874c84dba60e95672e517b3439b641c28c846826dc240209e7818e0a972defeea7b998a60f818dc710b5e1ed982f486f53854964789bec5dac970b5526c3efba8dc8d1a52f5a7f936b611a339b18b8a26210de24ea76e12f43ebecdd7c12342489da2855aee5754e312b6763b6a8d7ab730a03cec5ea593fc7eb2a45aea8625b2f009939abb45f73c308ec80118f470e8f2a1343e191066255bbffba3da9a93d260faeca7d628b155589d694344dd665 |
| SignatureAlgorithmOID             | 1.2.840.113549.1.1.5 |
| IsCertificateAuthority            | True |
| SerialNumber                      | 610c120600000000001b |
| Version                           | 3 |

{{< /details >}}
#### Imports
{{< details "Expand" >}}
* ntoskrnl.exe
* HAL.dll

{{< /details >}}
#### Imported Functions
{{< details "Expand" >}}
* RtlInitUnicodeString
* ZwClose
* ZwMapViewOfSection
* ObReferenceObjectByHandle
* ZwOpenSection
* IoDeleteSymbolicLink
* IofCompleteRequest
* MmIsAddressValid
* ZwUnmapViewOfSection
* IoCreateSymbolicLink
* IoCreateDevice
* __C_specific_handler
* IoDeleteDevice
* HalTranslateBusAddress

{{< /details >}}
#### Exported Functions
{{< details "Expand" >}}

{{< /details >}}

#### Sections
{{< details "Expand" >}}
* .text
* .rdata
* .data
* .pdata
* INIT

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
        "SHA256": "3ca71e85908ff67368e4dc00253f5691b9e6d50c966e7784143d75fb92aa3448",
        "SHA384": "d9d366f9328f2b55ee19a32cc5fd5148b81d764282fe5dc196c872ae249caa51d2c212ef39f33945dfe0cda81925e326"
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
        "SHA256": "cbdc9a0ad785d0c2013211746b42234e18bdc7d54a7a260647badc1c9e712ed4",
        "SHA384": "dcec542f242317863d0b3d23947e17d6982e381003831777b07ed75b46fb18bd0392a89c9beb6862981cd05f3f2fb77b"
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
        "SHA256": "4783380498acf592286ef2dea0fcc5bdea3f54d5e374d3e3497df9d5f662cfb6",
        "SHA384": "4f428f115cf3d008248f15f32007fc7c54bd454e1b48b765776b4c87c23ab8818d8fbcbb3646d35eca012b025260a3b8"
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
        "SHA256": "5b81998ed98b343c04134c336e03f3051779eae0e9f882e8339593d18556375d",
        "SHA384": "db0076cad41a0ef4ea68754ef6905bd5ff772adcb745b05c0060344e43588abc95952dc3ad272f5a8f17b206e4089aca"
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
        "SHA256": "ef14ea05bb066ee9f4188196dd69cd769b283ac4d7555db52f5e76922d3456e1",
        "SHA384": "6e7450a139856aeda6fa6284ff89b3752a9b646e096b4d33dd7e8e727742a2111481531581c0aa2cda0338e22cfdbad3"
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
| Filename           |  |
| Creation Timestamp           | 2005-05-25 00:39:12 |
| MD5                | [c475c7d0f2d934f150b6c32c01479134](https://www.virustotal.com/gui/file/c475c7d0f2d934f150b6c32c01479134) |
| SHA1               | [2739c2cfa8306e6f78c335c55639566b3d450644](https://www.virustotal.com/gui/file/2739c2cfa8306e6f78c335c55639566b3d450644) |
| SHA256             | [54bf602a6f1baaec5809a630a5c33f76f1c3147e4b05cecf17b96a93b1d41dca](https://www.virustotal.com/gui/file/54bf602a6f1baaec5809a630a5c33f76f1c3147e4b05cecf17b96a93b1d41dca) |
| Authentihash MD5   | [a17d227444e090ff69e24fcb6d43162b](https://www.virustotal.com/gui/search/authentihash%253Aa17d227444e090ff69e24fcb6d43162b) |
| Authentihash SHA1  | [43d3a3c1f7b14cfcc051cae2534dbbbb4c7fc120](https://www.virustotal.com/gui/search/authentihash%253A43d3a3c1f7b14cfcc051cae2534dbbbb4c7fc120) |
| Authentihash SHA256| [b8eb26b6f79020ae988e4fb752dc06e1b6779749bf4f8df2872fc2b92bab8020](https://www.virustotal.com/gui/search/authentihash%253Ab8eb26b6f79020ae988e4fb752dc06e1b6779749bf4f8df2872fc2b92bab8020) |
| RichPEHeaderHash MD5   | [deb9c1e252f598099d70d2b33a313da3](https://www.virustotal.com/gui/search/rich_pe_header_hash%253Adeb9c1e252f598099d70d2b33a313da3) |
| RichPEHeaderHash SHA1  | [f0c2801e0091ed6f5e10ea7045e911aa90030290](https://www.virustotal.com/gui/search/rich_pe_header_hash%253Af0c2801e0091ed6f5e10ea7045e911aa90030290) |
| RichPEHeaderHash SHA256| [914fb9761d50c3fa2ecf9fbd8af3735f9b8d6c4903e067c8af9546e79b6f22c7](https://www.virustotal.com/gui/search/rich_pe_header_hash%253A914fb9761d50c3fa2ecf9fbd8af3735f9b8d6c4903e067c8af9546e79b6f22c7) |

{{< button "https://github.com/magicsword-io/LOLDrivers/raw/main/drivers/c475c7d0f2d934f150b6c32c01479134.bin" "Download" >}} 

#### Certificates

{{< details "Expand" >}}
###### Certificate 0400000000012019c19066
| Field                             | Value                      |
|-----------------------------------|----------------------------|
| ToBeSigned (TBS) MD5              | 42023b9487cafe46c1b6a49c369a362e  |
| ToBeSigned (TBS) SHA1             | 7c7b524d269334b9f073c32e888e09544c6acd98 |
| ToBeSigned (TBS) SHA256           | b7126567833f3daa4085ff41e73112daad3d1e3808a942c1936520e2d6c46c78 |
| Subject                           | OU=Timestamping CA, O=GlobalSign, CN=GlobalSign Timestamping CA |
| ValidFrom                         | 2009-03-18 11:00:00 |
| ValidTo                           | 2028-01-28 12:00:00 |
| Signature                         | 5df6cb2b0d0140849f857a43706ae0c5e7aa0600d76713c9089131654f14a8a905dc389e6aa0300abd8dc78028ee4245ca94f3de5845a9803204f5595c6a70003927944df5b44634e81c5331b2b35416e9cc42abd5d959301cfb462725b88723b1e8758824831ec876377b01494548a4ede25dd27c9ca2dc2dba105a126265abae00c710343bcb72bd14240cdcc37627b4a7fee15829f20e169f91391d89a6e60f1c878ce258ac927e243eaaec14e73a33348bc63bac83ab0f14627aba1a2d4d4b1bc530f00b92797d3c78e0f8e6d215965999392b3061e8b8f8c0a1e9221411787dc4dc89bec0bb94e172aeebb540404fef171e585ed0a88996ac9228e9babf |
| SignatureAlgorithmOID             | 1.2.840.113549.1.1.5 |
| IsCertificateAuthority            | True |
| SerialNumber                      | 0400000000012019c19066 |
| Version                           | 3 |
###### Certificate 01000000000125b0b4cc01
| Field                             | Value                      |
|-----------------------------------|----------------------------|
| ToBeSigned (TBS) MD5              | e3369c8e5aec0504b3a50455f615d9f9  |
| ToBeSigned (TBS) SHA1             | 13c244a894b40ecd18aaf97c362f20385bd005a7 |
| ToBeSigned (TBS) SHA256           | 26da721a670c72836926032fee6920118bfb9bff89cc8d0ce30d9452c33f2532 |
| Subject                           | C=BE, O=GlobalSign NV, CN=GlobalSign Time Stamping Authority |
| ValidFrom                         | 2009-12-21 09:32:56 |
| ValidTo                           | 2020-12-22 09:32:56 |
| Signature                         | bc89ecfee63655935c79d4117a86808f17b693b26d9b91a1561811c655eaf608edad9b9ef52b81c8bbdd607b1b47991e6d403e1d80c213d58e04052fdbe7ae529e688472a1e54a603cf89bd52f46d8c3b2b79353ac9b6c432424d1f1fce9562e3411581843eaefff34746ca0c06c7fad031969881e9560cabbbd0cbb76efc724b081c63831cf36ad0c38b89020849b2e8f28b99ff6ca9427cdac396157e0e3955a9c769230f5dea6973d721c2a6032a8334d8635338a5cf3a4fdf7062ce16b4b30f5cbd34362f841b9de7d20cb058c8e2cf65f35fd338d42896508362ca389f45a858bb0b97bdb6ccba1f8d20e1bbb977cd12779be9d7c3be6a75634d8c991a9 |
| SignatureAlgorithmOID             | 1.2.840.113549.1.1.5 |
| IsCertificateAuthority            | False |
| SerialNumber                      | 01000000000125b0b4cc01 |
| Version                           | 3 |
###### Certificate 79c32d7ddd2458cf2eabe5b1b5c5290f
| Field                             | Value                      |
|-----------------------------------|----------------------------|
| ToBeSigned (TBS) MD5              | 5ba772ec00357ae706016510775c7a00  |
| ToBeSigned (TBS) SHA1             | eeb31b244ea14abae1e947ecdca0d6ae4720031b |
| ToBeSigned (TBS) SHA256           | c8e707c2615c26ac78ed06b42dd20bc8ff82bc5e02ddafe2c9af85755097691b |
| Subject                           | C=US, ST=California, L=Brea, O=EVGA, OU=Digital ID Class 3 , Microsoft Software Validation v2, CN=EVGA |
| ValidFrom                         | 2010-04-14 00:00:00 |
| ValidTo                           | 2012-04-15 23:59:59 |
| Signature                         | ba96817224593697c9135d803c5fc87767f2a7ed8fa0aa18eab4030a3daed18c55fb7eda8835d0488d18136c0db39d8edf3224790842cdf8580b35324631de717e9279d28d605285615341aeea10a73005d59cbe3138bebfa5003cbcf2971249423d820d6d252a18bf4dd124a1ac0c2f66015cbb23690e1b0fb9d5ce3f047663f1fb6735e54f09cfb6162da298bdc956490586cfdadee74a5766c187223e19112d22f59c7f3f325449afebc42689ec4c9399bd0d97397c37230804a4e5bc17e904008aa9c5972e2332302e57648006d057c9ed8c6384fb42d138971c86079b155c202733b837b3eef122c866ce3e6d8a8d9f1685e618cc2466d623d212b73df6 |
| SignatureAlgorithmOID             | 1.2.840.113549.1.1.5 |
| IsCertificateAuthority            | False |
| SerialNumber                      | 79c32d7ddd2458cf2eabe5b1b5c5290f |
| Version                           | 3 |
###### Certificate 655226e1b22e18e1590f2985ac22e75c
| Field                             | Value                      |
|-----------------------------------|----------------------------|
| ToBeSigned (TBS) MD5              | 650704c342850095f3288eaf791147d4  |
| ToBeSigned (TBS) SHA1             | 4cdc38c800761463749c3cbd94a12f32e49877bf |
| ToBeSigned (TBS) SHA256           | 07b8f662558ec85b71b43a79c6e94698144f4ced2308af21e7ba1e5d461da214 |
| Subject                           | C=US, O=VeriSign, Inc., OU=VeriSign Trust Network, OU=Terms of use at https://www.verisign.com/rpa (c)09, CN=VeriSign Class 3 Code Signing 2009,2 CA |
| ValidFrom                         | 2009-05-21 00:00:00 |
| ValidTo                           | 2019-05-20 23:59:59 |
| Signature                         | 8b03c0dd94d841a26169b015a878c730c6903c7e42f724b6e4837317047f04109ca1e2fa812febc0ca44e772e050b6551020836e9692e49a516ab43731dca52deb8c00c71d4fe74d32ba85f84ebefa675565f06abe7aca64381a101078457631f3867a030f60c2b35d9df68b6676821b59e183e5bd49a53856e5de41770e580f |
| SignatureAlgorithmOID             | 1.2.840.113549.1.1.5 |
| IsCertificateAuthority            | True |
| SerialNumber                      | 655226e1b22e18e1590f2985ac22e75c |
| Version                           | 3 |
###### Certificate 610c120600000000001b
| Field                             | Value                      |
|-----------------------------------|----------------------------|
| ToBeSigned (TBS) MD5              | 53c41bc1164e09e0cd1617a5bf913efd  |
| ToBeSigned (TBS) SHA1             | 93c03aac8951d494ecd5696b1c08658541b18727 |
| ToBeSigned (TBS) SHA256           | 40bddadac24dc61ca4fb5cab2a2bc5d876bc36808311039a7a3e1a4066f7489b |
| Subject                           | C=US, O=VeriSign, Inc., OU=Class 3 Public Primary Certification Authority |
| ValidFrom                         | 2006-05-23 17:01:29 |
| ValidTo                           | 2016-05-23 17:11:29 |
| Signature                         | 01e446b33b457f7513877e5f43de468ecb8abdb64741bccccc7491d8ce395195a4a6b547c0efd2da7b8f5711f4328c7ccd3fee42da04214af7c843884a6f5cca14fc4bd19f4cbdd4556ecc02be0da6888f8609baa425bde8b0f0fa8b714e67b0cb82a8d78e55f737ebf03e88efe4e08afd1c6e2e61414875b4b02c1d28d8490fd715f02473253ccc880cde284c6554fe5eae8cea19ad2c51b29b3a47f53c80350117e24987d6544afb4bab07bcbf7d79cfbf35005cbb9ecffc82891b39a05197b6dec0b307ff449644c0342a195cabeef03bec294eb513c537857e75d5b4d60d066eb5d26c237167eaf1718eaf4e74aa0cf9ecbf4c58fa5e909b6d39cb86883f8b1ca81632d5fe6db9f1f8b3ead791f6364778c0272a15c768d6f4c5fc4f4ec8673f102d409ff11ec96148e7a703fc31730cf04688fe56da492995ef09daa3e5beef60ecd954a0599c28bd54ef66157f874c84dba60e95672e517b3439b641c28c846826dc240209e7818e0a972defeea7b998a60f818dc710b5e1ed982f486f53854964789bec5dac970b5526c3efba8dc8d1a52f5a7f936b611a339b18b8a26210de24ea76e12f43ebecdd7c12342489da2855aee5754e312b6763b6a8d7ab730a03cec5ea593fc7eb2a45aea8625b2f009939abb45f73c308ec80118f470e8f2a1343e191066255bbffba3da9a93d260faeca7d628b155589d694344dd665 |
| SignatureAlgorithmOID             | 1.2.840.113549.1.1.5 |
| IsCertificateAuthority            | True |
| SerialNumber                      | 610c120600000000001b |
| Version                           | 3 |

{{< /details >}}
#### Imports
{{< details "Expand" >}}
* ntoskrnl.exe
* HAL.dll

{{< /details >}}
#### Imported Functions
{{< details "Expand" >}}
* RtlInitUnicodeString
* ZwClose
* ZwMapViewOfSection
* ObReferenceObjectByHandle
* ZwOpenSection
* IoDeleteSymbolicLink
* IofCompleteRequest
* MmIsAddressValid
* ZwUnmapViewOfSection
* IoCreateSymbolicLink
* IoCreateDevice
* __C_specific_handler
* IoDeleteDevice
* HalTranslateBusAddress

{{< /details >}}
#### Exported Functions
{{< details "Expand" >}}

{{< /details >}}

#### Sections
{{< details "Expand" >}}
* .text
* .rdata
* .data
* .pdata
* INIT

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
        "SHA256": "3ca71e85908ff67368e4dc00253f5691b9e6d50c966e7784143d75fb92aa3448",
        "SHA384": "d9d366f9328f2b55ee19a32cc5fd5148b81d764282fe5dc196c872ae249caa51d2c212ef39f33945dfe0cda81925e326"
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
        "SHA256": "cbdc9a0ad785d0c2013211746b42234e18bdc7d54a7a260647badc1c9e712ed4",
        "SHA384": "dcec542f242317863d0b3d23947e17d6982e381003831777b07ed75b46fb18bd0392a89c9beb6862981cd05f3f2fb77b"
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
        "SHA256": "4783380498acf592286ef2dea0fcc5bdea3f54d5e374d3e3497df9d5f662cfb6",
        "SHA384": "4f428f115cf3d008248f15f32007fc7c54bd454e1b48b765776b4c87c23ab8818d8fbcbb3646d35eca012b025260a3b8"
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
        "SHA256": "5b81998ed98b343c04134c336e03f3051779eae0e9f882e8339593d18556375d",
        "SHA384": "db0076cad41a0ef4ea68754ef6905bd5ff772adcb745b05c0060344e43588abc95952dc3ad272f5a8f17b206e4089aca"
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
        "SHA256": "ef14ea05bb066ee9f4188196dd69cd769b283ac4d7555db52f5e76922d3456e1",
        "SHA384": "6e7450a139856aeda6fa6284ff89b3752a9b646e096b4d33dd7e8e727742a2111481531581c0aa2cda0338e22cfdbad3"
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
| Filename           |  |
| Creation Timestamp           | 2005-05-25 00:39:12 |
| MD5                | [79b8119b012352d255961e76605567d6](https://www.virustotal.com/gui/file/79b8119b012352d255961e76605567d6) |
| SHA1               | [ea63567ea8d168cb6e9aae705b80a09f927b2f77](https://www.virustotal.com/gui/file/ea63567ea8d168cb6e9aae705b80a09f927b2f77) |
| SHA256             | [7149fbd191d7e4941a32a3118ab017426b551d5d369f20c94c4f36ae4ef54f26](https://www.virustotal.com/gui/file/7149fbd191d7e4941a32a3118ab017426b551d5d369f20c94c4f36ae4ef54f26) |
| Authentihash MD5   | [a17d227444e090ff69e24fcb6d43162b](https://www.virustotal.com/gui/search/authentihash%253Aa17d227444e090ff69e24fcb6d43162b) |
| Authentihash SHA1  | [43d3a3c1f7b14cfcc051cae2534dbbbb4c7fc120](https://www.virustotal.com/gui/search/authentihash%253A43d3a3c1f7b14cfcc051cae2534dbbbb4c7fc120) |
| Authentihash SHA256| [b8eb26b6f79020ae988e4fb752dc06e1b6779749bf4f8df2872fc2b92bab8020](https://www.virustotal.com/gui/search/authentihash%253Ab8eb26b6f79020ae988e4fb752dc06e1b6779749bf4f8df2872fc2b92bab8020) |
| RichPEHeaderHash MD5   | [deb9c1e252f598099d70d2b33a313da3](https://www.virustotal.com/gui/search/rich_pe_header_hash%253Adeb9c1e252f598099d70d2b33a313da3) |
| RichPEHeaderHash SHA1  | [f0c2801e0091ed6f5e10ea7045e911aa90030290](https://www.virustotal.com/gui/search/rich_pe_header_hash%253Af0c2801e0091ed6f5e10ea7045e911aa90030290) |
| RichPEHeaderHash SHA256| [914fb9761d50c3fa2ecf9fbd8af3735f9b8d6c4903e067c8af9546e79b6f22c7](https://www.virustotal.com/gui/search/rich_pe_header_hash%253A914fb9761d50c3fa2ecf9fbd8af3735f9b8d6c4903e067c8af9546e79b6f22c7) |

{{< button "https://github.com/magicsword-io/LOLDrivers/raw/main/drivers/79b8119b012352d255961e76605567d6.bin" "Download" >}} 

#### Certificates

{{< details "Expand" >}}
###### Certificate 040000000000f97faa2e1e
| Field                             | Value                      |
|-----------------------------------|----------------------------|
| ToBeSigned (TBS) MD5              | 59466cb0c1788b2f251fce3495837102  |
| ToBeSigned (TBS) SHA1             | c5cfc5f6a131a3a77c3905c9893c99bb1b2baa0b |
| ToBeSigned (TBS) SHA256           | eedda02668f7636eeec69429a7164cc47ca3de0539122d37f5b8078df7ee56db |
| Subject                           | CN=GlobalSign RootSign Partners CA, OU=RootSign Partners CA, O=GlobalSign nv,sa, C=BE |
| ValidFrom                         | 2003-12-16 13:00:00 |
| ValidTo                           | 2014-01-27 11:00:00 |
| Signature                         | 5c2f2e674a26b3e7b53f353cdda003ed569af9443752163065c7d14ea20f8db7b6b6678ee74cec8d95bee6cea7227874acd7f87499b3f7ce8b1338d596cc8d76c52f38b23aae61be0b8799e321626423398d84f6858df777ffb03806f07ec1485fb5ee582606660522749283a7dbb5f992e3e8c3192c2e63efbb1fdff9f70747660d0789977ef8332c9ecbae143df11cdfa3f179afc8928f9471c4d144c554db1eb50b0aa942a3afd643391dee8f9398585bbe6e9c0bf563ec5e99c2f954fa010746da0db06424cf8ed1061d4f3ca26377455ba4bc5fb080bb31e00b54015c161d724ed52a6947d11b667e5f016ef135916be02efeb045d81627b5c58bc2da53 |
| SignatureAlgorithmOID             | 1.2.840.113549.1.1.5 |
| IsCertificateAuthority            | True |
| SerialNumber                      | 040000000000f97faa2e1e |
| Version                           | 3 |
###### Certificate 0400000000011092eb8295
| Field                             | Value                      |
|-----------------------------------|----------------------------|
| ToBeSigned (TBS) MD5              | 11d73a3638fc78e0bac6c459feadcc42  |
| ToBeSigned (TBS) SHA1             | 6636f7dcf81b370b919966f9063295ec84422f91 |
| ToBeSigned (TBS) SHA256           | 1eb5fc1d2e3254b1e3c4587a6efed87ee65306525e684b4cfa4b51893cfe86a3 |
| Subject                           | O=GlobalSign, CN=GlobalSign Time Stamping Authority, emailAddress=timestampinfo@globalsign.com |
| ValidFrom                         | 2007-02-05 09:00:00 |
| ValidTo                           | 2014-01-27 09:00:00 |
| Signature                         | 649b07caaccc411e37ef6f349cb5e8ca48f9daeafaf7172e5cad193b7311ec5adbfd7b213161c092515bb166b07c64d8fe10b471a8bc9e75379c5f6ff2da0437b8ecc003e256b7785995581d7a7c3e18d74c32bdf91ee723457fdee08d65825b45fd64c66fc3d7ea12411d0c395ef696f8c3cd9e1fff51886976988b8eb42788821ad63c7aabb04eb73ee8d434d2c1a439533cb2747b15373054a6ebb924cc2f084b4364f14aaf8d9ce8546cb2dbdc3bb1c722849f558e72a8b2a8f6f0ff03c996ebab8273dabe45561936fdba6cbc71f0d3c7c376d7e4bce2a1a67200cfbdb200ed92aa39ab09d16e3953862ad43b517398b754e9972d9977ee123e3642257f |
| SignatureAlgorithmOID             | 1.2.840.113549.1.1.5 |
| IsCertificateAuthority            | True |
| SerialNumber                      | 0400000000011092eb8295 |
| Version                           | 3 |
###### Certificate 4191a15a3978dfcf496566381d4c75c2
| Field                             | Value                      |
|-----------------------------------|----------------------------|
| ToBeSigned (TBS) MD5              | 41011f8d0e7c7a6408334ca387914c61  |
| ToBeSigned (TBS) SHA1             | c7fc1727f5b75a6421a1f95c73bbdb23580c48e5 |
| ToBeSigned (TBS) SHA256           | 88dd3952638ee82738c03168e6fd863fe4eab1059ee5e2926ad8cb587c255dc0 |
| Subject                           | C=US, O=VeriSign, Inc., OU=VeriSign Trust Network, OU=Terms of use at https://www.verisign.com/rpa (c)04, CN=VeriSign Class 3 Code Signing 2004 CA |
| ValidFrom                         | 2004-07-16 00:00:00 |
| ValidTo                           | 2014-07-15 23:59:59 |
| Signature                         | ae3a17b84a7b55fa6455ec40a4ed494190999c89bcaf2e1dca7823f91c190f7feb68bc32d98838dedc3fd389b43fb18296f1a45abaed2e26d3de7c016e000a00a4069211480940f91c1879672324e0bbd5e150ae1bf50edde02e81cd80a36c524f9175558aba22f2d2ea4175882f63557d1e545a9559cad93481c05f5ef67ab5 |
| SignatureAlgorithmOID             | 1.2.840.113549.1.1.5 |
| IsCertificateAuthority            | True |
| SerialNumber                      | 4191a15a3978dfcf496566381d4c75c2 |
| Version                           | 3 |
###### Certificate 546ea040bf5075ce0a5c01d4c6ded19d
| Field                             | Value                      |
|-----------------------------------|----------------------------|
| ToBeSigned (TBS) MD5              | 8f51b4e16b87e1cc89b9d0c997227546  |
| ToBeSigned (TBS) SHA1             | 8f3cdd2b86ae03653f0612911a2f01a9dca49a22 |
| ToBeSigned (TBS) SHA256           | c7f57b7287c808d2713aba9e368fe387b5825bfbda1bd1824f374beaa8e30be9 |
| Subject                           | C=US, ST=California, L=Brea, O=EVGA, OU=Digital ID Class 3 , Microsoft Software Validation v2, CN=EVGA |
| ValidFrom                         | 2008-04-16 00:00:00 |
| ValidTo                           | 2010-04-16 23:59:59 |
| Signature                         | 13a3b8caa6bd8d63308898b0c92b79574e5d122a3ecba9758ec450b7c8c848ee5bc486db6370a8dfeb4c96c2c25512f7a3e759cc57a4d92f1a44fba15ca0c1156d22c49251b4e6a01bb93e4a62522ee5af4286c759c01c66fa5ce4452a4f112d03560bfa9737a3d0f3008b3cc48f2042b4428643f1efb4b99a34d0545c9934f1a6f35819e469430b74ba475a2135660948131cf24c9b1fb84580a1fd63eb3218d282e4f7caf77f4adbecb51e4b8237937eda0b7fcc20fc2273bf38282ee69ae6730b21c5314bcdc3f2e3a1e6f6c3ccb2139800f69d3f2fadc235080214f1c9b11e6a8f2165a45e15cca3c3542c2bac7225208a84828456d2e93cfe8315b092a1 |
| SignatureAlgorithmOID             | 1.2.840.113549.1.1.5 |
| IsCertificateAuthority            | False |
| SerialNumber                      | 546ea040bf5075ce0a5c01d4c6ded19d |
| Version                           | 3 |
###### Certificate 610c120600000000001b
| Field                             | Value                      |
|-----------------------------------|----------------------------|
| ToBeSigned (TBS) MD5              | 53c41bc1164e09e0cd1617a5bf913efd  |
| ToBeSigned (TBS) SHA1             | 93c03aac8951d494ecd5696b1c08658541b18727 |
| ToBeSigned (TBS) SHA256           | 40bddadac24dc61ca4fb5cab2a2bc5d876bc36808311039a7a3e1a4066f7489b |
| Subject                           | C=US, O=VeriSign, Inc., OU=Class 3 Public Primary Certification Authority |
| ValidFrom                         | 2006-05-23 17:01:29 |
| ValidTo                           | 2016-05-23 17:11:29 |
| Signature                         | 01e446b33b457f7513877e5f43de468ecb8abdb64741bccccc7491d8ce395195a4a6b547c0efd2da7b8f5711f4328c7ccd3fee42da04214af7c843884a6f5cca14fc4bd19f4cbdd4556ecc02be0da6888f8609baa425bde8b0f0fa8b714e67b0cb82a8d78e55f737ebf03e88efe4e08afd1c6e2e61414875b4b02c1d28d8490fd715f02473253ccc880cde284c6554fe5eae8cea19ad2c51b29b3a47f53c80350117e24987d6544afb4bab07bcbf7d79cfbf35005cbb9ecffc82891b39a05197b6dec0b307ff449644c0342a195cabeef03bec294eb513c537857e75d5b4d60d066eb5d26c237167eaf1718eaf4e74aa0cf9ecbf4c58fa5e909b6d39cb86883f8b1ca81632d5fe6db9f1f8b3ead791f6364778c0272a15c768d6f4c5fc4f4ec8673f102d409ff11ec96148e7a703fc31730cf04688fe56da492995ef09daa3e5beef60ecd954a0599c28bd54ef66157f874c84dba60e95672e517b3439b641c28c846826dc240209e7818e0a972defeea7b998a60f818dc710b5e1ed982f486f53854964789bec5dac970b5526c3efba8dc8d1a52f5a7f936b611a339b18b8a26210de24ea76e12f43ebecdd7c12342489da2855aee5754e312b6763b6a8d7ab730a03cec5ea593fc7eb2a45aea8625b2f009939abb45f73c308ec80118f470e8f2a1343e191066255bbffba3da9a93d260faeca7d628b155589d694344dd665 |
| SignatureAlgorithmOID             | 1.2.840.113549.1.1.5 |
| IsCertificateAuthority            | True |
| SerialNumber                      | 610c120600000000001b |
| Version                           | 3 |

{{< /details >}}
#### Imports
{{< details "Expand" >}}
* ntoskrnl.exe
* HAL.dll

{{< /details >}}
#### Imported Functions
{{< details "Expand" >}}
* RtlInitUnicodeString
* ZwClose
* ZwMapViewOfSection
* ObReferenceObjectByHandle
* ZwOpenSection
* IoDeleteSymbolicLink
* IofCompleteRequest
* MmIsAddressValid
* ZwUnmapViewOfSection
* IoCreateSymbolicLink
* IoCreateDevice
* __C_specific_handler
* IoDeleteDevice
* HalTranslateBusAddress

{{< /details >}}
#### Exported Functions
{{< details "Expand" >}}

{{< /details >}}

#### Sections
{{< details "Expand" >}}
* .text
* .rdata
* .data
* .pdata
* INIT

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
        "SHA256": "3ca71e85908ff67368e4dc00253f5691b9e6d50c966e7784143d75fb92aa3448",
        "SHA384": "d9d366f9328f2b55ee19a32cc5fd5148b81d764282fe5dc196c872ae249caa51d2c212ef39f33945dfe0cda81925e326"
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
        "SHA256": "cbdc9a0ad785d0c2013211746b42234e18bdc7d54a7a260647badc1c9e712ed4",
        "SHA384": "dcec542f242317863d0b3d23947e17d6982e381003831777b07ed75b46fb18bd0392a89c9beb6862981cd05f3f2fb77b"
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
        "SHA256": "4783380498acf592286ef2dea0fcc5bdea3f54d5e374d3e3497df9d5f662cfb6",
        "SHA384": "4f428f115cf3d008248f15f32007fc7c54bd454e1b48b765776b4c87c23ab8818d8fbcbb3646d35eca012b025260a3b8"
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
        "SHA256": "5b81998ed98b343c04134c336e03f3051779eae0e9f882e8339593d18556375d",
        "SHA384": "db0076cad41a0ef4ea68754ef6905bd5ff772adcb745b05c0060344e43588abc95952dc3ad272f5a8f17b206e4089aca"
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
        "SHA256": "ef14ea05bb066ee9f4188196dd69cd769b283ac4d7555db52f5e76922d3456e1",
        "SHA384": "6e7450a139856aeda6fa6284ff89b3752a9b646e096b4d33dd7e8e727742a2111481531581c0aa2cda0338e22cfdbad3"
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
| Filename           |  |
| Creation Timestamp           | 2005-05-25 00:39:12 |
| MD5                | [6fb3d42a4f07d8115d59eb2ea6504de5](https://www.virustotal.com/gui/file/6fb3d42a4f07d8115d59eb2ea6504de5) |
| SHA1               | [f56186b6a7aa3dd7832c9d821f9d2d93bc2a9360](https://www.virustotal.com/gui/file/f56186b6a7aa3dd7832c9d821f9d2d93bc2a9360) |
| SHA256             | [67e9d1f6f7ed58d86b025d3578cb7a3f3c389b9dd425b7f46bb1056e83bffc78](https://www.virustotal.com/gui/file/67e9d1f6f7ed58d86b025d3578cb7a3f3c389b9dd425b7f46bb1056e83bffc78) |
| Authentihash MD5   | [a17d227444e090ff69e24fcb6d43162b](https://www.virustotal.com/gui/search/authentihash%253Aa17d227444e090ff69e24fcb6d43162b) |
| Authentihash SHA1  | [43d3a3c1f7b14cfcc051cae2534dbbbb4c7fc120](https://www.virustotal.com/gui/search/authentihash%253A43d3a3c1f7b14cfcc051cae2534dbbbb4c7fc120) |
| Authentihash SHA256| [b8eb26b6f79020ae988e4fb752dc06e1b6779749bf4f8df2872fc2b92bab8020](https://www.virustotal.com/gui/search/authentihash%253Ab8eb26b6f79020ae988e4fb752dc06e1b6779749bf4f8df2872fc2b92bab8020) |
| RichPEHeaderHash MD5   | [deb9c1e252f598099d70d2b33a313da3](https://www.virustotal.com/gui/search/rich_pe_header_hash%253Adeb9c1e252f598099d70d2b33a313da3) |
| RichPEHeaderHash SHA1  | [f0c2801e0091ed6f5e10ea7045e911aa90030290](https://www.virustotal.com/gui/search/rich_pe_header_hash%253Af0c2801e0091ed6f5e10ea7045e911aa90030290) |
| RichPEHeaderHash SHA256| [914fb9761d50c3fa2ecf9fbd8af3735f9b8d6c4903e067c8af9546e79b6f22c7](https://www.virustotal.com/gui/search/rich_pe_header_hash%253A914fb9761d50c3fa2ecf9fbd8af3735f9b8d6c4903e067c8af9546e79b6f22c7) |

{{< button "https://github.com/magicsword-io/LOLDrivers/raw/main/drivers/6fb3d42a4f07d8115d59eb2ea6504de5.bin" "Download" >}} 

#### Certificates

{{< details "Expand" >}}
###### Certificate 3825d7faf861af9ef490e726b5d65ad5
| Field                             | Value                      |
|-----------------------------------|----------------------------|
| ToBeSigned (TBS) MD5              | d6c7684e9aaa508cf268335f83afe040  |
| ToBeSigned (TBS) SHA1             | 18066d20ad92409c567cdfde745279ff71c75226 |
| ToBeSigned (TBS) SHA256           | a612fb22ce8be6dab75e47c98508f98496583e79c9c97b936a8caee9ea9f3fff |
| Subject                           | C=US, O=VeriSign, Inc., CN=VeriSign Time Stamping Services Signer , G2 |
| ValidFrom                         | 2007-06-15 00:00:00 |
| ValidTo                           | 2012-06-14 23:59:59 |
| Signature                         | 50c54bc82480dfe40d24c2de1ab1a102a1a6822d0c831581370a820e2cb05a1761b5d805fe88dbf19191b3561a40a6eb92be3839b07536743a984fe437ba9989ca95421db0b9c7a08d57e0fad5640442354e01d133a217c84daa27c7f2e1864c02384d8378c6fc53e0ebe00687dda4969e5e0c98e2a5bebf8285c360e1dfad28d8c7a54b64dac71b5bbdac3908d53822a1338b2f8a9aebbc07213f44410907b5651c24bc48d34480eba1cfc902b414cf54c716a3805cf9793e5d727d88179e2c43a2ca53ce7d3df62a3ab84f9400a56d0a835df95e53f418b3570f70c3fbf5ad95a00e17dec4168060c90f2b6e8604f1ebf47827d105c5ee345b5eb94932f233 |
| SignatureAlgorithmOID             | 1.2.840.113549.1.1.5 |
| IsCertificateAuthority            | False |
| SerialNumber                      | 3825d7faf861af9ef490e726b5d65ad5 |
| Version                           | 3 |
###### Certificate 47bf1995df8d524643f7db6d480d31a4
| Field                             | Value                      |
|-----------------------------------|----------------------------|
| ToBeSigned (TBS) MD5              | 518d2ea8a21e879c942d504824ac211c  |
| ToBeSigned (TBS) SHA1             | 21ce87d827077e61abddf2beba69fde5432ea031 |
| ToBeSigned (TBS) SHA256           | 1ec3b4f02e03930a470020e0e48d24b84678bb558f46182888d870541f5e25c7 |
| Subject                           | C=US, O=VeriSign, Inc., CN=VeriSign Time Stamping Services CA |
| ValidFrom                         | 2003-12-04 00:00:00 |
| ValidTo                           | 2013-12-03 23:59:59 |
| Signature                         | 4a6bf9ea58c2441c318979992b96bf82ac01d61c4ccdb08a586edf0829a35ec8ca9313e704520def47272f0038b0e4c9934e9ad4226215f73f37214f703180f18b3887b3e8e89700fecf55964e24d2a9274e7aaeb76141f32acee7c9d95eddbb2b853eb59db5d9e157ffbeb4c57ef5cf0c9ef097fe2bd33b521b1b3827f73f4a |
| SignatureAlgorithmOID             | 1.2.840.113549.1.1.5 |
| IsCertificateAuthority            | True |
| SerialNumber                      | 47bf1995df8d524643f7db6d480d31a4 |
| Version                           | 3 |
###### Certificate 04000000000108d9611cd6
| Field                             | Value                      |
|-----------------------------------|----------------------------|
| ToBeSigned (TBS) MD5              | 698f075151097d84c0b1f3e7bc3d6fca  |
| ToBeSigned (TBS) SHA1             | 041750993d7c9e063f02dfe74699598640911aab |
| ToBeSigned (TBS) SHA256           | a8622cca0913a20477be8313b8d16fcad5d83088b46b36ddac10b31e96abb5e8 |
| Subject                           | C=BE, O=GlobalSign nv,sa, OU=Primary Object Publishing CA, CN=GlobalSign Primary Object Publishing CA |
| ValidFrom                         | 1999-01-28 12:00:00 |
| ValidTo                           | 2014-01-27 11:00:00 |
| Signature                         | a0422eb876a7427186404d464d5b26b0b074f93f89a87b7cb7f1c697e08239999d43fe60823642b55b878df55df4bbffa91044a871d3c7f12241f29aa4a5ec63fae5eb654a19309d8bc7b6fddc3fe16cfdd5521407fc6d24ccb3cc81a2c052f327b96d9e063dd8a849023269c7054294d0bbe3bba908c393501bdb846dc0ba1e5298659c1376bdb3d567292f1f7baa2c51a0fd854f263c48a38127a6feee7f7899c245cf9d1f527ed7958bfde1d020c3af7e51a22f663bab2dcf2d8e8c4d7d18392128fbdcae6d6581d0e0d7184be7b5f774d784e6522aac3b68fd3b4ab80154849132bb95d28e6330a69ece2396feab2eb86a8b74dcde21a114c2fbbf53af10 |
| SignatureAlgorithmOID             | 1.2.840.113549.1.1.5 |
| IsCertificateAuthority            | True |
| SerialNumber                      | 04000000000108d9611cd6 |
| Version                           | 3 |
###### Certificate 0100000000011c08b7f67e
| Field                             | Value                      |
|-----------------------------------|----------------------------|
| ToBeSigned (TBS) MD5              | 4566c37f56f951a0ce5b4ae966c0ea9f  |
| ToBeSigned (TBS) SHA1             | a51cbf2834eb6f8535bc5e44913a9ec979379782 |
| ToBeSigned (TBS) SHA256           | 88a8e9a799af515b9223e4cdf24d0ef1e72f12124be02786f026a3c26317b417 |
| Subject                           | C=TW, O=Micro,Star Int&#39;l Co. Ltd., CN=Micro,Star Int&#39;l Co. Ltd. |
| ValidFrom                         | 2008-08-28 09:49:45 |
| ValidTo                           | 2011-08-28 09:49:45 |
| Signature                         | 572df373e9b036711b3cf5ee882e5d75d8d50f012407cf0c1b554ff8f41c7b6477fa0b2ad579f2c1fe7b8b9d7374b690527c219eb979686fb67d0b4cf2885d8d7d1261f05cb72fe4c9f294c52aa05f3e5d1ceb0d77085dbd6af07978032505da666f353283a8982af26985e69c1599479945b591124183574b8a4cc34caa62e31b523dac3fedbd04951b3661399ed34f5c5868d9bbe3295fc09890d9521e1cdcae2ff129f547d4c8ce8aa08616107c555fac60e5b63c14ddfeb6962af3608b75d9c77c69260d8af9775b83afaa15b8ecef6840cb4ee87d451f9042b49735ea40931c0664c8c2bf6a139db6ac5b90edcea63a6bf5b54978f027b1046170d476d0 |
| SignatureAlgorithmOID             | 1.2.840.113549.1.1.5 |
| IsCertificateAuthority            | False |
| SerialNumber                      | 0100000000011c08b7f67e |
| Version                           | 3 |
###### Certificate 04000000000117ab50b915
| Field                             | Value                      |
|-----------------------------------|----------------------------|
| ToBeSigned (TBS) MD5              | 5686b287d716c4d2428b092c4ef30f9c  |
| ToBeSigned (TBS) SHA1             | 306fb5fbeb3d531510bb4b663c4fd48adc121e14 |
| ToBeSigned (TBS) SHA256           | 60846fc990e271a707cd2d53d0bb21834a04f7652214aa0c12597ff6649d352d |
| Subject                           | C=BE, O=GlobalSign nv,sa, OU=ObjectSign CA, CN=GlobalSign ObjectSign CA |
| ValidFrom                         | 2004-01-22 09:00:00 |
| ValidTo                           | 2014-01-27 10:00:00 |
| Signature                         | 3c4a010267edf20a2e736e40252f1dccbc2db652141b27122cf1229e190a89b6ef352a29152b1a88c20f37168d2602d5e93080f608b9939ac0498f332c3035ff4ab9892aa75c38e761a778fe22851a07b4b9edcf21f25ddedff329c5d38d9e14c4285c88e590a300442912b23e759540244a6beee2d0ef862ddf6d741a4f1cc79424c443464f7b81015d23733cd9752e995361565e7ccd13e237d222e570f8a743f6154147fda24702c43651ca545da6cdcad61817533ff1d38e0f0aafda17941657a0991431c90e1611d2c04ca2a25978fbb6b933cff763c9d2c4c84953dd8a59525e7d3b385eed220360ac85cd58325dcdc31c07fa7ef67efbc8ac378be498 |
| SignatureAlgorithmOID             | 1.2.840.113549.1.1.5 |
| IsCertificateAuthority            | True |
| SerialNumber                      | 04000000000117ab50b915 |
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
#### Imported Functions
{{< details "Expand" >}}
* RtlInitUnicodeString
* ZwClose
* ZwMapViewOfSection
* ObReferenceObjectByHandle
* ZwOpenSection
* IoDeleteSymbolicLink
* IofCompleteRequest
* MmIsAddressValid
* ZwUnmapViewOfSection
* IoCreateSymbolicLink
* IoCreateDevice
* __C_specific_handler
* IoDeleteDevice
* HalTranslateBusAddress

{{< /details >}}
#### Exported Functions
{{< details "Expand" >}}

{{< /details >}}

#### Sections
{{< details "Expand" >}}
* .text
* .rdata
* .data
* .pdata
* INIT

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
        "SHA256": "3ca71e85908ff67368e4dc00253f5691b9e6d50c966e7784143d75fb92aa3448",
        "SHA384": "d9d366f9328f2b55ee19a32cc5fd5148b81d764282fe5dc196c872ae249caa51d2c212ef39f33945dfe0cda81925e326"
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
        "SHA256": "cbdc9a0ad785d0c2013211746b42234e18bdc7d54a7a260647badc1c9e712ed4",
        "SHA384": "dcec542f242317863d0b3d23947e17d6982e381003831777b07ed75b46fb18bd0392a89c9beb6862981cd05f3f2fb77b"
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
        "SHA256": "4783380498acf592286ef2dea0fcc5bdea3f54d5e374d3e3497df9d5f662cfb6",
        "SHA384": "4f428f115cf3d008248f15f32007fc7c54bd454e1b48b765776b4c87c23ab8818d8fbcbb3646d35eca012b025260a3b8"
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
        "SHA256": "5b81998ed98b343c04134c336e03f3051779eae0e9f882e8339593d18556375d",
        "SHA384": "db0076cad41a0ef4ea68754ef6905bd5ff772adcb745b05c0060344e43588abc95952dc3ad272f5a8f17b206e4089aca"
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
        "SHA256": "ef14ea05bb066ee9f4188196dd69cd769b283ac4d7555db52f5e76922d3456e1",
        "SHA384": "6e7450a139856aeda6fa6284ff89b3752a9b646e096b4d33dd7e8e727742a2111481531581c0aa2cda0338e22cfdbad3"
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
| Filename           |  |
| Creation Timestamp           | 2005-05-25 00:39:12 |
| MD5                | [700e9902b0a28979724582f116288bad](https://www.virustotal.com/gui/file/700e9902b0a28979724582f116288bad) |
| SHA1               | [38a863bcd37c9c56d53274753d5b0e614ba6c8bb](https://www.virustotal.com/gui/file/38a863bcd37c9c56d53274753d5b0e614ba6c8bb) |
| SHA256             | [f48f31bf9c6abbd44124b66bce2ab1200176e31ef1e901733761f2b5ceb60fb2](https://www.virustotal.com/gui/file/f48f31bf9c6abbd44124b66bce2ab1200176e31ef1e901733761f2b5ceb60fb2) |
| Authentihash MD5   | [a17d227444e090ff69e24fcb6d43162b](https://www.virustotal.com/gui/search/authentihash%253Aa17d227444e090ff69e24fcb6d43162b) |
| Authentihash SHA1  | [43d3a3c1f7b14cfcc051cae2534dbbbb4c7fc120](https://www.virustotal.com/gui/search/authentihash%253A43d3a3c1f7b14cfcc051cae2534dbbbb4c7fc120) |
| Authentihash SHA256| [b8eb26b6f79020ae988e4fb752dc06e1b6779749bf4f8df2872fc2b92bab8020](https://www.virustotal.com/gui/search/authentihash%253Ab8eb26b6f79020ae988e4fb752dc06e1b6779749bf4f8df2872fc2b92bab8020) |
| RichPEHeaderHash MD5   | [deb9c1e252f598099d70d2b33a313da3](https://www.virustotal.com/gui/search/rich_pe_header_hash%253Adeb9c1e252f598099d70d2b33a313da3) |
| RichPEHeaderHash SHA1  | [f0c2801e0091ed6f5e10ea7045e911aa90030290](https://www.virustotal.com/gui/search/rich_pe_header_hash%253Af0c2801e0091ed6f5e10ea7045e911aa90030290) |
| RichPEHeaderHash SHA256| [914fb9761d50c3fa2ecf9fbd8af3735f9b8d6c4903e067c8af9546e79b6f22c7](https://www.virustotal.com/gui/search/rich_pe_header_hash%253A914fb9761d50c3fa2ecf9fbd8af3735f9b8d6c4903e067c8af9546e79b6f22c7) |

{{< button "https://github.com/magicsword-io/LOLDrivers/raw/main/drivers/700e9902b0a28979724582f116288bad.bin" "Download" >}} 

#### Certificates

{{< details "Expand" >}}
###### Certificate 3825d7faf861af9ef490e726b5d65ad5
| Field                             | Value                      |
|-----------------------------------|----------------------------|
| ToBeSigned (TBS) MD5              | d6c7684e9aaa508cf268335f83afe040  |
| ToBeSigned (TBS) SHA1             | 18066d20ad92409c567cdfde745279ff71c75226 |
| ToBeSigned (TBS) SHA256           | a612fb22ce8be6dab75e47c98508f98496583e79c9c97b936a8caee9ea9f3fff |
| Subject                           | C=US, O=VeriSign, Inc., CN=VeriSign Time Stamping Services Signer , G2 |
| ValidFrom                         | 2007-06-15 00:00:00 |
| ValidTo                           | 2012-06-14 23:59:59 |
| Signature                         | 50c54bc82480dfe40d24c2de1ab1a102a1a6822d0c831581370a820e2cb05a1761b5d805fe88dbf19191b3561a40a6eb92be3839b07536743a984fe437ba9989ca95421db0b9c7a08d57e0fad5640442354e01d133a217c84daa27c7f2e1864c02384d8378c6fc53e0ebe00687dda4969e5e0c98e2a5bebf8285c360e1dfad28d8c7a54b64dac71b5bbdac3908d53822a1338b2f8a9aebbc07213f44410907b5651c24bc48d34480eba1cfc902b414cf54c716a3805cf9793e5d727d88179e2c43a2ca53ce7d3df62a3ab84f9400a56d0a835df95e53f418b3570f70c3fbf5ad95a00e17dec4168060c90f2b6e8604f1ebf47827d105c5ee345b5eb94932f233 |
| SignatureAlgorithmOID             | 1.2.840.113549.1.1.5 |
| IsCertificateAuthority            | False |
| SerialNumber                      | 3825d7faf861af9ef490e726b5d65ad5 |
| Version                           | 3 |
###### Certificate 47bf1995df8d524643f7db6d480d31a4
| Field                             | Value                      |
|-----------------------------------|----------------------------|
| ToBeSigned (TBS) MD5              | 518d2ea8a21e879c942d504824ac211c  |
| ToBeSigned (TBS) SHA1             | 21ce87d827077e61abddf2beba69fde5432ea031 |
| ToBeSigned (TBS) SHA256           | 1ec3b4f02e03930a470020e0e48d24b84678bb558f46182888d870541f5e25c7 |
| Subject                           | C=US, O=VeriSign, Inc., CN=VeriSign Time Stamping Services CA |
| ValidFrom                         | 2003-12-04 00:00:00 |
| ValidTo                           | 2013-12-03 23:59:59 |
| Signature                         | 4a6bf9ea58c2441c318979992b96bf82ac01d61c4ccdb08a586edf0829a35ec8ca9313e704520def47272f0038b0e4c9934e9ad4226215f73f37214f703180f18b3887b3e8e89700fecf55964e24d2a9274e7aaeb76141f32acee7c9d95eddbb2b853eb59db5d9e157ffbeb4c57ef5cf0c9ef097fe2bd33b521b1b3827f73f4a |
| SignatureAlgorithmOID             | 1.2.840.113549.1.1.5 |
| IsCertificateAuthority            | True |
| SerialNumber                      | 47bf1995df8d524643f7db6d480d31a4 |
| Version                           | 3 |
###### Certificate 04000000000108d9611cd6
| Field                             | Value                      |
|-----------------------------------|----------------------------|
| ToBeSigned (TBS) MD5              | 698f075151097d84c0b1f3e7bc3d6fca  |
| ToBeSigned (TBS) SHA1             | 041750993d7c9e063f02dfe74699598640911aab |
| ToBeSigned (TBS) SHA256           | a8622cca0913a20477be8313b8d16fcad5d83088b46b36ddac10b31e96abb5e8 |
| Subject                           | C=BE, O=GlobalSign nv,sa, OU=Primary Object Publishing CA, CN=GlobalSign Primary Object Publishing CA |
| ValidFrom                         | 1999-01-28 12:00:00 |
| ValidTo                           | 2014-01-27 11:00:00 |
| Signature                         | a0422eb876a7427186404d464d5b26b0b074f93f89a87b7cb7f1c697e08239999d43fe60823642b55b878df55df4bbffa91044a871d3c7f12241f29aa4a5ec63fae5eb654a19309d8bc7b6fddc3fe16cfdd5521407fc6d24ccb3cc81a2c052f327b96d9e063dd8a849023269c7054294d0bbe3bba908c393501bdb846dc0ba1e5298659c1376bdb3d567292f1f7baa2c51a0fd854f263c48a38127a6feee7f7899c245cf9d1f527ed7958bfde1d020c3af7e51a22f663bab2dcf2d8e8c4d7d18392128fbdcae6d6581d0e0d7184be7b5f774d784e6522aac3b68fd3b4ab80154849132bb95d28e6330a69ece2396feab2eb86a8b74dcde21a114c2fbbf53af10 |
| SignatureAlgorithmOID             | 1.2.840.113549.1.1.5 |
| IsCertificateAuthority            | True |
| SerialNumber                      | 04000000000108d9611cd6 |
| Version                           | 3 |
###### Certificate 0100000000011c08b7f67e
| Field                             | Value                      |
|-----------------------------------|----------------------------|
| ToBeSigned (TBS) MD5              | 4566c37f56f951a0ce5b4ae966c0ea9f  |
| ToBeSigned (TBS) SHA1             | a51cbf2834eb6f8535bc5e44913a9ec979379782 |
| ToBeSigned (TBS) SHA256           | 88a8e9a799af515b9223e4cdf24d0ef1e72f12124be02786f026a3c26317b417 |
| Subject                           | C=TW, O=Micro,Star Int&#39;l Co. Ltd., CN=Micro,Star Int&#39;l Co. Ltd. |
| ValidFrom                         | 2008-08-28 09:49:45 |
| ValidTo                           | 2011-08-28 09:49:45 |
| Signature                         | 572df373e9b036711b3cf5ee882e5d75d8d50f012407cf0c1b554ff8f41c7b6477fa0b2ad579f2c1fe7b8b9d7374b690527c219eb979686fb67d0b4cf2885d8d7d1261f05cb72fe4c9f294c52aa05f3e5d1ceb0d77085dbd6af07978032505da666f353283a8982af26985e69c1599479945b591124183574b8a4cc34caa62e31b523dac3fedbd04951b3661399ed34f5c5868d9bbe3295fc09890d9521e1cdcae2ff129f547d4c8ce8aa08616107c555fac60e5b63c14ddfeb6962af3608b75d9c77c69260d8af9775b83afaa15b8ecef6840cb4ee87d451f9042b49735ea40931c0664c8c2bf6a139db6ac5b90edcea63a6bf5b54978f027b1046170d476d0 |
| SignatureAlgorithmOID             | 1.2.840.113549.1.1.5 |
| IsCertificateAuthority            | False |
| SerialNumber                      | 0100000000011c08b7f67e |
| Version                           | 3 |
###### Certificate 04000000000117ab50b915
| Field                             | Value                      |
|-----------------------------------|----------------------------|
| ToBeSigned (TBS) MD5              | 5686b287d716c4d2428b092c4ef30f9c  |
| ToBeSigned (TBS) SHA1             | 306fb5fbeb3d531510bb4b663c4fd48adc121e14 |
| ToBeSigned (TBS) SHA256           | 60846fc990e271a707cd2d53d0bb21834a04f7652214aa0c12597ff6649d352d |
| Subject                           | C=BE, O=GlobalSign nv,sa, OU=ObjectSign CA, CN=GlobalSign ObjectSign CA |
| ValidFrom                         | 2004-01-22 09:00:00 |
| ValidTo                           | 2014-01-27 10:00:00 |
| Signature                         | 3c4a010267edf20a2e736e40252f1dccbc2db652141b27122cf1229e190a89b6ef352a29152b1a88c20f37168d2602d5e93080f608b9939ac0498f332c3035ff4ab9892aa75c38e761a778fe22851a07b4b9edcf21f25ddedff329c5d38d9e14c4285c88e590a300442912b23e759540244a6beee2d0ef862ddf6d741a4f1cc79424c443464f7b81015d23733cd9752e995361565e7ccd13e237d222e570f8a743f6154147fda24702c43651ca545da6cdcad61817533ff1d38e0f0aafda17941657a0991431c90e1611d2c04ca2a25978fbb6b933cff763c9d2c4c84953dd8a59525e7d3b385eed220360ac85cd58325dcdc31c07fa7ef67efbc8ac378be498 |
| SignatureAlgorithmOID             | 1.2.840.113549.1.1.5 |
| IsCertificateAuthority            | True |
| SerialNumber                      | 04000000000117ab50b915 |
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
#### Imported Functions
{{< details "Expand" >}}
* RtlInitUnicodeString
* ZwClose
* ZwMapViewOfSection
* ObReferenceObjectByHandle
* ZwOpenSection
* IoDeleteSymbolicLink
* IofCompleteRequest
* MmIsAddressValid
* ZwUnmapViewOfSection
* IoCreateSymbolicLink
* IoCreateDevice
* __C_specific_handler
* IoDeleteDevice
* HalTranslateBusAddress

{{< /details >}}
#### Exported Functions
{{< details "Expand" >}}

{{< /details >}}

#### Sections
{{< details "Expand" >}}
* .text
* .rdata
* .data
* .pdata
* INIT

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
        "SHA256": "3ca71e85908ff67368e4dc00253f5691b9e6d50c966e7784143d75fb92aa3448",
        "SHA384": "d9d366f9328f2b55ee19a32cc5fd5148b81d764282fe5dc196c872ae249caa51d2c212ef39f33945dfe0cda81925e326"
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
        "SHA256": "cbdc9a0ad785d0c2013211746b42234e18bdc7d54a7a260647badc1c9e712ed4",
        "SHA384": "dcec542f242317863d0b3d23947e17d6982e381003831777b07ed75b46fb18bd0392a89c9beb6862981cd05f3f2fb77b"
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
        "SHA256": "4783380498acf592286ef2dea0fcc5bdea3f54d5e374d3e3497df9d5f662cfb6",
        "SHA384": "4f428f115cf3d008248f15f32007fc7c54bd454e1b48b765776b4c87c23ab8818d8fbcbb3646d35eca012b025260a3b8"
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
        "SHA256": "5b81998ed98b343c04134c336e03f3051779eae0e9f882e8339593d18556375d",
        "SHA384": "db0076cad41a0ef4ea68754ef6905bd5ff772adcb745b05c0060344e43588abc95952dc3ad272f5a8f17b206e4089aca"
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
        "SHA256": "ef14ea05bb066ee9f4188196dd69cd769b283ac4d7555db52f5e76922d3456e1",
        "SHA384": "6e7450a139856aeda6fa6284ff89b3752a9b646e096b4d33dd7e8e727742a2111481531581c0aa2cda0338e22cfdbad3"
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
| Filename           |  |
| Creation Timestamp           | 2011-09-06 06:24:50 |
| MD5                | [ef5ba21690c2f4ba7e62bf022b2df1f7](https://www.virustotal.com/gui/file/ef5ba21690c2f4ba7e62bf022b2df1f7) |
| SHA1               | [dd49a71f158c879fb8d607cc558b507c7c8bc5b9](https://www.virustotal.com/gui/file/dd49a71f158c879fb8d607cc558b507c7c8bc5b9) |
| SHA256             | [c181ce9a57e8d763db89ba7c45702a8cf66ef1bb58e3f21874cf0265711f886b](https://www.virustotal.com/gui/file/c181ce9a57e8d763db89ba7c45702a8cf66ef1bb58e3f21874cf0265711f886b) |
| Authentihash MD5   | [55466195f0b2f4afc4243b43a806e6d9](https://www.virustotal.com/gui/search/authentihash%253A55466195f0b2f4afc4243b43a806e6d9) |
| Authentihash SHA1  | [38b353d8480885de5dcf299deca99ce4f26a1d20](https://www.virustotal.com/gui/search/authentihash%253A38b353d8480885de5dcf299deca99ce4f26a1d20) |
| Authentihash SHA256| [5182caf10de9cec0740ecde5a081c21cdc100d7eb328ffe6f3f63183889fec6b](https://www.virustotal.com/gui/search/authentihash%253A5182caf10de9cec0740ecde5a081c21cdc100d7eb328ffe6f3f63183889fec6b) |
| RichPEHeaderHash MD5   | [59080883b71fd56bbf10ec0ae4b6bdd4](https://www.virustotal.com/gui/search/rich_pe_header_hash%253A59080883b71fd56bbf10ec0ae4b6bdd4) |
| RichPEHeaderHash SHA1  | [503a36a225568553cc9b05f63b3506c6ff21e12e](https://www.virustotal.com/gui/search/rich_pe_header_hash%253A503a36a225568553cc9b05f63b3506c6ff21e12e) |
| RichPEHeaderHash SHA256| [bc812d4ddc3ecfbf38c4d0d185e368fc58bac6e07f722db032bf6303daa7c946](https://www.virustotal.com/gui/search/rich_pe_header_hash%253Abc812d4ddc3ecfbf38c4d0d185e368fc58bac6e07f722db032bf6303daa7c946) |

{{< button "https://github.com/magicsword-io/LOLDrivers/raw/main/drivers/ef5ba21690c2f4ba7e62bf022b2df1f7.bin" "Download" >}} 

#### Certificates

{{< details "Expand" >}}
###### Certificate 0400000000012019c19066
| Field                             | Value                      |
|-----------------------------------|----------------------------|
| ToBeSigned (TBS) MD5              | 42023b9487cafe46c1b6a49c369a362e  |
| ToBeSigned (TBS) SHA1             | 7c7b524d269334b9f073c32e888e09544c6acd98 |
| ToBeSigned (TBS) SHA256           | b7126567833f3daa4085ff41e73112daad3d1e3808a942c1936520e2d6c46c78 |
| Subject                           | OU=Timestamping CA, O=GlobalSign, CN=GlobalSign Timestamping CA |
| ValidFrom                         | 2009-03-18 11:00:00 |
| ValidTo                           | 2028-01-28 12:00:00 |
| Signature                         | 5df6cb2b0d0140849f857a43706ae0c5e7aa0600d76713c9089131654f14a8a905dc389e6aa0300abd8dc78028ee4245ca94f3de5845a9803204f5595c6a70003927944df5b44634e81c5331b2b35416e9cc42abd5d959301cfb462725b88723b1e8758824831ec876377b01494548a4ede25dd27c9ca2dc2dba105a126265abae00c710343bcb72bd14240cdcc37627b4a7fee15829f20e169f91391d89a6e60f1c878ce258ac927e243eaaec14e73a33348bc63bac83ab0f14627aba1a2d4d4b1bc530f00b92797d3c78e0f8e6d215965999392b3061e8b8f8c0a1e9221411787dc4dc89bec0bb94e172aeebb540404fef171e585ed0a88996ac9228e9babf |
| SignatureAlgorithmOID             | 1.2.840.113549.1.1.5 |
| IsCertificateAuthority            | True |
| SerialNumber                      | 0400000000012019c19066 |
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
###### Certificate 01000000000125b0b4cc01
| Field                             | Value                      |
|-----------------------------------|----------------------------|
| ToBeSigned (TBS) MD5              | e3369c8e5aec0504b3a50455f615d9f9  |
| ToBeSigned (TBS) SHA1             | 13c244a894b40ecd18aaf97c362f20385bd005a7 |
| ToBeSigned (TBS) SHA256           | 26da721a670c72836926032fee6920118bfb9bff89cc8d0ce30d9452c33f2532 |
| Subject                           | C=BE, O=GlobalSign NV, CN=GlobalSign Time Stamping Authority |
| ValidFrom                         | 2009-12-21 09:32:56 |
| ValidTo                           | 2020-12-22 09:32:56 |
| Signature                         | bc89ecfee63655935c79d4117a86808f17b693b26d9b91a1561811c655eaf608edad9b9ef52b81c8bbdd607b1b47991e6d403e1d80c213d58e04052fdbe7ae529e688472a1e54a603cf89bd52f46d8c3b2b79353ac9b6c432424d1f1fce9562e3411581843eaefff34746ca0c06c7fad031969881e9560cabbbd0cbb76efc724b081c63831cf36ad0c38b89020849b2e8f28b99ff6ca9427cdac396157e0e3955a9c769230f5dea6973d721c2a6032a8334d8635338a5cf3a4fdf7062ce16b4b30f5cbd34362f841b9de7d20cb058c8e2cf65f35fd338d42896508362ca389f45a858bb0b97bdb6ccba1f8d20e1bbb977cd12779be9d7c3be6a75634d8c991a9 |
| SignatureAlgorithmOID             | 1.2.840.113549.1.1.5 |
| IsCertificateAuthority            | False |
| SerialNumber                      | 01000000000125b0b4cc01 |
| Version                           | 3 |
###### Certificate 1121a559b50ef9848661f0faeb7421bbdd2c
| Field                             | Value                      |
|-----------------------------------|----------------------------|
| ToBeSigned (TBS) MD5              | 3a98a18e8636f2a01e49e2a6d116c360  |
| ToBeSigned (TBS) SHA1             | a2938150e46525adcec2e3a2348824bc1cf532b2 |
| ToBeSigned (TBS) SHA256           | 01a2e2d31d0a4f3005753cce5972b5da2a7c08b0750fb6947e0fd231e64ae7ec |
| Subject                           | C=TW, ST=Taiwan, L=New Taipei City, O=MICRO,STAR INTERNATIONAL CO., LTD., OU=MICRO,STAR INTERNATIONAL CO., LTD., CN=MICRO,STAR INTERNATIONAL CO., LTD. |
| ValidFrom                         | 2011-08-30 06:46:09 |
| ValidTo                           | 2014-08-30 06:46:09 |
| Signature                         | 87bf57ab7ffd7e005076b34b14ddd924045ec7e389871661794f1ece1bef10e050893b28236cb650af1415f8cd95e86c2052d93311d73e0bbe6fb1c22ddea438a93c8b18bd4b8c0f81ad07032efb46d406bbaa730dd3ac92cbf0d9cc711a397a0e0320b213a5161e6be83ec69967a712b463129ea56d5a8ecd3ff8901be09dfaa0a0f10e879b307863e1b1c3a3149ac73bc3f3160db7012229b57bced6d47b875878663642a8cddd03da1e7f236b8cf16713a5e0f4c892aaca77a8c7dab41d84567e2bbf09b336a2824e0e18d54d199e6e024d2630bb210cd24a9ef4b377be0429e2ecc9bf8478a8c6a78c686e26f29c95925baee85e4bbb97b6eecffe44a25e |
| SignatureAlgorithmOID             | 1.2.840.113549.1.1.5 |
| IsCertificateAuthority            | False |
| SerialNumber                      | 1121a559b50ef9848661f0faeb7421bbdd2c |
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
#### Imported Functions
{{< details "Expand" >}}
* RtlInitUnicodeString
* ZwClose
* ZwMapViewOfSection
* ObReferenceObjectByHandle
* ZwOpenSection
* MmMapIoSpace
* IoDeleteSymbolicLink
* IofCompleteRequest
* ZwUnmapViewOfSection
* MmUnmapIoSpace
* IoCreateSymbolicLink
* IoCreateDevice
* __C_specific_handler
* IoDeleteDevice
* HalTranslateBusAddress

{{< /details >}}
#### Exported Functions
{{< details "Expand" >}}

{{< /details >}}

#### Sections
{{< details "Expand" >}}
* .text
* .rdata
* .data
* .pdata
* INIT

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
        "SHA256": "3ca71e85908ff67368e4dc00253f5691b9e6d50c966e7784143d75fb92aa3448",
        "SHA384": "d9d366f9328f2b55ee19a32cc5fd5148b81d764282fe5dc196c872ae249caa51d2c212ef39f33945dfe0cda81925e326"
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
        "SHA256": "cbdc9a0ad785d0c2013211746b42234e18bdc7d54a7a260647badc1c9e712ed4",
        "SHA384": "dcec542f242317863d0b3d23947e17d6982e381003831777b07ed75b46fb18bd0392a89c9beb6862981cd05f3f2fb77b"
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
        "SHA256": "4783380498acf592286ef2dea0fcc5bdea3f54d5e374d3e3497df9d5f662cfb6",
        "SHA384": "4f428f115cf3d008248f15f32007fc7c54bd454e1b48b765776b4c87c23ab8818d8fbcbb3646d35eca012b025260a3b8"
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
        "SHA256": "5b81998ed98b343c04134c336e03f3051779eae0e9f882e8339593d18556375d",
        "SHA384": "db0076cad41a0ef4ea68754ef6905bd5ff772adcb745b05c0060344e43588abc95952dc3ad272f5a8f17b206e4089aca"
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
        "SHA256": "ef14ea05bb066ee9f4188196dd69cd769b283ac4d7555db52f5e76922d3456e1",
        "SHA384": "6e7450a139856aeda6fa6284ff89b3752a9b646e096b4d33dd7e8e727742a2111481531581c0aa2cda0338e22cfdbad3"
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
| Filename           |  |
| Creation Timestamp           | 2005-05-25 00:39:12 |
| MD5                | [d6cc5709aca6a6b868962a6506d48abc](https://www.virustotal.com/gui/file/d6cc5709aca6a6b868962a6506d48abc) |
| SHA1               | [c0568bcdf57db1fa43cdee5a2a12b768a0064622](https://www.virustotal.com/gui/file/c0568bcdf57db1fa43cdee5a2a12b768a0064622) |
| SHA256             | [ad0309c2d225d8540a47250e3773876e05ce6a47a7767511e2f68645562c0686](https://www.virustotal.com/gui/file/ad0309c2d225d8540a47250e3773876e05ce6a47a7767511e2f68645562c0686) |
| Authentihash MD5   | [a17d227444e090ff69e24fcb6d43162b](https://www.virustotal.com/gui/search/authentihash%253Aa17d227444e090ff69e24fcb6d43162b) |
| Authentihash SHA1  | [43d3a3c1f7b14cfcc051cae2534dbbbb4c7fc120](https://www.virustotal.com/gui/search/authentihash%253A43d3a3c1f7b14cfcc051cae2534dbbbb4c7fc120) |
| Authentihash SHA256| [b8eb26b6f79020ae988e4fb752dc06e1b6779749bf4f8df2872fc2b92bab8020](https://www.virustotal.com/gui/search/authentihash%253Ab8eb26b6f79020ae988e4fb752dc06e1b6779749bf4f8df2872fc2b92bab8020) |
| RichPEHeaderHash MD5   | [deb9c1e252f598099d70d2b33a313da3](https://www.virustotal.com/gui/search/rich_pe_header_hash%253Adeb9c1e252f598099d70d2b33a313da3) |
| RichPEHeaderHash SHA1  | [f0c2801e0091ed6f5e10ea7045e911aa90030290](https://www.virustotal.com/gui/search/rich_pe_header_hash%253Af0c2801e0091ed6f5e10ea7045e911aa90030290) |
| RichPEHeaderHash SHA256| [914fb9761d50c3fa2ecf9fbd8af3735f9b8d6c4903e067c8af9546e79b6f22c7](https://www.virustotal.com/gui/search/rich_pe_header_hash%253A914fb9761d50c3fa2ecf9fbd8af3735f9b8d6c4903e067c8af9546e79b6f22c7) |

{{< button "https://github.com/magicsword-io/LOLDrivers/raw/main/drivers/d6cc5709aca6a6b868962a6506d48abc.bin" "Download" >}} 

#### Certificates

{{< details "Expand" >}}
###### Certificate 3825d7faf861af9ef490e726b5d65ad5
| Field                             | Value                      |
|-----------------------------------|----------------------------|
| ToBeSigned (TBS) MD5              | d6c7684e9aaa508cf268335f83afe040  |
| ToBeSigned (TBS) SHA1             | 18066d20ad92409c567cdfde745279ff71c75226 |
| ToBeSigned (TBS) SHA256           | a612fb22ce8be6dab75e47c98508f98496583e79c9c97b936a8caee9ea9f3fff |
| Subject                           | C=US, O=VeriSign, Inc., CN=VeriSign Time Stamping Services Signer , G2 |
| ValidFrom                         | 2007-06-15 00:00:00 |
| ValidTo                           | 2012-06-14 23:59:59 |
| Signature                         | 50c54bc82480dfe40d24c2de1ab1a102a1a6822d0c831581370a820e2cb05a1761b5d805fe88dbf19191b3561a40a6eb92be3839b07536743a984fe437ba9989ca95421db0b9c7a08d57e0fad5640442354e01d133a217c84daa27c7f2e1864c02384d8378c6fc53e0ebe00687dda4969e5e0c98e2a5bebf8285c360e1dfad28d8c7a54b64dac71b5bbdac3908d53822a1338b2f8a9aebbc07213f44410907b5651c24bc48d34480eba1cfc902b414cf54c716a3805cf9793e5d727d88179e2c43a2ca53ce7d3df62a3ab84f9400a56d0a835df95e53f418b3570f70c3fbf5ad95a00e17dec4168060c90f2b6e8604f1ebf47827d105c5ee345b5eb94932f233 |
| SignatureAlgorithmOID             | 1.2.840.113549.1.1.5 |
| IsCertificateAuthority            | False |
| SerialNumber                      | 3825d7faf861af9ef490e726b5d65ad5 |
| Version                           | 3 |
###### Certificate 47bf1995df8d524643f7db6d480d31a4
| Field                             | Value                      |
|-----------------------------------|----------------------------|
| ToBeSigned (TBS) MD5              | 518d2ea8a21e879c942d504824ac211c  |
| ToBeSigned (TBS) SHA1             | 21ce87d827077e61abddf2beba69fde5432ea031 |
| ToBeSigned (TBS) SHA256           | 1ec3b4f02e03930a470020e0e48d24b84678bb558f46182888d870541f5e25c7 |
| Subject                           | C=US, O=VeriSign, Inc., CN=VeriSign Time Stamping Services CA |
| ValidFrom                         | 2003-12-04 00:00:00 |
| ValidTo                           | 2013-12-03 23:59:59 |
| Signature                         | 4a6bf9ea58c2441c318979992b96bf82ac01d61c4ccdb08a586edf0829a35ec8ca9313e704520def47272f0038b0e4c9934e9ad4226215f73f37214f703180f18b3887b3e8e89700fecf55964e24d2a9274e7aaeb76141f32acee7c9d95eddbb2b853eb59db5d9e157ffbeb4c57ef5cf0c9ef097fe2bd33b521b1b3827f73f4a |
| SignatureAlgorithmOID             | 1.2.840.113549.1.1.5 |
| IsCertificateAuthority            | True |
| SerialNumber                      | 47bf1995df8d524643f7db6d480d31a4 |
| Version                           | 3 |
###### Certificate 04000000000108d9611cd6
| Field                             | Value                      |
|-----------------------------------|----------------------------|
| ToBeSigned (TBS) MD5              | 698f075151097d84c0b1f3e7bc3d6fca  |
| ToBeSigned (TBS) SHA1             | 041750993d7c9e063f02dfe74699598640911aab |
| ToBeSigned (TBS) SHA256           | a8622cca0913a20477be8313b8d16fcad5d83088b46b36ddac10b31e96abb5e8 |
| Subject                           | C=BE, O=GlobalSign nv,sa, OU=Primary Object Publishing CA, CN=GlobalSign Primary Object Publishing CA |
| ValidFrom                         | 1999-01-28 12:00:00 |
| ValidTo                           | 2014-01-27 11:00:00 |
| Signature                         | a0422eb876a7427186404d464d5b26b0b074f93f89a87b7cb7f1c697e08239999d43fe60823642b55b878df55df4bbffa91044a871d3c7f12241f29aa4a5ec63fae5eb654a19309d8bc7b6fddc3fe16cfdd5521407fc6d24ccb3cc81a2c052f327b96d9e063dd8a849023269c7054294d0bbe3bba908c393501bdb846dc0ba1e5298659c1376bdb3d567292f1f7baa2c51a0fd854f263c48a38127a6feee7f7899c245cf9d1f527ed7958bfde1d020c3af7e51a22f663bab2dcf2d8e8c4d7d18392128fbdcae6d6581d0e0d7184be7b5f774d784e6522aac3b68fd3b4ab80154849132bb95d28e6330a69ece2396feab2eb86a8b74dcde21a114c2fbbf53af10 |
| SignatureAlgorithmOID             | 1.2.840.113549.1.1.5 |
| IsCertificateAuthority            | True |
| SerialNumber                      | 04000000000108d9611cd6 |
| Version                           | 3 |
###### Certificate 0100000000011c08b7f67e
| Field                             | Value                      |
|-----------------------------------|----------------------------|
| ToBeSigned (TBS) MD5              | 4566c37f56f951a0ce5b4ae966c0ea9f  |
| ToBeSigned (TBS) SHA1             | a51cbf2834eb6f8535bc5e44913a9ec979379782 |
| ToBeSigned (TBS) SHA256           | 88a8e9a799af515b9223e4cdf24d0ef1e72f12124be02786f026a3c26317b417 |
| Subject                           | C=TW, O=Micro,Star Int&#39;l Co. Ltd., CN=Micro,Star Int&#39;l Co. Ltd. |
| ValidFrom                         | 2008-08-28 09:49:45 |
| ValidTo                           | 2011-08-28 09:49:45 |
| Signature                         | 572df373e9b036711b3cf5ee882e5d75d8d50f012407cf0c1b554ff8f41c7b6477fa0b2ad579f2c1fe7b8b9d7374b690527c219eb979686fb67d0b4cf2885d8d7d1261f05cb72fe4c9f294c52aa05f3e5d1ceb0d77085dbd6af07978032505da666f353283a8982af26985e69c1599479945b591124183574b8a4cc34caa62e31b523dac3fedbd04951b3661399ed34f5c5868d9bbe3295fc09890d9521e1cdcae2ff129f547d4c8ce8aa08616107c555fac60e5b63c14ddfeb6962af3608b75d9c77c69260d8af9775b83afaa15b8ecef6840cb4ee87d451f9042b49735ea40931c0664c8c2bf6a139db6ac5b90edcea63a6bf5b54978f027b1046170d476d0 |
| SignatureAlgorithmOID             | 1.2.840.113549.1.1.5 |
| IsCertificateAuthority            | False |
| SerialNumber                      | 0100000000011c08b7f67e |
| Version                           | 3 |
###### Certificate 04000000000117ab50b915
| Field                             | Value                      |
|-----------------------------------|----------------------------|
| ToBeSigned (TBS) MD5              | 5686b287d716c4d2428b092c4ef30f9c  |
| ToBeSigned (TBS) SHA1             | 306fb5fbeb3d531510bb4b663c4fd48adc121e14 |
| ToBeSigned (TBS) SHA256           | 60846fc990e271a707cd2d53d0bb21834a04f7652214aa0c12597ff6649d352d |
| Subject                           | C=BE, O=GlobalSign nv,sa, OU=ObjectSign CA, CN=GlobalSign ObjectSign CA |
| ValidFrom                         | 2004-01-22 09:00:00 |
| ValidTo                           | 2014-01-27 10:00:00 |
| Signature                         | 3c4a010267edf20a2e736e40252f1dccbc2db652141b27122cf1229e190a89b6ef352a29152b1a88c20f37168d2602d5e93080f608b9939ac0498f332c3035ff4ab9892aa75c38e761a778fe22851a07b4b9edcf21f25ddedff329c5d38d9e14c4285c88e590a300442912b23e759540244a6beee2d0ef862ddf6d741a4f1cc79424c443464f7b81015d23733cd9752e995361565e7ccd13e237d222e570f8a743f6154147fda24702c43651ca545da6cdcad61817533ff1d38e0f0aafda17941657a0991431c90e1611d2c04ca2a25978fbb6b933cff763c9d2c4c84953dd8a59525e7d3b385eed220360ac85cd58325dcdc31c07fa7ef67efbc8ac378be498 |
| SignatureAlgorithmOID             | 1.2.840.113549.1.1.5 |
| IsCertificateAuthority            | True |
| SerialNumber                      | 04000000000117ab50b915 |
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
#### Imported Functions
{{< details "Expand" >}}
* RtlInitUnicodeString
* ZwClose
* ZwMapViewOfSection
* ObReferenceObjectByHandle
* ZwOpenSection
* IoDeleteSymbolicLink
* IofCompleteRequest
* MmIsAddressValid
* ZwUnmapViewOfSection
* IoCreateSymbolicLink
* IoCreateDevice
* __C_specific_handler
* IoDeleteDevice
* HalTranslateBusAddress

{{< /details >}}
#### Exported Functions
{{< details "Expand" >}}

{{< /details >}}

#### Sections
{{< details "Expand" >}}
* .text
* .rdata
* .data
* .pdata
* INIT

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
        "SHA256": "3ca71e85908ff67368e4dc00253f5691b9e6d50c966e7784143d75fb92aa3448",
        "SHA384": "d9d366f9328f2b55ee19a32cc5fd5148b81d764282fe5dc196c872ae249caa51d2c212ef39f33945dfe0cda81925e326"
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
        "SHA256": "cbdc9a0ad785d0c2013211746b42234e18bdc7d54a7a260647badc1c9e712ed4",
        "SHA384": "dcec542f242317863d0b3d23947e17d6982e381003831777b07ed75b46fb18bd0392a89c9beb6862981cd05f3f2fb77b"
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
        "SHA256": "4783380498acf592286ef2dea0fcc5bdea3f54d5e374d3e3497df9d5f662cfb6",
        "SHA384": "4f428f115cf3d008248f15f32007fc7c54bd454e1b48b765776b4c87c23ab8818d8fbcbb3646d35eca012b025260a3b8"
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
        "SHA256": "5b81998ed98b343c04134c336e03f3051779eae0e9f882e8339593d18556375d",
        "SHA384": "db0076cad41a0ef4ea68754ef6905bd5ff772adcb745b05c0060344e43588abc95952dc3ad272f5a8f17b206e4089aca"
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
        "SHA256": "ef14ea05bb066ee9f4188196dd69cd769b283ac4d7555db52f5e76922d3456e1",
        "SHA384": "6e7450a139856aeda6fa6284ff89b3752a9b646e096b4d33dd7e8e727742a2111481531581c0aa2cda0338e22cfdbad3"
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
| Filename           |  |
| Creation Timestamp           | 2005-05-25 00:39:12 |
| MD5                | [adc1e141b57505fd011bc1efb1ae6967](https://www.virustotal.com/gui/file/adc1e141b57505fd011bc1efb1ae6967) |
| SHA1               | [d28b604b9bb608979cc0eab1e9e93e11c721aa3d](https://www.virustotal.com/gui/file/d28b604b9bb608979cc0eab1e9e93e11c721aa3d) |
| SHA256             | [1c425793a8ce87be916969d6d7e9dd0687b181565c3b483ce53ad1ec6fb72a17](https://www.virustotal.com/gui/file/1c425793a8ce87be916969d6d7e9dd0687b181565c3b483ce53ad1ec6fb72a17) |
| Authentihash MD5   | [a17d227444e090ff69e24fcb6d43162b](https://www.virustotal.com/gui/search/authentihash%253Aa17d227444e090ff69e24fcb6d43162b) |
| Authentihash SHA1  | [43d3a3c1f7b14cfcc051cae2534dbbbb4c7fc120](https://www.virustotal.com/gui/search/authentihash%253A43d3a3c1f7b14cfcc051cae2534dbbbb4c7fc120) |
| Authentihash SHA256| [b8eb26b6f79020ae988e4fb752dc06e1b6779749bf4f8df2872fc2b92bab8020](https://www.virustotal.com/gui/search/authentihash%253Ab8eb26b6f79020ae988e4fb752dc06e1b6779749bf4f8df2872fc2b92bab8020) |
| RichPEHeaderHash MD5   | [deb9c1e252f598099d70d2b33a313da3](https://www.virustotal.com/gui/search/rich_pe_header_hash%253Adeb9c1e252f598099d70d2b33a313da3) |
| RichPEHeaderHash SHA1  | [f0c2801e0091ed6f5e10ea7045e911aa90030290](https://www.virustotal.com/gui/search/rich_pe_header_hash%253Af0c2801e0091ed6f5e10ea7045e911aa90030290) |
| RichPEHeaderHash SHA256| [914fb9761d50c3fa2ecf9fbd8af3735f9b8d6c4903e067c8af9546e79b6f22c7](https://www.virustotal.com/gui/search/rich_pe_header_hash%253A914fb9761d50c3fa2ecf9fbd8af3735f9b8d6c4903e067c8af9546e79b6f22c7) |

{{< button "https://github.com/magicsword-io/LOLDrivers/raw/main/drivers/adc1e141b57505fd011bc1efb1ae6967.bin" "Download" >}} 

#### Certificates

{{< details "Expand" >}}
###### Certificate 040000000000f97faa2e1e
| Field                             | Value                      |
|-----------------------------------|----------------------------|
| ToBeSigned (TBS) MD5              | 59466cb0c1788b2f251fce3495837102  |
| ToBeSigned (TBS) SHA1             | c5cfc5f6a131a3a77c3905c9893c99bb1b2baa0b |
| ToBeSigned (TBS) SHA256           | eedda02668f7636eeec69429a7164cc47ca3de0539122d37f5b8078df7ee56db |
| Subject                           | CN=GlobalSign RootSign Partners CA, OU=RootSign Partners CA, O=GlobalSign nv,sa, C=BE |
| ValidFrom                         | 2003-12-16 13:00:00 |
| ValidTo                           | 2014-01-27 11:00:00 |
| Signature                         | 5c2f2e674a26b3e7b53f353cdda003ed569af9443752163065c7d14ea20f8db7b6b6678ee74cec8d95bee6cea7227874acd7f87499b3f7ce8b1338d596cc8d76c52f38b23aae61be0b8799e321626423398d84f6858df777ffb03806f07ec1485fb5ee582606660522749283a7dbb5f992e3e8c3192c2e63efbb1fdff9f70747660d0789977ef8332c9ecbae143df11cdfa3f179afc8928f9471c4d144c554db1eb50b0aa942a3afd643391dee8f9398585bbe6e9c0bf563ec5e99c2f954fa010746da0db06424cf8ed1061d4f3ca26377455ba4bc5fb080bb31e00b54015c161d724ed52a6947d11b667e5f016ef135916be02efeb045d81627b5c58bc2da53 |
| SignatureAlgorithmOID             | 1.2.840.113549.1.1.5 |
| IsCertificateAuthority            | True |
| SerialNumber                      | 040000000000f97faa2e1e |
| Version                           | 3 |
###### Certificate 0400000000011092eb8295
| Field                             | Value                      |
|-----------------------------------|----------------------------|
| ToBeSigned (TBS) MD5              | 11d73a3638fc78e0bac6c459feadcc42  |
| ToBeSigned (TBS) SHA1             | 6636f7dcf81b370b919966f9063295ec84422f91 |
| ToBeSigned (TBS) SHA256           | 1eb5fc1d2e3254b1e3c4587a6efed87ee65306525e684b4cfa4b51893cfe86a3 |
| Subject                           | O=GlobalSign, CN=GlobalSign Time Stamping Authority, emailAddress=timestampinfo@globalsign.com |
| ValidFrom                         | 2007-02-05 09:00:00 |
| ValidTo                           | 2014-01-27 09:00:00 |
| Signature                         | 649b07caaccc411e37ef6f349cb5e8ca48f9daeafaf7172e5cad193b7311ec5adbfd7b213161c092515bb166b07c64d8fe10b471a8bc9e75379c5f6ff2da0437b8ecc003e256b7785995581d7a7c3e18d74c32bdf91ee723457fdee08d65825b45fd64c66fc3d7ea12411d0c395ef696f8c3cd9e1fff51886976988b8eb42788821ad63c7aabb04eb73ee8d434d2c1a439533cb2747b15373054a6ebb924cc2f084b4364f14aaf8d9ce8546cb2dbdc3bb1c722849f558e72a8b2a8f6f0ff03c996ebab8273dabe45561936fdba6cbc71f0d3c7c376d7e4bce2a1a67200cfbdb200ed92aa39ab09d16e3953862ad43b517398b754e9972d9977ee123e3642257f |
| SignatureAlgorithmOID             | 1.2.840.113549.1.1.5 |
| IsCertificateAuthority            | True |
| SerialNumber                      | 0400000000011092eb8295 |
| Version                           | 3 |
###### Certificate 4191a15a3978dfcf496566381d4c75c2
| Field                             | Value                      |
|-----------------------------------|----------------------------|
| ToBeSigned (TBS) MD5              | 41011f8d0e7c7a6408334ca387914c61  |
| ToBeSigned (TBS) SHA1             | c7fc1727f5b75a6421a1f95c73bbdb23580c48e5 |
| ToBeSigned (TBS) SHA256           | 88dd3952638ee82738c03168e6fd863fe4eab1059ee5e2926ad8cb587c255dc0 |
| Subject                           | C=US, O=VeriSign, Inc., OU=VeriSign Trust Network, OU=Terms of use at https://www.verisign.com/rpa (c)04, CN=VeriSign Class 3 Code Signing 2004 CA |
| ValidFrom                         | 2004-07-16 00:00:00 |
| ValidTo                           | 2014-07-15 23:59:59 |
| Signature                         | ae3a17b84a7b55fa6455ec40a4ed494190999c89bcaf2e1dca7823f91c190f7feb68bc32d98838dedc3fd389b43fb18296f1a45abaed2e26d3de7c016e000a00a4069211480940f91c1879672324e0bbd5e150ae1bf50edde02e81cd80a36c524f9175558aba22f2d2ea4175882f63557d1e545a9559cad93481c05f5ef67ab5 |
| SignatureAlgorithmOID             | 1.2.840.113549.1.1.5 |
| IsCertificateAuthority            | True |
| SerialNumber                      | 4191a15a3978dfcf496566381d4c75c2 |
| Version                           | 3 |
###### Certificate 546ea040bf5075ce0a5c01d4c6ded19d
| Field                             | Value                      |
|-----------------------------------|----------------------------|
| ToBeSigned (TBS) MD5              | 8f51b4e16b87e1cc89b9d0c997227546  |
| ToBeSigned (TBS) SHA1             | 8f3cdd2b86ae03653f0612911a2f01a9dca49a22 |
| ToBeSigned (TBS) SHA256           | c7f57b7287c808d2713aba9e368fe387b5825bfbda1bd1824f374beaa8e30be9 |
| Subject                           | C=US, ST=California, L=Brea, O=EVGA, OU=Digital ID Class 3 , Microsoft Software Validation v2, CN=EVGA |
| ValidFrom                         | 2008-04-16 00:00:00 |
| ValidTo                           | 2010-04-16 23:59:59 |
| Signature                         | 13a3b8caa6bd8d63308898b0c92b79574e5d122a3ecba9758ec450b7c8c848ee5bc486db6370a8dfeb4c96c2c25512f7a3e759cc57a4d92f1a44fba15ca0c1156d22c49251b4e6a01bb93e4a62522ee5af4286c759c01c66fa5ce4452a4f112d03560bfa9737a3d0f3008b3cc48f2042b4428643f1efb4b99a34d0545c9934f1a6f35819e469430b74ba475a2135660948131cf24c9b1fb84580a1fd63eb3218d282e4f7caf77f4adbecb51e4b8237937eda0b7fcc20fc2273bf38282ee69ae6730b21c5314bcdc3f2e3a1e6f6c3ccb2139800f69d3f2fadc235080214f1c9b11e6a8f2165a45e15cca3c3542c2bac7225208a84828456d2e93cfe8315b092a1 |
| SignatureAlgorithmOID             | 1.2.840.113549.1.1.5 |
| IsCertificateAuthority            | False |
| SerialNumber                      | 546ea040bf5075ce0a5c01d4c6ded19d |
| Version                           | 3 |
###### Certificate 610c120600000000001b
| Field                             | Value                      |
|-----------------------------------|----------------------------|
| ToBeSigned (TBS) MD5              | 53c41bc1164e09e0cd1617a5bf913efd  |
| ToBeSigned (TBS) SHA1             | 93c03aac8951d494ecd5696b1c08658541b18727 |
| ToBeSigned (TBS) SHA256           | 40bddadac24dc61ca4fb5cab2a2bc5d876bc36808311039a7a3e1a4066f7489b |
| Subject                           | C=US, O=VeriSign, Inc., OU=Class 3 Public Primary Certification Authority |
| ValidFrom                         | 2006-05-23 17:01:29 |
| ValidTo                           | 2016-05-23 17:11:29 |
| Signature                         | 01e446b33b457f7513877e5f43de468ecb8abdb64741bccccc7491d8ce395195a4a6b547c0efd2da7b8f5711f4328c7ccd3fee42da04214af7c843884a6f5cca14fc4bd19f4cbdd4556ecc02be0da6888f8609baa425bde8b0f0fa8b714e67b0cb82a8d78e55f737ebf03e88efe4e08afd1c6e2e61414875b4b02c1d28d8490fd715f02473253ccc880cde284c6554fe5eae8cea19ad2c51b29b3a47f53c80350117e24987d6544afb4bab07bcbf7d79cfbf35005cbb9ecffc82891b39a05197b6dec0b307ff449644c0342a195cabeef03bec294eb513c537857e75d5b4d60d066eb5d26c237167eaf1718eaf4e74aa0cf9ecbf4c58fa5e909b6d39cb86883f8b1ca81632d5fe6db9f1f8b3ead791f6364778c0272a15c768d6f4c5fc4f4ec8673f102d409ff11ec96148e7a703fc31730cf04688fe56da492995ef09daa3e5beef60ecd954a0599c28bd54ef66157f874c84dba60e95672e517b3439b641c28c846826dc240209e7818e0a972defeea7b998a60f818dc710b5e1ed982f486f53854964789bec5dac970b5526c3efba8dc8d1a52f5a7f936b611a339b18b8a26210de24ea76e12f43ebecdd7c12342489da2855aee5754e312b6763b6a8d7ab730a03cec5ea593fc7eb2a45aea8625b2f009939abb45f73c308ec80118f470e8f2a1343e191066255bbffba3da9a93d260faeca7d628b155589d694344dd665 |
| SignatureAlgorithmOID             | 1.2.840.113549.1.1.5 |
| IsCertificateAuthority            | True |
| SerialNumber                      | 610c120600000000001b |
| Version                           | 3 |

{{< /details >}}
#### Imports
{{< details "Expand" >}}
* ntoskrnl.exe
* HAL.dll

{{< /details >}}
#### Imported Functions
{{< details "Expand" >}}
* RtlInitUnicodeString
* ZwClose
* ZwMapViewOfSection
* ObReferenceObjectByHandle
* ZwOpenSection
* IoDeleteSymbolicLink
* IofCompleteRequest
* MmIsAddressValid
* ZwUnmapViewOfSection
* IoCreateSymbolicLink
* IoCreateDevice
* __C_specific_handler
* IoDeleteDevice
* HalTranslateBusAddress

{{< /details >}}
#### Exported Functions
{{< details "Expand" >}}

{{< /details >}}

#### Sections
{{< details "Expand" >}}
* .text
* .rdata
* .data
* .pdata
* INIT

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
        "SHA256": "3ca71e85908ff67368e4dc00253f5691b9e6d50c966e7784143d75fb92aa3448",
        "SHA384": "d9d366f9328f2b55ee19a32cc5fd5148b81d764282fe5dc196c872ae249caa51d2c212ef39f33945dfe0cda81925e326"
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
        "SHA256": "cbdc9a0ad785d0c2013211746b42234e18bdc7d54a7a260647badc1c9e712ed4",
        "SHA384": "dcec542f242317863d0b3d23947e17d6982e381003831777b07ed75b46fb18bd0392a89c9beb6862981cd05f3f2fb77b"
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
        "SHA256": "4783380498acf592286ef2dea0fcc5bdea3f54d5e374d3e3497df9d5f662cfb6",
        "SHA384": "4f428f115cf3d008248f15f32007fc7c54bd454e1b48b765776b4c87c23ab8818d8fbcbb3646d35eca012b025260a3b8"
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
        "SHA256": "5b81998ed98b343c04134c336e03f3051779eae0e9f882e8339593d18556375d",
        "SHA384": "db0076cad41a0ef4ea68754ef6905bd5ff772adcb745b05c0060344e43588abc95952dc3ad272f5a8f17b206e4089aca"
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
        "SHA256": "ef14ea05bb066ee9f4188196dd69cd769b283ac4d7555db52f5e76922d3456e1",
        "SHA384": "6e7450a139856aeda6fa6284ff89b3752a9b646e096b4d33dd7e8e727742a2111481531581c0aa2cda0338e22cfdbad3"
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
| Filename           |  |
| Creation Timestamp           | 2005-05-25 00:39:12 |
| MD5                | [2e887e52e45bba3c47ccd0e75fc5266f](https://www.virustotal.com/gui/file/2e887e52e45bba3c47ccd0e75fc5266f) |
| SHA1               | [022f7aa4d0f04d594588ae9fa65c90bcc4bda833](https://www.virustotal.com/gui/file/022f7aa4d0f04d594588ae9fa65c90bcc4bda833) |
| SHA256             | [d21aba58222930cb75946a0fb72b4adc96de583d3f7d8dc13829b804eb877257](https://www.virustotal.com/gui/file/d21aba58222930cb75946a0fb72b4adc96de583d3f7d8dc13829b804eb877257) |
| Authentihash MD5   | [a17d227444e090ff69e24fcb6d43162b](https://www.virustotal.com/gui/search/authentihash%253Aa17d227444e090ff69e24fcb6d43162b) |
| Authentihash SHA1  | [43d3a3c1f7b14cfcc051cae2534dbbbb4c7fc120](https://www.virustotal.com/gui/search/authentihash%253A43d3a3c1f7b14cfcc051cae2534dbbbb4c7fc120) |
| Authentihash SHA256| [b8eb26b6f79020ae988e4fb752dc06e1b6779749bf4f8df2872fc2b92bab8020](https://www.virustotal.com/gui/search/authentihash%253Ab8eb26b6f79020ae988e4fb752dc06e1b6779749bf4f8df2872fc2b92bab8020) |
| RichPEHeaderHash MD5   | [deb9c1e252f598099d70d2b33a313da3](https://www.virustotal.com/gui/search/rich_pe_header_hash%253Adeb9c1e252f598099d70d2b33a313da3) |
| RichPEHeaderHash SHA1  | [f0c2801e0091ed6f5e10ea7045e911aa90030290](https://www.virustotal.com/gui/search/rich_pe_header_hash%253Af0c2801e0091ed6f5e10ea7045e911aa90030290) |
| RichPEHeaderHash SHA256| [914fb9761d50c3fa2ecf9fbd8af3735f9b8d6c4903e067c8af9546e79b6f22c7](https://www.virustotal.com/gui/search/rich_pe_header_hash%253A914fb9761d50c3fa2ecf9fbd8af3735f9b8d6c4903e067c8af9546e79b6f22c7) |

{{< button "https://github.com/magicsword-io/LOLDrivers/raw/main/drivers/2e887e52e45bba3c47ccd0e75fc5266f.bin" "Download" >}} 

#### Certificates

{{< details "Expand" >}}
###### Certificate 3825d7faf861af9ef490e726b5d65ad5
| Field                             | Value                      |
|-----------------------------------|----------------------------|
| ToBeSigned (TBS) MD5              | d6c7684e9aaa508cf268335f83afe040  |
| ToBeSigned (TBS) SHA1             | 18066d20ad92409c567cdfde745279ff71c75226 |
| ToBeSigned (TBS) SHA256           | a612fb22ce8be6dab75e47c98508f98496583e79c9c97b936a8caee9ea9f3fff |
| Subject                           | C=US, O=VeriSign, Inc., CN=VeriSign Time Stamping Services Signer , G2 |
| ValidFrom                         | 2007-06-15 00:00:00 |
| ValidTo                           | 2012-06-14 23:59:59 |
| Signature                         | 50c54bc82480dfe40d24c2de1ab1a102a1a6822d0c831581370a820e2cb05a1761b5d805fe88dbf19191b3561a40a6eb92be3839b07536743a984fe437ba9989ca95421db0b9c7a08d57e0fad5640442354e01d133a217c84daa27c7f2e1864c02384d8378c6fc53e0ebe00687dda4969e5e0c98e2a5bebf8285c360e1dfad28d8c7a54b64dac71b5bbdac3908d53822a1338b2f8a9aebbc07213f44410907b5651c24bc48d34480eba1cfc902b414cf54c716a3805cf9793e5d727d88179e2c43a2ca53ce7d3df62a3ab84f9400a56d0a835df95e53f418b3570f70c3fbf5ad95a00e17dec4168060c90f2b6e8604f1ebf47827d105c5ee345b5eb94932f233 |
| SignatureAlgorithmOID             | 1.2.840.113549.1.1.5 |
| IsCertificateAuthority            | False |
| SerialNumber                      | 3825d7faf861af9ef490e726b5d65ad5 |
| Version                           | 3 |
###### Certificate 47bf1995df8d524643f7db6d480d31a4
| Field                             | Value                      |
|-----------------------------------|----------------------------|
| ToBeSigned (TBS) MD5              | 518d2ea8a21e879c942d504824ac211c  |
| ToBeSigned (TBS) SHA1             | 21ce87d827077e61abddf2beba69fde5432ea031 |
| ToBeSigned (TBS) SHA256           | 1ec3b4f02e03930a470020e0e48d24b84678bb558f46182888d870541f5e25c7 |
| Subject                           | C=US, O=VeriSign, Inc., CN=VeriSign Time Stamping Services CA |
| ValidFrom                         | 2003-12-04 00:00:00 |
| ValidTo                           | 2013-12-03 23:59:59 |
| Signature                         | 4a6bf9ea58c2441c318979992b96bf82ac01d61c4ccdb08a586edf0829a35ec8ca9313e704520def47272f0038b0e4c9934e9ad4226215f73f37214f703180f18b3887b3e8e89700fecf55964e24d2a9274e7aaeb76141f32acee7c9d95eddbb2b853eb59db5d9e157ffbeb4c57ef5cf0c9ef097fe2bd33b521b1b3827f73f4a |
| SignatureAlgorithmOID             | 1.2.840.113549.1.1.5 |
| IsCertificateAuthority            | True |
| SerialNumber                      | 47bf1995df8d524643f7db6d480d31a4 |
| Version                           | 3 |
###### Certificate 04000000000108d9611cd6
| Field                             | Value                      |
|-----------------------------------|----------------------------|
| ToBeSigned (TBS) MD5              | 698f075151097d84c0b1f3e7bc3d6fca  |
| ToBeSigned (TBS) SHA1             | 041750993d7c9e063f02dfe74699598640911aab |
| ToBeSigned (TBS) SHA256           | a8622cca0913a20477be8313b8d16fcad5d83088b46b36ddac10b31e96abb5e8 |
| Subject                           | C=BE, O=GlobalSign nv,sa, OU=Primary Object Publishing CA, CN=GlobalSign Primary Object Publishing CA |
| ValidFrom                         | 1999-01-28 12:00:00 |
| ValidTo                           | 2014-01-27 11:00:00 |
| Signature                         | a0422eb876a7427186404d464d5b26b0b074f93f89a87b7cb7f1c697e08239999d43fe60823642b55b878df55df4bbffa91044a871d3c7f12241f29aa4a5ec63fae5eb654a19309d8bc7b6fddc3fe16cfdd5521407fc6d24ccb3cc81a2c052f327b96d9e063dd8a849023269c7054294d0bbe3bba908c393501bdb846dc0ba1e5298659c1376bdb3d567292f1f7baa2c51a0fd854f263c48a38127a6feee7f7899c245cf9d1f527ed7958bfde1d020c3af7e51a22f663bab2dcf2d8e8c4d7d18392128fbdcae6d6581d0e0d7184be7b5f774d784e6522aac3b68fd3b4ab80154849132bb95d28e6330a69ece2396feab2eb86a8b74dcde21a114c2fbbf53af10 |
| SignatureAlgorithmOID             | 1.2.840.113549.1.1.5 |
| IsCertificateAuthority            | True |
| SerialNumber                      | 04000000000108d9611cd6 |
| Version                           | 3 |
###### Certificate 0100000000011c08b7f67e
| Field                             | Value                      |
|-----------------------------------|----------------------------|
| ToBeSigned (TBS) MD5              | 4566c37f56f951a0ce5b4ae966c0ea9f  |
| ToBeSigned (TBS) SHA1             | a51cbf2834eb6f8535bc5e44913a9ec979379782 |
| ToBeSigned (TBS) SHA256           | 88a8e9a799af515b9223e4cdf24d0ef1e72f12124be02786f026a3c26317b417 |
| Subject                           | C=TW, O=Micro,Star Int&#39;l Co. Ltd., CN=Micro,Star Int&#39;l Co. Ltd. |
| ValidFrom                         | 2008-08-28 09:49:45 |
| ValidTo                           | 2011-08-28 09:49:45 |
| Signature                         | 572df373e9b036711b3cf5ee882e5d75d8d50f012407cf0c1b554ff8f41c7b6477fa0b2ad579f2c1fe7b8b9d7374b690527c219eb979686fb67d0b4cf2885d8d7d1261f05cb72fe4c9f294c52aa05f3e5d1ceb0d77085dbd6af07978032505da666f353283a8982af26985e69c1599479945b591124183574b8a4cc34caa62e31b523dac3fedbd04951b3661399ed34f5c5868d9bbe3295fc09890d9521e1cdcae2ff129f547d4c8ce8aa08616107c555fac60e5b63c14ddfeb6962af3608b75d9c77c69260d8af9775b83afaa15b8ecef6840cb4ee87d451f9042b49735ea40931c0664c8c2bf6a139db6ac5b90edcea63a6bf5b54978f027b1046170d476d0 |
| SignatureAlgorithmOID             | 1.2.840.113549.1.1.5 |
| IsCertificateAuthority            | False |
| SerialNumber                      | 0100000000011c08b7f67e |
| Version                           | 3 |
###### Certificate 04000000000117ab50b915
| Field                             | Value                      |
|-----------------------------------|----------------------------|
| ToBeSigned (TBS) MD5              | 5686b287d716c4d2428b092c4ef30f9c  |
| ToBeSigned (TBS) SHA1             | 306fb5fbeb3d531510bb4b663c4fd48adc121e14 |
| ToBeSigned (TBS) SHA256           | 60846fc990e271a707cd2d53d0bb21834a04f7652214aa0c12597ff6649d352d |
| Subject                           | C=BE, O=GlobalSign nv,sa, OU=ObjectSign CA, CN=GlobalSign ObjectSign CA |
| ValidFrom                         | 2004-01-22 09:00:00 |
| ValidTo                           | 2014-01-27 10:00:00 |
| Signature                         | 3c4a010267edf20a2e736e40252f1dccbc2db652141b27122cf1229e190a89b6ef352a29152b1a88c20f37168d2602d5e93080f608b9939ac0498f332c3035ff4ab9892aa75c38e761a778fe22851a07b4b9edcf21f25ddedff329c5d38d9e14c4285c88e590a300442912b23e759540244a6beee2d0ef862ddf6d741a4f1cc79424c443464f7b81015d23733cd9752e995361565e7ccd13e237d222e570f8a743f6154147fda24702c43651ca545da6cdcad61817533ff1d38e0f0aafda17941657a0991431c90e1611d2c04ca2a25978fbb6b933cff763c9d2c4c84953dd8a59525e7d3b385eed220360ac85cd58325dcdc31c07fa7ef67efbc8ac378be498 |
| SignatureAlgorithmOID             | 1.2.840.113549.1.1.5 |
| IsCertificateAuthority            | True |
| SerialNumber                      | 04000000000117ab50b915 |
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
#### Imported Functions
{{< details "Expand" >}}
* RtlInitUnicodeString
* ZwClose
* ZwMapViewOfSection
* ObReferenceObjectByHandle
* ZwOpenSection
* IoDeleteSymbolicLink
* IofCompleteRequest
* MmIsAddressValid
* ZwUnmapViewOfSection
* IoCreateSymbolicLink
* IoCreateDevice
* __C_specific_handler
* IoDeleteDevice
* HalTranslateBusAddress

{{< /details >}}
#### Exported Functions
{{< details "Expand" >}}

{{< /details >}}

#### Sections
{{< details "Expand" >}}
* .text
* .rdata
* .data
* .pdata
* INIT

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
        "SHA256": "3ca71e85908ff67368e4dc00253f5691b9e6d50c966e7784143d75fb92aa3448",
        "SHA384": "d9d366f9328f2b55ee19a32cc5fd5148b81d764282fe5dc196c872ae249caa51d2c212ef39f33945dfe0cda81925e326"
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
        "SHA256": "cbdc9a0ad785d0c2013211746b42234e18bdc7d54a7a260647badc1c9e712ed4",
        "SHA384": "dcec542f242317863d0b3d23947e17d6982e381003831777b07ed75b46fb18bd0392a89c9beb6862981cd05f3f2fb77b"
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
        "SHA256": "4783380498acf592286ef2dea0fcc5bdea3f54d5e374d3e3497df9d5f662cfb6",
        "SHA384": "4f428f115cf3d008248f15f32007fc7c54bd454e1b48b765776b4c87c23ab8818d8fbcbb3646d35eca012b025260a3b8"
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
        "SHA256": "5b81998ed98b343c04134c336e03f3051779eae0e9f882e8339593d18556375d",
        "SHA384": "db0076cad41a0ef4ea68754ef6905bd5ff772adcb745b05c0060344e43588abc95952dc3ad272f5a8f17b206e4089aca"
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
        "SHA256": "ef14ea05bb066ee9f4188196dd69cd769b283ac4d7555db52f5e76922d3456e1",
        "SHA384": "6e7450a139856aeda6fa6284ff89b3752a9b646e096b4d33dd7e8e727742a2111481531581c0aa2cda0338e22cfdbad3"
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
| Filename           |  |
| Creation Timestamp           | 2011-09-06 06:24:50 |
| MD5                | [7f7b8cde26c4943c9465e412adbb790f](https://www.virustotal.com/gui/file/7f7b8cde26c4943c9465e412adbb790f) |
| SHA1               | [879e92a7427bdbcc051a18bbb3727ac68154e825](https://www.virustotal.com/gui/file/879e92a7427bdbcc051a18bbb3727ac68154e825) |
| SHA256             | [08828990218ebb4415c1bb33fa2b0a009efd0784b18b3f7ecd3bc078343f7208](https://www.virustotal.com/gui/file/08828990218ebb4415c1bb33fa2b0a009efd0784b18b3f7ecd3bc078343f7208) |
| Authentihash MD5   | [55466195f0b2f4afc4243b43a806e6d9](https://www.virustotal.com/gui/search/authentihash%253A55466195f0b2f4afc4243b43a806e6d9) |
| Authentihash SHA1  | [38b353d8480885de5dcf299deca99ce4f26a1d20](https://www.virustotal.com/gui/search/authentihash%253A38b353d8480885de5dcf299deca99ce4f26a1d20) |
| Authentihash SHA256| [5182caf10de9cec0740ecde5a081c21cdc100d7eb328ffe6f3f63183889fec6b](https://www.virustotal.com/gui/search/authentihash%253A5182caf10de9cec0740ecde5a081c21cdc100d7eb328ffe6f3f63183889fec6b) |
| RichPEHeaderHash MD5   | [59080883b71fd56bbf10ec0ae4b6bdd4](https://www.virustotal.com/gui/search/rich_pe_header_hash%253A59080883b71fd56bbf10ec0ae4b6bdd4) |
| RichPEHeaderHash SHA1  | [503a36a225568553cc9b05f63b3506c6ff21e12e](https://www.virustotal.com/gui/search/rich_pe_header_hash%253A503a36a225568553cc9b05f63b3506c6ff21e12e) |
| RichPEHeaderHash SHA256| [bc812d4ddc3ecfbf38c4d0d185e368fc58bac6e07f722db032bf6303daa7c946](https://www.virustotal.com/gui/search/rich_pe_header_hash%253Abc812d4ddc3ecfbf38c4d0d185e368fc58bac6e07f722db032bf6303daa7c946) |

{{< button "https://github.com/magicsword-io/LOLDrivers/raw/main/drivers/7f7b8cde26c4943c9465e412adbb790f.bin" "Download" >}} 

#### Certificates

{{< details "Expand" >}}
###### Certificate 0400000000012019c19066
| Field                             | Value                      |
|-----------------------------------|----------------------------|
| ToBeSigned (TBS) MD5              | 42023b9487cafe46c1b6a49c369a362e  |
| ToBeSigned (TBS) SHA1             | 7c7b524d269334b9f073c32e888e09544c6acd98 |
| ToBeSigned (TBS) SHA256           | b7126567833f3daa4085ff41e73112daad3d1e3808a942c1936520e2d6c46c78 |
| Subject                           | OU=Timestamping CA, O=GlobalSign, CN=GlobalSign Timestamping CA |
| ValidFrom                         | 2009-03-18 11:00:00 |
| ValidTo                           | 2028-01-28 12:00:00 |
| Signature                         | 5df6cb2b0d0140849f857a43706ae0c5e7aa0600d76713c9089131654f14a8a905dc389e6aa0300abd8dc78028ee4245ca94f3de5845a9803204f5595c6a70003927944df5b44634e81c5331b2b35416e9cc42abd5d959301cfb462725b88723b1e8758824831ec876377b01494548a4ede25dd27c9ca2dc2dba105a126265abae00c710343bcb72bd14240cdcc37627b4a7fee15829f20e169f91391d89a6e60f1c878ce258ac927e243eaaec14e73a33348bc63bac83ab0f14627aba1a2d4d4b1bc530f00b92797d3c78e0f8e6d215965999392b3061e8b8f8c0a1e9221411787dc4dc89bec0bb94e172aeebb540404fef171e585ed0a88996ac9228e9babf |
| SignatureAlgorithmOID             | 1.2.840.113549.1.1.5 |
| IsCertificateAuthority            | True |
| SerialNumber                      | 0400000000012019c19066 |
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
###### Certificate 01000000000125b0b4cc01
| Field                             | Value                      |
|-----------------------------------|----------------------------|
| ToBeSigned (TBS) MD5              | e3369c8e5aec0504b3a50455f615d9f9  |
| ToBeSigned (TBS) SHA1             | 13c244a894b40ecd18aaf97c362f20385bd005a7 |
| ToBeSigned (TBS) SHA256           | 26da721a670c72836926032fee6920118bfb9bff89cc8d0ce30d9452c33f2532 |
| Subject                           | C=BE, O=GlobalSign NV, CN=GlobalSign Time Stamping Authority |
| ValidFrom                         | 2009-12-21 09:32:56 |
| ValidTo                           | 2020-12-22 09:32:56 |
| Signature                         | bc89ecfee63655935c79d4117a86808f17b693b26d9b91a1561811c655eaf608edad9b9ef52b81c8bbdd607b1b47991e6d403e1d80c213d58e04052fdbe7ae529e688472a1e54a603cf89bd52f46d8c3b2b79353ac9b6c432424d1f1fce9562e3411581843eaefff34746ca0c06c7fad031969881e9560cabbbd0cbb76efc724b081c63831cf36ad0c38b89020849b2e8f28b99ff6ca9427cdac396157e0e3955a9c769230f5dea6973d721c2a6032a8334d8635338a5cf3a4fdf7062ce16b4b30f5cbd34362f841b9de7d20cb058c8e2cf65f35fd338d42896508362ca389f45a858bb0b97bdb6ccba1f8d20e1bbb977cd12779be9d7c3be6a75634d8c991a9 |
| SignatureAlgorithmOID             | 1.2.840.113549.1.1.5 |
| IsCertificateAuthority            | False |
| SerialNumber                      | 01000000000125b0b4cc01 |
| Version                           | 3 |
###### Certificate 1121a559b50ef9848661f0faeb7421bbdd2c
| Field                             | Value                      |
|-----------------------------------|----------------------------|
| ToBeSigned (TBS) MD5              | 3a98a18e8636f2a01e49e2a6d116c360  |
| ToBeSigned (TBS) SHA1             | a2938150e46525adcec2e3a2348824bc1cf532b2 |
| ToBeSigned (TBS) SHA256           | 01a2e2d31d0a4f3005753cce5972b5da2a7c08b0750fb6947e0fd231e64ae7ec |
| Subject                           | C=TW, ST=Taiwan, L=New Taipei City, O=MICRO,STAR INTERNATIONAL CO., LTD., OU=MICRO,STAR INTERNATIONAL CO., LTD., CN=MICRO,STAR INTERNATIONAL CO., LTD. |
| ValidFrom                         | 2011-08-30 06:46:09 |
| ValidTo                           | 2014-08-30 06:46:09 |
| Signature                         | 87bf57ab7ffd7e005076b34b14ddd924045ec7e389871661794f1ece1bef10e050893b28236cb650af1415f8cd95e86c2052d93311d73e0bbe6fb1c22ddea438a93c8b18bd4b8c0f81ad07032efb46d406bbaa730dd3ac92cbf0d9cc711a397a0e0320b213a5161e6be83ec69967a712b463129ea56d5a8ecd3ff8901be09dfaa0a0f10e879b307863e1b1c3a3149ac73bc3f3160db7012229b57bced6d47b875878663642a8cddd03da1e7f236b8cf16713a5e0f4c892aaca77a8c7dab41d84567e2bbf09b336a2824e0e18d54d199e6e024d2630bb210cd24a9ef4b377be0429e2ecc9bf8478a8c6a78c686e26f29c95925baee85e4bbb97b6eecffe44a25e |
| SignatureAlgorithmOID             | 1.2.840.113549.1.1.5 |
| IsCertificateAuthority            | False |
| SerialNumber                      | 1121a559b50ef9848661f0faeb7421bbdd2c |
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
#### Imported Functions
{{< details "Expand" >}}
* RtlInitUnicodeString
* ZwClose
* ZwMapViewOfSection
* ObReferenceObjectByHandle
* ZwOpenSection
* MmMapIoSpace
* IoDeleteSymbolicLink
* IofCompleteRequest
* ZwUnmapViewOfSection
* MmUnmapIoSpace
* IoCreateSymbolicLink
* IoCreateDevice
* __C_specific_handler
* IoDeleteDevice
* HalTranslateBusAddress

{{< /details >}}
#### Exported Functions
{{< details "Expand" >}}

{{< /details >}}

#### Sections
{{< details "Expand" >}}
* .text
* .rdata
* .data
* .pdata
* INIT

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
        "SHA256": "3ca71e85908ff67368e4dc00253f5691b9e6d50c966e7784143d75fb92aa3448",
        "SHA384": "d9d366f9328f2b55ee19a32cc5fd5148b81d764282fe5dc196c872ae249caa51d2c212ef39f33945dfe0cda81925e326"
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
        "SHA256": "cbdc9a0ad785d0c2013211746b42234e18bdc7d54a7a260647badc1c9e712ed4",
        "SHA384": "dcec542f242317863d0b3d23947e17d6982e381003831777b07ed75b46fb18bd0392a89c9beb6862981cd05f3f2fb77b"
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
        "SHA256": "4783380498acf592286ef2dea0fcc5bdea3f54d5e374d3e3497df9d5f662cfb6",
        "SHA384": "4f428f115cf3d008248f15f32007fc7c54bd454e1b48b765776b4c87c23ab8818d8fbcbb3646d35eca012b025260a3b8"
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
        "SHA256": "5b81998ed98b343c04134c336e03f3051779eae0e9f882e8339593d18556375d",
        "SHA384": "db0076cad41a0ef4ea68754ef6905bd5ff772adcb745b05c0060344e43588abc95952dc3ad272f5a8f17b206e4089aca"
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
        "SHA256": "ef14ea05bb066ee9f4188196dd69cd769b283ac4d7555db52f5e76922d3456e1",
        "SHA384": "6e7450a139856aeda6fa6284ff89b3752a9b646e096b4d33dd7e8e727742a2111481531581c0aa2cda0338e22cfdbad3"
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
| Filename           |  |
| Creation Timestamp           | 2016-09-30 06:03:17 |
| MD5                | [86635fdc8e28957e6c01fc483fe7b020](https://www.virustotal.com/gui/file/86635fdc8e28957e6c01fc483fe7b020) |
| SHA1               | [089411e052ea17d66033155f77ae683c50147018](https://www.virustotal.com/gui/file/089411e052ea17d66033155f77ae683c50147018) |
| SHA256             | [1cedd5815bb6e20d3697103cfc0275f5015f469e6007e8cac16892c97731c695](https://www.virustotal.com/gui/file/1cedd5815bb6e20d3697103cfc0275f5015f469e6007e8cac16892c97731c695) |
| Authentihash MD5   | [538e5e595c61d2ea8defb7b047784734](https://www.virustotal.com/gui/search/authentihash%253A538e5e595c61d2ea8defb7b047784734) |
| Authentihash SHA1  | [4a68c2d7a4c471e062a32c83a36eedb45a619683](https://www.virustotal.com/gui/search/authentihash%253A4a68c2d7a4c471e062a32c83a36eedb45a619683) |
| Authentihash SHA256| [478c36f8af7844a80e24c1822507beef6314519185717ec7ae224a0e04b2f330](https://www.virustotal.com/gui/search/authentihash%253A478c36f8af7844a80e24c1822507beef6314519185717ec7ae224a0e04b2f330) |
| RichPEHeaderHash MD5   | [ebe2ae976914018e88e9fc480e7b6269](https://www.virustotal.com/gui/search/rich_pe_header_hash%253Aebe2ae976914018e88e9fc480e7b6269) |
| RichPEHeaderHash SHA1  | [960715bfbccb53b6c4eccca3b232b25640e15b52](https://www.virustotal.com/gui/search/rich_pe_header_hash%253A960715bfbccb53b6c4eccca3b232b25640e15b52) |
| RichPEHeaderHash SHA256| [d755e9f3cb861f5227319238f1811265e332e36a922b9a25da38b122a791fdfa](https://www.virustotal.com/gui/search/rich_pe_header_hash%253Ad755e9f3cb861f5227319238f1811265e332e36a922b9a25da38b122a791fdfa) |

{{< button "https://github.com/magicsword-io/LOLDrivers/raw/main/drivers/86635fdc8e28957e6c01fc483fe7b020.bin" "Download" >}} 

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
#### Imported Functions
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
#### Exported Functions
{{< details "Expand" >}}

{{< /details >}}

#### Sections
{{< details "Expand" >}}
* .text
* .rdata
* .data
* .pdata
* INIT

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
        "SHA256": "3ca71e85908ff67368e4dc00253f5691b9e6d50c966e7784143d75fb92aa3448",
        "SHA384": "d9d366f9328f2b55ee19a32cc5fd5148b81d764282fe5dc196c872ae249caa51d2c212ef39f33945dfe0cda81925e326"
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
        "SHA256": "cbdc9a0ad785d0c2013211746b42234e18bdc7d54a7a260647badc1c9e712ed4",
        "SHA384": "dcec542f242317863d0b3d23947e17d6982e381003831777b07ed75b46fb18bd0392a89c9beb6862981cd05f3f2fb77b"
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
        "SHA256": "4783380498acf592286ef2dea0fcc5bdea3f54d5e374d3e3497df9d5f662cfb6",
        "SHA384": "4f428f115cf3d008248f15f32007fc7c54bd454e1b48b765776b4c87c23ab8818d8fbcbb3646d35eca012b025260a3b8"
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
        "SHA256": "5b81998ed98b343c04134c336e03f3051779eae0e9f882e8339593d18556375d",
        "SHA384": "db0076cad41a0ef4ea68754ef6905bd5ff772adcb745b05c0060344e43588abc95952dc3ad272f5a8f17b206e4089aca"
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
        "SHA256": "ef14ea05bb066ee9f4188196dd69cd769b283ac4d7555db52f5e76922d3456e1",
        "SHA384": "6e7450a139856aeda6fa6284ff89b3752a9b646e096b4d33dd7e8e727742a2111481531581c0aa2cda0338e22cfdbad3"
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
| Filename           |  |
| Creation Timestamp           | 2015-04-24 01:01:47 |
| MD5                | [e6ea0e8d2edcc6cad3c414a889d17ac4](https://www.virustotal.com/gui/file/e6ea0e8d2edcc6cad3c414a889d17ac4) |
| SHA1               | [9db1585c0fab6a9feb411c39267ac4ad29171696](https://www.virustotal.com/gui/file/9db1585c0fab6a9feb411c39267ac4ad29171696) |
| SHA256             | [a0dd3d43ab891777b11d4fdcb3b7f246b80bc66d12f7810cf268a5f6f4f8eb7b](https://www.virustotal.com/gui/file/a0dd3d43ab891777b11d4fdcb3b7f246b80bc66d12f7810cf268a5f6f4f8eb7b) |
| Authentihash MD5   | [cfe667280acf69d4b5d0e2dbc76510e4](https://www.virustotal.com/gui/search/authentihash%253Acfe667280acf69d4b5d0e2dbc76510e4) |
| Authentihash SHA1  | [b3249bacda6e43aa2c46c2af802c9ee0b7e2fd7b](https://www.virustotal.com/gui/search/authentihash%253Ab3249bacda6e43aa2c46c2af802c9ee0b7e2fd7b) |
| Authentihash SHA256| [3c9829a16eb85272b0e1a2917feffaab8ddb23e633b168b389669339a0cee0b5](https://www.virustotal.com/gui/search/authentihash%253A3c9829a16eb85272b0e1a2917feffaab8ddb23e633b168b389669339a0cee0b5) |
| RichPEHeaderHash MD5   | [ebe2ae976914018e88e9fc480e7b6269](https://www.virustotal.com/gui/search/rich_pe_header_hash%253Aebe2ae976914018e88e9fc480e7b6269) |
| RichPEHeaderHash SHA1  | [960715bfbccb53b6c4eccca3b232b25640e15b52](https://www.virustotal.com/gui/search/rich_pe_header_hash%253A960715bfbccb53b6c4eccca3b232b25640e15b52) |
| RichPEHeaderHash SHA256| [d755e9f3cb861f5227319238f1811265e332e36a922b9a25da38b122a791fdfa](https://www.virustotal.com/gui/search/rich_pe_header_hash%253Ad755e9f3cb861f5227319238f1811265e332e36a922b9a25da38b122a791fdfa) |

{{< button "https://github.com/magicsword-io/LOLDrivers/raw/main/drivers/e6ea0e8d2edcc6cad3c414a889d17ac4.bin" "Download" >}} 

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
###### Certificate 112106a081d33fd87ae5824cc16b52094e03
| Field                             | Value                      |
|-----------------------------------|----------------------------|
| ToBeSigned (TBS) MD5              | a0ac4d48fe852f7b3ed4e623d59a825f  |
| ToBeSigned (TBS) SHA1             | d4db9846bc4d7db142eeb364286f6de7c102420c |
| ToBeSigned (TBS) SHA256           | 78d2e41a13eb4e9171bae2d2adb192cf39210b5231f77cda936bcfbe8c003bdf |
| Subject                           | C=SG, O=GMO GlobalSign Pte Ltd, CN=GlobalSign TSA for MS Authenticode , G2 |
| ValidFrom                         | 2015-02-03 00:00:00 |
| ValidTo                           | 2026-03-03 00:00:00 |
| Signature                         | 8032dc078d1ca09c9d3c2ae83d218b59a14d7ecc44ce03be7eaabcc4e67b73bb4bf188da904e7537283863b9d72b0f54a956ce7739973073cd9bd9d905451c8da4b8035d4fd91c2e98e0e988e6ecd7057e562a7bf7165ba3ad8f972512841bb25c634a0ad2ef10544782843569289c0ce41f141624fa75dc74726e4ecae36a43afcf7d3648d1bde906912c2fa6c871fdcfbdd89d2198fcafdbde228cafa7f377ef9ddca3704b441af078851ef2a58c39b5dc881c37edad14f5070b26bdbe6d025eb1b8b0586c853a0df6ff5a270cc5de53e7543c564cc94e4c30f6f25cfb1a8cc282bead5991f61b4d557bcf5b01dcfd7ad36f235c32479b01f3c15114468a9b |
| SignatureAlgorithmOID             | 1.2.840.113549.1.1.5 |
| IsCertificateAuthority            | False |
| SerialNumber                      | 112106a081d33fd87ae5824cc16b52094e03 |
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
#### Imported Functions
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
* HalSetBusDataByOffset
* HalTranslateBusAddress
* HalGetBusDataByOffset

{{< /details >}}
#### Exported Functions
{{< details "Expand" >}}

{{< /details >}}

#### Sections
{{< details "Expand" >}}
* .text
* .rdata
* .data
* .pdata
* INIT

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
        "SHA256": "3ca71e85908ff67368e4dc00253f5691b9e6d50c966e7784143d75fb92aa3448",
        "SHA384": "d9d366f9328f2b55ee19a32cc5fd5148b81d764282fe5dc196c872ae249caa51d2c212ef39f33945dfe0cda81925e326"
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
        "SHA256": "cbdc9a0ad785d0c2013211746b42234e18bdc7d54a7a260647badc1c9e712ed4",
        "SHA384": "dcec542f242317863d0b3d23947e17d6982e381003831777b07ed75b46fb18bd0392a89c9beb6862981cd05f3f2fb77b"
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
        "SHA256": "4783380498acf592286ef2dea0fcc5bdea3f54d5e374d3e3497df9d5f662cfb6",
        "SHA384": "4f428f115cf3d008248f15f32007fc7c54bd454e1b48b765776b4c87c23ab8818d8fbcbb3646d35eca012b025260a3b8"
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
        "SHA256": "5b81998ed98b343c04134c336e03f3051779eae0e9f882e8339593d18556375d",
        "SHA384": "db0076cad41a0ef4ea68754ef6905bd5ff772adcb745b05c0060344e43588abc95952dc3ad272f5a8f17b206e4089aca"
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
        "SHA256": "ef14ea05bb066ee9f4188196dd69cd769b283ac4d7555db52f5e76922d3456e1",
        "SHA384": "6e7450a139856aeda6fa6284ff89b3752a9b646e096b4d33dd7e8e727742a2111481531581c0aa2cda0338e22cfdbad3"
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
| Filename           |  |
| Creation Timestamp           | 2013-03-10 23:32:06 |
| MD5                | [0d992b69029d1f23a872ff5a3352fb5b](https://www.virustotal.com/gui/file/0d992b69029d1f23a872ff5a3352fb5b) |
| SHA1               | [b5dfa3396136236cc9a5c91f06514fa717508ef5](https://www.virustotal.com/gui/file/b5dfa3396136236cc9a5c91f06514fa717508ef5) |
| SHA256             | [0aca4447ee54d635f76b941f6100b829dc8b2e0df27bdf584acb90f15f12fbda](https://www.virustotal.com/gui/file/0aca4447ee54d635f76b941f6100b829dc8b2e0df27bdf584acb90f15f12fbda) |
| Authentihash MD5   | [936e49d3eec0a2f433e9d0115a38a2b6](https://www.virustotal.com/gui/search/authentihash%253A936e49d3eec0a2f433e9d0115a38a2b6) |
| Authentihash SHA1  | [5717bf3e520accfff5ad9943e53a3b118fb67f2e](https://www.virustotal.com/gui/search/authentihash%253A5717bf3e520accfff5ad9943e53a3b118fb67f2e) |
| Authentihash SHA256| [918d2e68a724b58d37443aea159e70bf8b1b5ebb089c395cad1d62745ecdaa19](https://www.virustotal.com/gui/search/authentihash%253A918d2e68a724b58d37443aea159e70bf8b1b5ebb089c395cad1d62745ecdaa19) |
| RichPEHeaderHash MD5   | [59080883b71fd56bbf10ec0ae4b6bdd4](https://www.virustotal.com/gui/search/rich_pe_header_hash%253A59080883b71fd56bbf10ec0ae4b6bdd4) |
| RichPEHeaderHash SHA1  | [503a36a225568553cc9b05f63b3506c6ff21e12e](https://www.virustotal.com/gui/search/rich_pe_header_hash%253A503a36a225568553cc9b05f63b3506c6ff21e12e) |
| RichPEHeaderHash SHA256| [bc812d4ddc3ecfbf38c4d0d185e368fc58bac6e07f722db032bf6303daa7c946](https://www.virustotal.com/gui/search/rich_pe_header_hash%253Abc812d4ddc3ecfbf38c4d0d185e368fc58bac6e07f722db032bf6303daa7c946) |

{{< button "https://github.com/magicsword-io/LOLDrivers/raw/main/drivers/0d992b69029d1f23a872ff5a3352fb5b.bin" "Download" >}} 

#### Certificates

{{< details "Expand" >}}
###### Certificate 0400000000012019c19066
| Field                             | Value                      |
|-----------------------------------|----------------------------|
| ToBeSigned (TBS) MD5              | 42023b9487cafe46c1b6a49c369a362e  |
| ToBeSigned (TBS) SHA1             | 7c7b524d269334b9f073c32e888e09544c6acd98 |
| ToBeSigned (TBS) SHA256           | b7126567833f3daa4085ff41e73112daad3d1e3808a942c1936520e2d6c46c78 |
| Subject                           | OU=Timestamping CA, O=GlobalSign, CN=GlobalSign Timestamping CA |
| ValidFrom                         | 2009-03-18 11:00:00 |
| ValidTo                           | 2028-01-28 12:00:00 |
| Signature                         | 5df6cb2b0d0140849f857a43706ae0c5e7aa0600d76713c9089131654f14a8a905dc389e6aa0300abd8dc78028ee4245ca94f3de5845a9803204f5595c6a70003927944df5b44634e81c5331b2b35416e9cc42abd5d959301cfb462725b88723b1e8758824831ec876377b01494548a4ede25dd27c9ca2dc2dba105a126265abae00c710343bcb72bd14240cdcc37627b4a7fee15829f20e169f91391d89a6e60f1c878ce258ac927e243eaaec14e73a33348bc63bac83ab0f14627aba1a2d4d4b1bc530f00b92797d3c78e0f8e6d215965999392b3061e8b8f8c0a1e9221411787dc4dc89bec0bb94e172aeebb540404fef171e585ed0a88996ac9228e9babf |
| SignatureAlgorithmOID             | 1.2.840.113549.1.1.5 |
| IsCertificateAuthority            | True |
| SerialNumber                      | 0400000000012019c19066 |
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
###### Certificate 01000000000125b0b4cc01
| Field                             | Value                      |
|-----------------------------------|----------------------------|
| ToBeSigned (TBS) MD5              | e3369c8e5aec0504b3a50455f615d9f9  |
| ToBeSigned (TBS) SHA1             | 13c244a894b40ecd18aaf97c362f20385bd005a7 |
| ToBeSigned (TBS) SHA256           | 26da721a670c72836926032fee6920118bfb9bff89cc8d0ce30d9452c33f2532 |
| Subject                           | C=BE, O=GlobalSign NV, CN=GlobalSign Time Stamping Authority |
| ValidFrom                         | 2009-12-21 09:32:56 |
| ValidTo                           | 2020-12-22 09:32:56 |
| Signature                         | bc89ecfee63655935c79d4117a86808f17b693b26d9b91a1561811c655eaf608edad9b9ef52b81c8bbdd607b1b47991e6d403e1d80c213d58e04052fdbe7ae529e688472a1e54a603cf89bd52f46d8c3b2b79353ac9b6c432424d1f1fce9562e3411581843eaefff34746ca0c06c7fad031969881e9560cabbbd0cbb76efc724b081c63831cf36ad0c38b89020849b2e8f28b99ff6ca9427cdac396157e0e3955a9c769230f5dea6973d721c2a6032a8334d8635338a5cf3a4fdf7062ce16b4b30f5cbd34362f841b9de7d20cb058c8e2cf65f35fd338d42896508362ca389f45a858bb0b97bdb6ccba1f8d20e1bbb977cd12779be9d7c3be6a75634d8c991a9 |
| SignatureAlgorithmOID             | 1.2.840.113549.1.1.5 |
| IsCertificateAuthority            | False |
| SerialNumber                      | 01000000000125b0b4cc01 |
| Version                           | 3 |
###### Certificate 1121a559b50ef9848661f0faeb7421bbdd2c
| Field                             | Value                      |
|-----------------------------------|----------------------------|
| ToBeSigned (TBS) MD5              | 3a98a18e8636f2a01e49e2a6d116c360  |
| ToBeSigned (TBS) SHA1             | a2938150e46525adcec2e3a2348824bc1cf532b2 |
| ToBeSigned (TBS) SHA256           | 01a2e2d31d0a4f3005753cce5972b5da2a7c08b0750fb6947e0fd231e64ae7ec |
| Subject                           | C=TW, ST=Taiwan, L=New Taipei City, O=MICRO,STAR INTERNATIONAL CO., LTD., OU=MICRO,STAR INTERNATIONAL CO., LTD., CN=MICRO,STAR INTERNATIONAL CO., LTD. |
| ValidFrom                         | 2011-08-30 06:46:09 |
| ValidTo                           | 2014-08-30 06:46:09 |
| Signature                         | 87bf57ab7ffd7e005076b34b14ddd924045ec7e389871661794f1ece1bef10e050893b28236cb650af1415f8cd95e86c2052d93311d73e0bbe6fb1c22ddea438a93c8b18bd4b8c0f81ad07032efb46d406bbaa730dd3ac92cbf0d9cc711a397a0e0320b213a5161e6be83ec69967a712b463129ea56d5a8ecd3ff8901be09dfaa0a0f10e879b307863e1b1c3a3149ac73bc3f3160db7012229b57bced6d47b875878663642a8cddd03da1e7f236b8cf16713a5e0f4c892aaca77a8c7dab41d84567e2bbf09b336a2824e0e18d54d199e6e024d2630bb210cd24a9ef4b377be0429e2ecc9bf8478a8c6a78c686e26f29c95925baee85e4bbb97b6eecffe44a25e |
| SignatureAlgorithmOID             | 1.2.840.113549.1.1.5 |
| IsCertificateAuthority            | False |
| SerialNumber                      | 1121a559b50ef9848661f0faeb7421bbdd2c |
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
#### Imported Functions
{{< details "Expand" >}}
* RtlInitUnicodeString
* ZwClose
* ZwMapViewOfSection
* ObReferenceObjectByHandle
* ZwOpenSection
* MmMapIoSpace
* IoDeleteSymbolicLink
* IofCompleteRequest
* ZwUnmapViewOfSection
* MmUnmapIoSpace
* IoCreateSymbolicLink
* IoCreateDevice
* __C_specific_handler
* IoDeleteDevice
* HalTranslateBusAddress

{{< /details >}}
#### Exported Functions
{{< details "Expand" >}}

{{< /details >}}

#### Sections
{{< details "Expand" >}}
* .text
* .rdata
* .data
* .pdata
* INIT

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
        "SHA256": "3ca71e85908ff67368e4dc00253f5691b9e6d50c966e7784143d75fb92aa3448",
        "SHA384": "d9d366f9328f2b55ee19a32cc5fd5148b81d764282fe5dc196c872ae249caa51d2c212ef39f33945dfe0cda81925e326"
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
        "SHA256": "cbdc9a0ad785d0c2013211746b42234e18bdc7d54a7a260647badc1c9e712ed4",
        "SHA384": "dcec542f242317863d0b3d23947e17d6982e381003831777b07ed75b46fb18bd0392a89c9beb6862981cd05f3f2fb77b"
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
        "SHA256": "4783380498acf592286ef2dea0fcc5bdea3f54d5e374d3e3497df9d5f662cfb6",
        "SHA384": "4f428f115cf3d008248f15f32007fc7c54bd454e1b48b765776b4c87c23ab8818d8fbcbb3646d35eca012b025260a3b8"
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
        "SHA256": "5b81998ed98b343c04134c336e03f3051779eae0e9f882e8339593d18556375d",
        "SHA384": "db0076cad41a0ef4ea68754ef6905bd5ff772adcb745b05c0060344e43588abc95952dc3ad272f5a8f17b206e4089aca"
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
        "SHA256": "ef14ea05bb066ee9f4188196dd69cd769b283ac4d7555db52f5e76922d3456e1",
        "SHA384": "6e7450a139856aeda6fa6284ff89b3752a9b646e096b4d33dd7e8e727742a2111481531581c0aa2cda0338e22cfdbad3"
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
| Filename           |  |
| Creation Timestamp           | 2013-03-10 23:32:06 |
| MD5                | [b418293e25632c5f377bf034bb450e57](https://www.virustotal.com/gui/file/b418293e25632c5f377bf034bb450e57) |
| SHA1               | [22c905fcdd7964726b4be5e8b5a9781322687a45](https://www.virustotal.com/gui/file/22c905fcdd7964726b4be5e8b5a9781322687a45) |
| SHA256             | [63af3fdb1e85949c8adccb43f09ca4556ae258b363a99ae599e1e834d34c8670](https://www.virustotal.com/gui/file/63af3fdb1e85949c8adccb43f09ca4556ae258b363a99ae599e1e834d34c8670) |
| Authentihash MD5   | [936e49d3eec0a2f433e9d0115a38a2b6](https://www.virustotal.com/gui/search/authentihash%253A936e49d3eec0a2f433e9d0115a38a2b6) |
| Authentihash SHA1  | [5717bf3e520accfff5ad9943e53a3b118fb67f2e](https://www.virustotal.com/gui/search/authentihash%253A5717bf3e520accfff5ad9943e53a3b118fb67f2e) |
| Authentihash SHA256| [918d2e68a724b58d37443aea159e70bf8b1b5ebb089c395cad1d62745ecdaa19](https://www.virustotal.com/gui/search/authentihash%253A918d2e68a724b58d37443aea159e70bf8b1b5ebb089c395cad1d62745ecdaa19) |
| RichPEHeaderHash MD5   | [59080883b71fd56bbf10ec0ae4b6bdd4](https://www.virustotal.com/gui/search/rich_pe_header_hash%253A59080883b71fd56bbf10ec0ae4b6bdd4) |
| RichPEHeaderHash SHA1  | [503a36a225568553cc9b05f63b3506c6ff21e12e](https://www.virustotal.com/gui/search/rich_pe_header_hash%253A503a36a225568553cc9b05f63b3506c6ff21e12e) |
| RichPEHeaderHash SHA256| [bc812d4ddc3ecfbf38c4d0d185e368fc58bac6e07f722db032bf6303daa7c946](https://www.virustotal.com/gui/search/rich_pe_header_hash%253Abc812d4ddc3ecfbf38c4d0d185e368fc58bac6e07f722db032bf6303daa7c946) |

{{< button "https://github.com/magicsword-io/LOLDrivers/raw/main/drivers/b418293e25632c5f377bf034bb450e57.bin" "Download" >}} 

#### Certificates

{{< details "Expand" >}}
###### Certificate 0400000000012019c19066
| Field                             | Value                      |
|-----------------------------------|----------------------------|
| ToBeSigned (TBS) MD5              | 42023b9487cafe46c1b6a49c369a362e  |
| ToBeSigned (TBS) SHA1             | 7c7b524d269334b9f073c32e888e09544c6acd98 |
| ToBeSigned (TBS) SHA256           | b7126567833f3daa4085ff41e73112daad3d1e3808a942c1936520e2d6c46c78 |
| Subject                           | OU=Timestamping CA, O=GlobalSign, CN=GlobalSign Timestamping CA |
| ValidFrom                         | 2009-03-18 11:00:00 |
| ValidTo                           | 2028-01-28 12:00:00 |
| Signature                         | 5df6cb2b0d0140849f857a43706ae0c5e7aa0600d76713c9089131654f14a8a905dc389e6aa0300abd8dc78028ee4245ca94f3de5845a9803204f5595c6a70003927944df5b44634e81c5331b2b35416e9cc42abd5d959301cfb462725b88723b1e8758824831ec876377b01494548a4ede25dd27c9ca2dc2dba105a126265abae00c710343bcb72bd14240cdcc37627b4a7fee15829f20e169f91391d89a6e60f1c878ce258ac927e243eaaec14e73a33348bc63bac83ab0f14627aba1a2d4d4b1bc530f00b92797d3c78e0f8e6d215965999392b3061e8b8f8c0a1e9221411787dc4dc89bec0bb94e172aeebb540404fef171e585ed0a88996ac9228e9babf |
| SignatureAlgorithmOID             | 1.2.840.113549.1.1.5 |
| IsCertificateAuthority            | True |
| SerialNumber                      | 0400000000012019c19066 |
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
###### Certificate 01000000000125b0b4cc01
| Field                             | Value                      |
|-----------------------------------|----------------------------|
| ToBeSigned (TBS) MD5              | e3369c8e5aec0504b3a50455f615d9f9  |
| ToBeSigned (TBS) SHA1             | 13c244a894b40ecd18aaf97c362f20385bd005a7 |
| ToBeSigned (TBS) SHA256           | 26da721a670c72836926032fee6920118bfb9bff89cc8d0ce30d9452c33f2532 |
| Subject                           | C=BE, O=GlobalSign NV, CN=GlobalSign Time Stamping Authority |
| ValidFrom                         | 2009-12-21 09:32:56 |
| ValidTo                           | 2020-12-22 09:32:56 |
| Signature                         | bc89ecfee63655935c79d4117a86808f17b693b26d9b91a1561811c655eaf608edad9b9ef52b81c8bbdd607b1b47991e6d403e1d80c213d58e04052fdbe7ae529e688472a1e54a603cf89bd52f46d8c3b2b79353ac9b6c432424d1f1fce9562e3411581843eaefff34746ca0c06c7fad031969881e9560cabbbd0cbb76efc724b081c63831cf36ad0c38b89020849b2e8f28b99ff6ca9427cdac396157e0e3955a9c769230f5dea6973d721c2a6032a8334d8635338a5cf3a4fdf7062ce16b4b30f5cbd34362f841b9de7d20cb058c8e2cf65f35fd338d42896508362ca389f45a858bb0b97bdb6ccba1f8d20e1bbb977cd12779be9d7c3be6a75634d8c991a9 |
| SignatureAlgorithmOID             | 1.2.840.113549.1.1.5 |
| IsCertificateAuthority            | False |
| SerialNumber                      | 01000000000125b0b4cc01 |
| Version                           | 3 |
###### Certificate 1121a559b50ef9848661f0faeb7421bbdd2c
| Field                             | Value                      |
|-----------------------------------|----------------------------|
| ToBeSigned (TBS) MD5              | 3a98a18e8636f2a01e49e2a6d116c360  |
| ToBeSigned (TBS) SHA1             | a2938150e46525adcec2e3a2348824bc1cf532b2 |
| ToBeSigned (TBS) SHA256           | 01a2e2d31d0a4f3005753cce5972b5da2a7c08b0750fb6947e0fd231e64ae7ec |
| Subject                           | C=TW, ST=Taiwan, L=New Taipei City, O=MICRO,STAR INTERNATIONAL CO., LTD., OU=MICRO,STAR INTERNATIONAL CO., LTD., CN=MICRO,STAR INTERNATIONAL CO., LTD. |
| ValidFrom                         | 2011-08-30 06:46:09 |
| ValidTo                           | 2014-08-30 06:46:09 |
| Signature                         | 87bf57ab7ffd7e005076b34b14ddd924045ec7e389871661794f1ece1bef10e050893b28236cb650af1415f8cd95e86c2052d93311d73e0bbe6fb1c22ddea438a93c8b18bd4b8c0f81ad07032efb46d406bbaa730dd3ac92cbf0d9cc711a397a0e0320b213a5161e6be83ec69967a712b463129ea56d5a8ecd3ff8901be09dfaa0a0f10e879b307863e1b1c3a3149ac73bc3f3160db7012229b57bced6d47b875878663642a8cddd03da1e7f236b8cf16713a5e0f4c892aaca77a8c7dab41d84567e2bbf09b336a2824e0e18d54d199e6e024d2630bb210cd24a9ef4b377be0429e2ecc9bf8478a8c6a78c686e26f29c95925baee85e4bbb97b6eecffe44a25e |
| SignatureAlgorithmOID             | 1.2.840.113549.1.1.5 |
| IsCertificateAuthority            | False |
| SerialNumber                      | 1121a559b50ef9848661f0faeb7421bbdd2c |
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
#### Imported Functions
{{< details "Expand" >}}
* RtlInitUnicodeString
* ZwClose
* ZwMapViewOfSection
* ObReferenceObjectByHandle
* ZwOpenSection
* MmMapIoSpace
* IoDeleteSymbolicLink
* IofCompleteRequest
* ZwUnmapViewOfSection
* MmUnmapIoSpace
* IoCreateSymbolicLink
* IoCreateDevice
* __C_specific_handler
* IoDeleteDevice
* HalTranslateBusAddress

{{< /details >}}
#### Exported Functions
{{< details "Expand" >}}

{{< /details >}}

#### Sections
{{< details "Expand" >}}
* .text
* .rdata
* .data
* .pdata
* INIT

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
        "SHA256": "3ca71e85908ff67368e4dc00253f5691b9e6d50c966e7784143d75fb92aa3448",
        "SHA384": "d9d366f9328f2b55ee19a32cc5fd5148b81d764282fe5dc196c872ae249caa51d2c212ef39f33945dfe0cda81925e326"
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
        "SHA256": "cbdc9a0ad785d0c2013211746b42234e18bdc7d54a7a260647badc1c9e712ed4",
        "SHA384": "dcec542f242317863d0b3d23947e17d6982e381003831777b07ed75b46fb18bd0392a89c9beb6862981cd05f3f2fb77b"
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
        "SHA256": "4783380498acf592286ef2dea0fcc5bdea3f54d5e374d3e3497df9d5f662cfb6",
        "SHA384": "4f428f115cf3d008248f15f32007fc7c54bd454e1b48b765776b4c87c23ab8818d8fbcbb3646d35eca012b025260a3b8"
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
        "SHA256": "5b81998ed98b343c04134c336e03f3051779eae0e9f882e8339593d18556375d",
        "SHA384": "db0076cad41a0ef4ea68754ef6905bd5ff772adcb745b05c0060344e43588abc95952dc3ad272f5a8f17b206e4089aca"
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
        "SHA256": "ef14ea05bb066ee9f4188196dd69cd769b283ac4d7555db52f5e76922d3456e1",
        "SHA384": "6e7450a139856aeda6fa6284ff89b3752a9b646e096b4d33dd7e8e727742a2111481531581c0aa2cda0338e22cfdbad3"
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
| Filename           |  |
| Creation Timestamp           | 2005-05-25 00:39:12 |
| MD5                | [f4b2580cf0477493908b7ed81e4482f8](https://www.virustotal.com/gui/file/f4b2580cf0477493908b7ed81e4482f8) |
| SHA1               | [57cc324326ab6c4239f8c10d2d1ce8862b2ce4d5](https://www.virustotal.com/gui/file/57cc324326ab6c4239f8c10d2d1ce8862b2ce4d5) |
| SHA256             | [d7a61c671eab1dfaa62fe1088a85f6d52fb11f2f32a53822a49521ca2c16585e](https://www.virustotal.com/gui/file/d7a61c671eab1dfaa62fe1088a85f6d52fb11f2f32a53822a49521ca2c16585e) |
| Authentihash MD5   | [a17d227444e090ff69e24fcb6d43162b](https://www.virustotal.com/gui/search/authentihash%253Aa17d227444e090ff69e24fcb6d43162b) |
| Authentihash SHA1  | [43d3a3c1f7b14cfcc051cae2534dbbbb4c7fc120](https://www.virustotal.com/gui/search/authentihash%253A43d3a3c1f7b14cfcc051cae2534dbbbb4c7fc120) |
| Authentihash SHA256| [b8eb26b6f79020ae988e4fb752dc06e1b6779749bf4f8df2872fc2b92bab8020](https://www.virustotal.com/gui/search/authentihash%253Ab8eb26b6f79020ae988e4fb752dc06e1b6779749bf4f8df2872fc2b92bab8020) |
| RichPEHeaderHash MD5   | [deb9c1e252f598099d70d2b33a313da3](https://www.virustotal.com/gui/search/rich_pe_header_hash%253Adeb9c1e252f598099d70d2b33a313da3) |
| RichPEHeaderHash SHA1  | [f0c2801e0091ed6f5e10ea7045e911aa90030290](https://www.virustotal.com/gui/search/rich_pe_header_hash%253Af0c2801e0091ed6f5e10ea7045e911aa90030290) |
| RichPEHeaderHash SHA256| [914fb9761d50c3fa2ecf9fbd8af3735f9b8d6c4903e067c8af9546e79b6f22c7](https://www.virustotal.com/gui/search/rich_pe_header_hash%253A914fb9761d50c3fa2ecf9fbd8af3735f9b8d6c4903e067c8af9546e79b6f22c7) |

{{< button "https://github.com/magicsword-io/LOLDrivers/raw/main/drivers/f4b2580cf0477493908b7ed81e4482f8.bin" "Download" >}} 

#### Certificates

{{< details "Expand" >}}
###### Certificate 3825d7faf861af9ef490e726b5d65ad5
| Field                             | Value                      |
|-----------------------------------|----------------------------|
| ToBeSigned (TBS) MD5              | d6c7684e9aaa508cf268335f83afe040  |
| ToBeSigned (TBS) SHA1             | 18066d20ad92409c567cdfde745279ff71c75226 |
| ToBeSigned (TBS) SHA256           | a612fb22ce8be6dab75e47c98508f98496583e79c9c97b936a8caee9ea9f3fff |
| Subject                           | C=US, O=VeriSign, Inc., CN=VeriSign Time Stamping Services Signer , G2 |
| ValidFrom                         | 2007-06-15 00:00:00 |
| ValidTo                           | 2012-06-14 23:59:59 |
| Signature                         | 50c54bc82480dfe40d24c2de1ab1a102a1a6822d0c831581370a820e2cb05a1761b5d805fe88dbf19191b3561a40a6eb92be3839b07536743a984fe437ba9989ca95421db0b9c7a08d57e0fad5640442354e01d133a217c84daa27c7f2e1864c02384d8378c6fc53e0ebe00687dda4969e5e0c98e2a5bebf8285c360e1dfad28d8c7a54b64dac71b5bbdac3908d53822a1338b2f8a9aebbc07213f44410907b5651c24bc48d34480eba1cfc902b414cf54c716a3805cf9793e5d727d88179e2c43a2ca53ce7d3df62a3ab84f9400a56d0a835df95e53f418b3570f70c3fbf5ad95a00e17dec4168060c90f2b6e8604f1ebf47827d105c5ee345b5eb94932f233 |
| SignatureAlgorithmOID             | 1.2.840.113549.1.1.5 |
| IsCertificateAuthority            | False |
| SerialNumber                      | 3825d7faf861af9ef490e726b5d65ad5 |
| Version                           | 3 |
###### Certificate 47bf1995df8d524643f7db6d480d31a4
| Field                             | Value                      |
|-----------------------------------|----------------------------|
| ToBeSigned (TBS) MD5              | 518d2ea8a21e879c942d504824ac211c  |
| ToBeSigned (TBS) SHA1             | 21ce87d827077e61abddf2beba69fde5432ea031 |
| ToBeSigned (TBS) SHA256           | 1ec3b4f02e03930a470020e0e48d24b84678bb558f46182888d870541f5e25c7 |
| Subject                           | C=US, O=VeriSign, Inc., CN=VeriSign Time Stamping Services CA |
| ValidFrom                         | 2003-12-04 00:00:00 |
| ValidTo                           | 2013-12-03 23:59:59 |
| Signature                         | 4a6bf9ea58c2441c318979992b96bf82ac01d61c4ccdb08a586edf0829a35ec8ca9313e704520def47272f0038b0e4c9934e9ad4226215f73f37214f703180f18b3887b3e8e89700fecf55964e24d2a9274e7aaeb76141f32acee7c9d95eddbb2b853eb59db5d9e157ffbeb4c57ef5cf0c9ef097fe2bd33b521b1b3827f73f4a |
| SignatureAlgorithmOID             | 1.2.840.113549.1.1.5 |
| IsCertificateAuthority            | True |
| SerialNumber                      | 47bf1995df8d524643f7db6d480d31a4 |
| Version                           | 3 |
###### Certificate 04000000000108d9611cd6
| Field                             | Value                      |
|-----------------------------------|----------------------------|
| ToBeSigned (TBS) MD5              | 698f075151097d84c0b1f3e7bc3d6fca  |
| ToBeSigned (TBS) SHA1             | 041750993d7c9e063f02dfe74699598640911aab |
| ToBeSigned (TBS) SHA256           | a8622cca0913a20477be8313b8d16fcad5d83088b46b36ddac10b31e96abb5e8 |
| Subject                           | C=BE, O=GlobalSign nv,sa, OU=Primary Object Publishing CA, CN=GlobalSign Primary Object Publishing CA |
| ValidFrom                         | 1999-01-28 12:00:00 |
| ValidTo                           | 2014-01-27 11:00:00 |
| Signature                         | a0422eb876a7427186404d464d5b26b0b074f93f89a87b7cb7f1c697e08239999d43fe60823642b55b878df55df4bbffa91044a871d3c7f12241f29aa4a5ec63fae5eb654a19309d8bc7b6fddc3fe16cfdd5521407fc6d24ccb3cc81a2c052f327b96d9e063dd8a849023269c7054294d0bbe3bba908c393501bdb846dc0ba1e5298659c1376bdb3d567292f1f7baa2c51a0fd854f263c48a38127a6feee7f7899c245cf9d1f527ed7958bfde1d020c3af7e51a22f663bab2dcf2d8e8c4d7d18392128fbdcae6d6581d0e0d7184be7b5f774d784e6522aac3b68fd3b4ab80154849132bb95d28e6330a69ece2396feab2eb86a8b74dcde21a114c2fbbf53af10 |
| SignatureAlgorithmOID             | 1.2.840.113549.1.1.5 |
| IsCertificateAuthority            | True |
| SerialNumber                      | 04000000000108d9611cd6 |
| Version                           | 3 |
###### Certificate 0100000000011c08b7f67e
| Field                             | Value                      |
|-----------------------------------|----------------------------|
| ToBeSigned (TBS) MD5              | 4566c37f56f951a0ce5b4ae966c0ea9f  |
| ToBeSigned (TBS) SHA1             | a51cbf2834eb6f8535bc5e44913a9ec979379782 |
| ToBeSigned (TBS) SHA256           | 88a8e9a799af515b9223e4cdf24d0ef1e72f12124be02786f026a3c26317b417 |
| Subject                           | C=TW, O=Micro,Star Int&#39;l Co. Ltd., CN=Micro,Star Int&#39;l Co. Ltd. |
| ValidFrom                         | 2008-08-28 09:49:45 |
| ValidTo                           | 2011-08-28 09:49:45 |
| Signature                         | 572df373e9b036711b3cf5ee882e5d75d8d50f012407cf0c1b554ff8f41c7b6477fa0b2ad579f2c1fe7b8b9d7374b690527c219eb979686fb67d0b4cf2885d8d7d1261f05cb72fe4c9f294c52aa05f3e5d1ceb0d77085dbd6af07978032505da666f353283a8982af26985e69c1599479945b591124183574b8a4cc34caa62e31b523dac3fedbd04951b3661399ed34f5c5868d9bbe3295fc09890d9521e1cdcae2ff129f547d4c8ce8aa08616107c555fac60e5b63c14ddfeb6962af3608b75d9c77c69260d8af9775b83afaa15b8ecef6840cb4ee87d451f9042b49735ea40931c0664c8c2bf6a139db6ac5b90edcea63a6bf5b54978f027b1046170d476d0 |
| SignatureAlgorithmOID             | 1.2.840.113549.1.1.5 |
| IsCertificateAuthority            | False |
| SerialNumber                      | 0100000000011c08b7f67e |
| Version                           | 3 |
###### Certificate 04000000000117ab50b915
| Field                             | Value                      |
|-----------------------------------|----------------------------|
| ToBeSigned (TBS) MD5              | 5686b287d716c4d2428b092c4ef30f9c  |
| ToBeSigned (TBS) SHA1             | 306fb5fbeb3d531510bb4b663c4fd48adc121e14 |
| ToBeSigned (TBS) SHA256           | 60846fc990e271a707cd2d53d0bb21834a04f7652214aa0c12597ff6649d352d |
| Subject                           | C=BE, O=GlobalSign nv,sa, OU=ObjectSign CA, CN=GlobalSign ObjectSign CA |
| ValidFrom                         | 2004-01-22 09:00:00 |
| ValidTo                           | 2014-01-27 10:00:00 |
| Signature                         | 3c4a010267edf20a2e736e40252f1dccbc2db652141b27122cf1229e190a89b6ef352a29152b1a88c20f37168d2602d5e93080f608b9939ac0498f332c3035ff4ab9892aa75c38e761a778fe22851a07b4b9edcf21f25ddedff329c5d38d9e14c4285c88e590a300442912b23e759540244a6beee2d0ef862ddf6d741a4f1cc79424c443464f7b81015d23733cd9752e995361565e7ccd13e237d222e570f8a743f6154147fda24702c43651ca545da6cdcad61817533ff1d38e0f0aafda17941657a0991431c90e1611d2c04ca2a25978fbb6b933cff763c9d2c4c84953dd8a59525e7d3b385eed220360ac85cd58325dcdc31c07fa7ef67efbc8ac378be498 |
| SignatureAlgorithmOID             | 1.2.840.113549.1.1.5 |
| IsCertificateAuthority            | True |
| SerialNumber                      | 04000000000117ab50b915 |
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
#### Imported Functions
{{< details "Expand" >}}
* RtlInitUnicodeString
* ZwClose
* ZwMapViewOfSection
* ObReferenceObjectByHandle
* ZwOpenSection
* IoDeleteSymbolicLink
* IofCompleteRequest
* MmIsAddressValid
* ZwUnmapViewOfSection
* IoCreateSymbolicLink
* IoCreateDevice
* __C_specific_handler
* IoDeleteDevice
* HalTranslateBusAddress

{{< /details >}}
#### Exported Functions
{{< details "Expand" >}}

{{< /details >}}

#### Sections
{{< details "Expand" >}}
* .text
* .rdata
* .data
* .pdata
* INIT

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
        "SHA256": "3ca71e85908ff67368e4dc00253f5691b9e6d50c966e7784143d75fb92aa3448",
        "SHA384": "d9d366f9328f2b55ee19a32cc5fd5148b81d764282fe5dc196c872ae249caa51d2c212ef39f33945dfe0cda81925e326"
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
        "SHA256": "cbdc9a0ad785d0c2013211746b42234e18bdc7d54a7a260647badc1c9e712ed4",
        "SHA384": "dcec542f242317863d0b3d23947e17d6982e381003831777b07ed75b46fb18bd0392a89c9beb6862981cd05f3f2fb77b"
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
        "SHA256": "4783380498acf592286ef2dea0fcc5bdea3f54d5e374d3e3497df9d5f662cfb6",
        "SHA384": "4f428f115cf3d008248f15f32007fc7c54bd454e1b48b765776b4c87c23ab8818d8fbcbb3646d35eca012b025260a3b8"
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
        "SHA256": "5b81998ed98b343c04134c336e03f3051779eae0e9f882e8339593d18556375d",
        "SHA384": "db0076cad41a0ef4ea68754ef6905bd5ff772adcb745b05c0060344e43588abc95952dc3ad272f5a8f17b206e4089aca"
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
        "SHA256": "ef14ea05bb066ee9f4188196dd69cd769b283ac4d7555db52f5e76922d3456e1",
        "SHA384": "6e7450a139856aeda6fa6284ff89b3752a9b646e096b4d33dd7e8e727742a2111481531581c0aa2cda0338e22cfdbad3"
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
| Filename           |  |
| Creation Timestamp           | 2005-05-25 00:39:12 |
| MD5                | [bc5366760098dc14ec00ae36c359f42b](https://www.virustotal.com/gui/file/bc5366760098dc14ec00ae36c359f42b) |
| SHA1               | [ba3faca988ff56f4850dede2587d5a3eff7c6677](https://www.virustotal.com/gui/file/ba3faca988ff56f4850dede2587d5a3eff7c6677) |
| SHA256             | [a10b4ed33a13c08804da8b46fd1b7bd653a6f2bb65668e82086de1940c5bb5d1](https://www.virustotal.com/gui/file/a10b4ed33a13c08804da8b46fd1b7bd653a6f2bb65668e82086de1940c5bb5d1) |
| Authentihash MD5   | [a17d227444e090ff69e24fcb6d43162b](https://www.virustotal.com/gui/search/authentihash%253Aa17d227444e090ff69e24fcb6d43162b) |
| Authentihash SHA1  | [43d3a3c1f7b14cfcc051cae2534dbbbb4c7fc120](https://www.virustotal.com/gui/search/authentihash%253A43d3a3c1f7b14cfcc051cae2534dbbbb4c7fc120) |
| Authentihash SHA256| [b8eb26b6f79020ae988e4fb752dc06e1b6779749bf4f8df2872fc2b92bab8020](https://www.virustotal.com/gui/search/authentihash%253Ab8eb26b6f79020ae988e4fb752dc06e1b6779749bf4f8df2872fc2b92bab8020) |
| RichPEHeaderHash MD5   | [deb9c1e252f598099d70d2b33a313da3](https://www.virustotal.com/gui/search/rich_pe_header_hash%253Adeb9c1e252f598099d70d2b33a313da3) |
| RichPEHeaderHash SHA1  | [f0c2801e0091ed6f5e10ea7045e911aa90030290](https://www.virustotal.com/gui/search/rich_pe_header_hash%253Af0c2801e0091ed6f5e10ea7045e911aa90030290) |
| RichPEHeaderHash SHA256| [914fb9761d50c3fa2ecf9fbd8af3735f9b8d6c4903e067c8af9546e79b6f22c7](https://www.virustotal.com/gui/search/rich_pe_header_hash%253A914fb9761d50c3fa2ecf9fbd8af3735f9b8d6c4903e067c8af9546e79b6f22c7) |

{{< button "https://github.com/magicsword-io/LOLDrivers/raw/main/drivers/bc5366760098dc14ec00ae36c359f42b.bin" "Download" >}} 

#### Certificates

{{< details "Expand" >}}
###### Certificate 040000000000f97faa2e1e
| Field                             | Value                      |
|-----------------------------------|----------------------------|
| ToBeSigned (TBS) MD5              | 59466cb0c1788b2f251fce3495837102  |
| ToBeSigned (TBS) SHA1             | c5cfc5f6a131a3a77c3905c9893c99bb1b2baa0b |
| ToBeSigned (TBS) SHA256           | eedda02668f7636eeec69429a7164cc47ca3de0539122d37f5b8078df7ee56db |
| Subject                           | CN=GlobalSign RootSign Partners CA, OU=RootSign Partners CA, O=GlobalSign nv,sa, C=BE |
| ValidFrom                         | 2003-12-16 13:00:00 |
| ValidTo                           | 2014-01-27 11:00:00 |
| Signature                         | 5c2f2e674a26b3e7b53f353cdda003ed569af9443752163065c7d14ea20f8db7b6b6678ee74cec8d95bee6cea7227874acd7f87499b3f7ce8b1338d596cc8d76c52f38b23aae61be0b8799e321626423398d84f6858df777ffb03806f07ec1485fb5ee582606660522749283a7dbb5f992e3e8c3192c2e63efbb1fdff9f70747660d0789977ef8332c9ecbae143df11cdfa3f179afc8928f9471c4d144c554db1eb50b0aa942a3afd643391dee8f9398585bbe6e9c0bf563ec5e99c2f954fa010746da0db06424cf8ed1061d4f3ca26377455ba4bc5fb080bb31e00b54015c161d724ed52a6947d11b667e5f016ef135916be02efeb045d81627b5c58bc2da53 |
| SignatureAlgorithmOID             | 1.2.840.113549.1.1.5 |
| IsCertificateAuthority            | True |
| SerialNumber                      | 040000000000f97faa2e1e |
| Version                           | 3 |
###### Certificate 0400000000011092eb8295
| Field                             | Value                      |
|-----------------------------------|----------------------------|
| ToBeSigned (TBS) MD5              | 11d73a3638fc78e0bac6c459feadcc42  |
| ToBeSigned (TBS) SHA1             | 6636f7dcf81b370b919966f9063295ec84422f91 |
| ToBeSigned (TBS) SHA256           | 1eb5fc1d2e3254b1e3c4587a6efed87ee65306525e684b4cfa4b51893cfe86a3 |
| Subject                           | O=GlobalSign, CN=GlobalSign Time Stamping Authority, emailAddress=timestampinfo@globalsign.com |
| ValidFrom                         | 2007-02-05 09:00:00 |
| ValidTo                           | 2014-01-27 09:00:00 |
| Signature                         | 649b07caaccc411e37ef6f349cb5e8ca48f9daeafaf7172e5cad193b7311ec5adbfd7b213161c092515bb166b07c64d8fe10b471a8bc9e75379c5f6ff2da0437b8ecc003e256b7785995581d7a7c3e18d74c32bdf91ee723457fdee08d65825b45fd64c66fc3d7ea12411d0c395ef696f8c3cd9e1fff51886976988b8eb42788821ad63c7aabb04eb73ee8d434d2c1a439533cb2747b15373054a6ebb924cc2f084b4364f14aaf8d9ce8546cb2dbdc3bb1c722849f558e72a8b2a8f6f0ff03c996ebab8273dabe45561936fdba6cbc71f0d3c7c376d7e4bce2a1a67200cfbdb200ed92aa39ab09d16e3953862ad43b517398b754e9972d9977ee123e3642257f |
| SignatureAlgorithmOID             | 1.2.840.113549.1.1.5 |
| IsCertificateAuthority            | True |
| SerialNumber                      | 0400000000011092eb8295 |
| Version                           | 3 |
###### Certificate 4191a15a3978dfcf496566381d4c75c2
| Field                             | Value                      |
|-----------------------------------|----------------------------|
| ToBeSigned (TBS) MD5              | 41011f8d0e7c7a6408334ca387914c61  |
| ToBeSigned (TBS) SHA1             | c7fc1727f5b75a6421a1f95c73bbdb23580c48e5 |
| ToBeSigned (TBS) SHA256           | 88dd3952638ee82738c03168e6fd863fe4eab1059ee5e2926ad8cb587c255dc0 |
| Subject                           | C=US, O=VeriSign, Inc., OU=VeriSign Trust Network, OU=Terms of use at https://www.verisign.com/rpa (c)04, CN=VeriSign Class 3 Code Signing 2004 CA |
| ValidFrom                         | 2004-07-16 00:00:00 |
| ValidTo                           | 2014-07-15 23:59:59 |
| Signature                         | ae3a17b84a7b55fa6455ec40a4ed494190999c89bcaf2e1dca7823f91c190f7feb68bc32d98838dedc3fd389b43fb18296f1a45abaed2e26d3de7c016e000a00a4069211480940f91c1879672324e0bbd5e150ae1bf50edde02e81cd80a36c524f9175558aba22f2d2ea4175882f63557d1e545a9559cad93481c05f5ef67ab5 |
| SignatureAlgorithmOID             | 1.2.840.113549.1.1.5 |
| IsCertificateAuthority            | True |
| SerialNumber                      | 4191a15a3978dfcf496566381d4c75c2 |
| Version                           | 3 |
###### Certificate 546ea040bf5075ce0a5c01d4c6ded19d
| Field                             | Value                      |
|-----------------------------------|----------------------------|
| ToBeSigned (TBS) MD5              | 8f51b4e16b87e1cc89b9d0c997227546  |
| ToBeSigned (TBS) SHA1             | 8f3cdd2b86ae03653f0612911a2f01a9dca49a22 |
| ToBeSigned (TBS) SHA256           | c7f57b7287c808d2713aba9e368fe387b5825bfbda1bd1824f374beaa8e30be9 |
| Subject                           | C=US, ST=California, L=Brea, O=EVGA, OU=Digital ID Class 3 , Microsoft Software Validation v2, CN=EVGA |
| ValidFrom                         | 2008-04-16 00:00:00 |
| ValidTo                           | 2010-04-16 23:59:59 |
| Signature                         | 13a3b8caa6bd8d63308898b0c92b79574e5d122a3ecba9758ec450b7c8c848ee5bc486db6370a8dfeb4c96c2c25512f7a3e759cc57a4d92f1a44fba15ca0c1156d22c49251b4e6a01bb93e4a62522ee5af4286c759c01c66fa5ce4452a4f112d03560bfa9737a3d0f3008b3cc48f2042b4428643f1efb4b99a34d0545c9934f1a6f35819e469430b74ba475a2135660948131cf24c9b1fb84580a1fd63eb3218d282e4f7caf77f4adbecb51e4b8237937eda0b7fcc20fc2273bf38282ee69ae6730b21c5314bcdc3f2e3a1e6f6c3ccb2139800f69d3f2fadc235080214f1c9b11e6a8f2165a45e15cca3c3542c2bac7225208a84828456d2e93cfe8315b092a1 |
| SignatureAlgorithmOID             | 1.2.840.113549.1.1.5 |
| IsCertificateAuthority            | False |
| SerialNumber                      | 546ea040bf5075ce0a5c01d4c6ded19d |
| Version                           | 3 |
###### Certificate 610c120600000000001b
| Field                             | Value                      |
|-----------------------------------|----------------------------|
| ToBeSigned (TBS) MD5              | 53c41bc1164e09e0cd1617a5bf913efd  |
| ToBeSigned (TBS) SHA1             | 93c03aac8951d494ecd5696b1c08658541b18727 |
| ToBeSigned (TBS) SHA256           | 40bddadac24dc61ca4fb5cab2a2bc5d876bc36808311039a7a3e1a4066f7489b |
| Subject                           | C=US, O=VeriSign, Inc., OU=Class 3 Public Primary Certification Authority |
| ValidFrom                         | 2006-05-23 17:01:29 |
| ValidTo                           | 2016-05-23 17:11:29 |
| Signature                         | 01e446b33b457f7513877e5f43de468ecb8abdb64741bccccc7491d8ce395195a4a6b547c0efd2da7b8f5711f4328c7ccd3fee42da04214af7c843884a6f5cca14fc4bd19f4cbdd4556ecc02be0da6888f8609baa425bde8b0f0fa8b714e67b0cb82a8d78e55f737ebf03e88efe4e08afd1c6e2e61414875b4b02c1d28d8490fd715f02473253ccc880cde284c6554fe5eae8cea19ad2c51b29b3a47f53c80350117e24987d6544afb4bab07bcbf7d79cfbf35005cbb9ecffc82891b39a05197b6dec0b307ff449644c0342a195cabeef03bec294eb513c537857e75d5b4d60d066eb5d26c237167eaf1718eaf4e74aa0cf9ecbf4c58fa5e909b6d39cb86883f8b1ca81632d5fe6db9f1f8b3ead791f6364778c0272a15c768d6f4c5fc4f4ec8673f102d409ff11ec96148e7a703fc31730cf04688fe56da492995ef09daa3e5beef60ecd954a0599c28bd54ef66157f874c84dba60e95672e517b3439b641c28c846826dc240209e7818e0a972defeea7b998a60f818dc710b5e1ed982f486f53854964789bec5dac970b5526c3efba8dc8d1a52f5a7f936b611a339b18b8a26210de24ea76e12f43ebecdd7c12342489da2855aee5754e312b6763b6a8d7ab730a03cec5ea593fc7eb2a45aea8625b2f009939abb45f73c308ec80118f470e8f2a1343e191066255bbffba3da9a93d260faeca7d628b155589d694344dd665 |
| SignatureAlgorithmOID             | 1.2.840.113549.1.1.5 |
| IsCertificateAuthority            | True |
| SerialNumber                      | 610c120600000000001b |
| Version                           | 3 |

{{< /details >}}
#### Imports
{{< details "Expand" >}}
* ntoskrnl.exe
* HAL.dll

{{< /details >}}
#### Imported Functions
{{< details "Expand" >}}
* RtlInitUnicodeString
* ZwClose
* ZwMapViewOfSection
* ObReferenceObjectByHandle
* ZwOpenSection
* IoDeleteSymbolicLink
* IofCompleteRequest
* MmIsAddressValid
* ZwUnmapViewOfSection
* IoCreateSymbolicLink
* IoCreateDevice
* __C_specific_handler
* IoDeleteDevice
* HalTranslateBusAddress

{{< /details >}}
#### Exported Functions
{{< details "Expand" >}}

{{< /details >}}

#### Sections
{{< details "Expand" >}}
* .text
* .rdata
* .data
* .pdata
* INIT

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
        "SHA256": "3ca71e85908ff67368e4dc00253f5691b9e6d50c966e7784143d75fb92aa3448",
        "SHA384": "d9d366f9328f2b55ee19a32cc5fd5148b81d764282fe5dc196c872ae249caa51d2c212ef39f33945dfe0cda81925e326"
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
        "SHA256": "cbdc9a0ad785d0c2013211746b42234e18bdc7d54a7a260647badc1c9e712ed4",
        "SHA384": "dcec542f242317863d0b3d23947e17d6982e381003831777b07ed75b46fb18bd0392a89c9beb6862981cd05f3f2fb77b"
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
        "SHA256": "4783380498acf592286ef2dea0fcc5bdea3f54d5e374d3e3497df9d5f662cfb6",
        "SHA384": "4f428f115cf3d008248f15f32007fc7c54bd454e1b48b765776b4c87c23ab8818d8fbcbb3646d35eca012b025260a3b8"
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
        "SHA256": "5b81998ed98b343c04134c336e03f3051779eae0e9f882e8339593d18556375d",
        "SHA384": "db0076cad41a0ef4ea68754ef6905bd5ff772adcb745b05c0060344e43588abc95952dc3ad272f5a8f17b206e4089aca"
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
        "SHA256": "ef14ea05bb066ee9f4188196dd69cd769b283ac4d7555db52f5e76922d3456e1",
        "SHA384": "6e7450a139856aeda6fa6284ff89b3752a9b646e096b4d33dd7e8e727742a2111481531581c0aa2cda0338e22cfdbad3"
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
| Filename           |  |
| Creation Timestamp           | 2005-05-25 00:39:12 |
| MD5                | [7c40ec9ed020cc9404de8fe3a5361a09](https://www.virustotal.com/gui/file/7c40ec9ed020cc9404de8fe3a5361a09) |
| SHA1               | [3d3b42d7b0af68da01019274e341b03d7c54f752](https://www.virustotal.com/gui/file/3d3b42d7b0af68da01019274e341b03d7c54f752) |
| SHA256             | [e6a2b1937fa277526a1e0ca9f9b32f85ab9cb7cb1a32250dd9c607e93fc2924f](https://www.virustotal.com/gui/file/e6a2b1937fa277526a1e0ca9f9b32f85ab9cb7cb1a32250dd9c607e93fc2924f) |
| Authentihash MD5   | [a17d227444e090ff69e24fcb6d43162b](https://www.virustotal.com/gui/search/authentihash%253Aa17d227444e090ff69e24fcb6d43162b) |
| Authentihash SHA1  | [43d3a3c1f7b14cfcc051cae2534dbbbb4c7fc120](https://www.virustotal.com/gui/search/authentihash%253A43d3a3c1f7b14cfcc051cae2534dbbbb4c7fc120) |
| Authentihash SHA256| [b8eb26b6f79020ae988e4fb752dc06e1b6779749bf4f8df2872fc2b92bab8020](https://www.virustotal.com/gui/search/authentihash%253Ab8eb26b6f79020ae988e4fb752dc06e1b6779749bf4f8df2872fc2b92bab8020) |
| RichPEHeaderHash MD5   | [deb9c1e252f598099d70d2b33a313da3](https://www.virustotal.com/gui/search/rich_pe_header_hash%253Adeb9c1e252f598099d70d2b33a313da3) |
| RichPEHeaderHash SHA1  | [f0c2801e0091ed6f5e10ea7045e911aa90030290](https://www.virustotal.com/gui/search/rich_pe_header_hash%253Af0c2801e0091ed6f5e10ea7045e911aa90030290) |
| RichPEHeaderHash SHA256| [914fb9761d50c3fa2ecf9fbd8af3735f9b8d6c4903e067c8af9546e79b6f22c7](https://www.virustotal.com/gui/search/rich_pe_header_hash%253A914fb9761d50c3fa2ecf9fbd8af3735f9b8d6c4903e067c8af9546e79b6f22c7) |

{{< button "https://github.com/magicsword-io/LOLDrivers/raw/main/drivers/7c40ec9ed020cc9404de8fe3a5361a09.bin" "Download" >}} 

#### Certificates

{{< details "Expand" >}}
###### Certificate 040000000000f97faa2e1e
| Field                             | Value                      |
|-----------------------------------|----------------------------|
| ToBeSigned (TBS) MD5              | 59466cb0c1788b2f251fce3495837102  |
| ToBeSigned (TBS) SHA1             | c5cfc5f6a131a3a77c3905c9893c99bb1b2baa0b |
| ToBeSigned (TBS) SHA256           | eedda02668f7636eeec69429a7164cc47ca3de0539122d37f5b8078df7ee56db |
| Subject                           | CN=GlobalSign RootSign Partners CA, OU=RootSign Partners CA, O=GlobalSign nv,sa, C=BE |
| ValidFrom                         | 2003-12-16 13:00:00 |
| ValidTo                           | 2014-01-27 11:00:00 |
| Signature                         | 5c2f2e674a26b3e7b53f353cdda003ed569af9443752163065c7d14ea20f8db7b6b6678ee74cec8d95bee6cea7227874acd7f87499b3f7ce8b1338d596cc8d76c52f38b23aae61be0b8799e321626423398d84f6858df777ffb03806f07ec1485fb5ee582606660522749283a7dbb5f992e3e8c3192c2e63efbb1fdff9f70747660d0789977ef8332c9ecbae143df11cdfa3f179afc8928f9471c4d144c554db1eb50b0aa942a3afd643391dee8f9398585bbe6e9c0bf563ec5e99c2f954fa010746da0db06424cf8ed1061d4f3ca26377455ba4bc5fb080bb31e00b54015c161d724ed52a6947d11b667e5f016ef135916be02efeb045d81627b5c58bc2da53 |
| SignatureAlgorithmOID             | 1.2.840.113549.1.1.5 |
| IsCertificateAuthority            | True |
| SerialNumber                      | 040000000000f97faa2e1e |
| Version                           | 3 |
###### Certificate 0400000000011092eb8295
| Field                             | Value                      |
|-----------------------------------|----------------------------|
| ToBeSigned (TBS) MD5              | 11d73a3638fc78e0bac6c459feadcc42  |
| ToBeSigned (TBS) SHA1             | 6636f7dcf81b370b919966f9063295ec84422f91 |
| ToBeSigned (TBS) SHA256           | 1eb5fc1d2e3254b1e3c4587a6efed87ee65306525e684b4cfa4b51893cfe86a3 |
| Subject                           | O=GlobalSign, CN=GlobalSign Time Stamping Authority, emailAddress=timestampinfo@globalsign.com |
| ValidFrom                         | 2007-02-05 09:00:00 |
| ValidTo                           | 2014-01-27 09:00:00 |
| Signature                         | 649b07caaccc411e37ef6f349cb5e8ca48f9daeafaf7172e5cad193b7311ec5adbfd7b213161c092515bb166b07c64d8fe10b471a8bc9e75379c5f6ff2da0437b8ecc003e256b7785995581d7a7c3e18d74c32bdf91ee723457fdee08d65825b45fd64c66fc3d7ea12411d0c395ef696f8c3cd9e1fff51886976988b8eb42788821ad63c7aabb04eb73ee8d434d2c1a439533cb2747b15373054a6ebb924cc2f084b4364f14aaf8d9ce8546cb2dbdc3bb1c722849f558e72a8b2a8f6f0ff03c996ebab8273dabe45561936fdba6cbc71f0d3c7c376d7e4bce2a1a67200cfbdb200ed92aa39ab09d16e3953862ad43b517398b754e9972d9977ee123e3642257f |
| SignatureAlgorithmOID             | 1.2.840.113549.1.1.5 |
| IsCertificateAuthority            | True |
| SerialNumber                      | 0400000000011092eb8295 |
| Version                           | 3 |
###### Certificate 4191a15a3978dfcf496566381d4c75c2
| Field                             | Value                      |
|-----------------------------------|----------------------------|
| ToBeSigned (TBS) MD5              | 41011f8d0e7c7a6408334ca387914c61  |
| ToBeSigned (TBS) SHA1             | c7fc1727f5b75a6421a1f95c73bbdb23580c48e5 |
| ToBeSigned (TBS) SHA256           | 88dd3952638ee82738c03168e6fd863fe4eab1059ee5e2926ad8cb587c255dc0 |
| Subject                           | C=US, O=VeriSign, Inc., OU=VeriSign Trust Network, OU=Terms of use at https://www.verisign.com/rpa (c)04, CN=VeriSign Class 3 Code Signing 2004 CA |
| ValidFrom                         | 2004-07-16 00:00:00 |
| ValidTo                           | 2014-07-15 23:59:59 |
| Signature                         | ae3a17b84a7b55fa6455ec40a4ed494190999c89bcaf2e1dca7823f91c190f7feb68bc32d98838dedc3fd389b43fb18296f1a45abaed2e26d3de7c016e000a00a4069211480940f91c1879672324e0bbd5e150ae1bf50edde02e81cd80a36c524f9175558aba22f2d2ea4175882f63557d1e545a9559cad93481c05f5ef67ab5 |
| SignatureAlgorithmOID             | 1.2.840.113549.1.1.5 |
| IsCertificateAuthority            | True |
| SerialNumber                      | 4191a15a3978dfcf496566381d4c75c2 |
| Version                           | 3 |
###### Certificate 546ea040bf5075ce0a5c01d4c6ded19d
| Field                             | Value                      |
|-----------------------------------|----------------------------|
| ToBeSigned (TBS) MD5              | 8f51b4e16b87e1cc89b9d0c997227546  |
| ToBeSigned (TBS) SHA1             | 8f3cdd2b86ae03653f0612911a2f01a9dca49a22 |
| ToBeSigned (TBS) SHA256           | c7f57b7287c808d2713aba9e368fe387b5825bfbda1bd1824f374beaa8e30be9 |
| Subject                           | C=US, ST=California, L=Brea, O=EVGA, OU=Digital ID Class 3 , Microsoft Software Validation v2, CN=EVGA |
| ValidFrom                         | 2008-04-16 00:00:00 |
| ValidTo                           | 2010-04-16 23:59:59 |
| Signature                         | 13a3b8caa6bd8d63308898b0c92b79574e5d122a3ecba9758ec450b7c8c848ee5bc486db6370a8dfeb4c96c2c25512f7a3e759cc57a4d92f1a44fba15ca0c1156d22c49251b4e6a01bb93e4a62522ee5af4286c759c01c66fa5ce4452a4f112d03560bfa9737a3d0f3008b3cc48f2042b4428643f1efb4b99a34d0545c9934f1a6f35819e469430b74ba475a2135660948131cf24c9b1fb84580a1fd63eb3218d282e4f7caf77f4adbecb51e4b8237937eda0b7fcc20fc2273bf38282ee69ae6730b21c5314bcdc3f2e3a1e6f6c3ccb2139800f69d3f2fadc235080214f1c9b11e6a8f2165a45e15cca3c3542c2bac7225208a84828456d2e93cfe8315b092a1 |
| SignatureAlgorithmOID             | 1.2.840.113549.1.1.5 |
| IsCertificateAuthority            | False |
| SerialNumber                      | 546ea040bf5075ce0a5c01d4c6ded19d |
| Version                           | 3 |
###### Certificate 610c120600000000001b
| Field                             | Value                      |
|-----------------------------------|----------------------------|
| ToBeSigned (TBS) MD5              | 53c41bc1164e09e0cd1617a5bf913efd  |
| ToBeSigned (TBS) SHA1             | 93c03aac8951d494ecd5696b1c08658541b18727 |
| ToBeSigned (TBS) SHA256           | 40bddadac24dc61ca4fb5cab2a2bc5d876bc36808311039a7a3e1a4066f7489b |
| Subject                           | C=US, O=VeriSign, Inc., OU=Class 3 Public Primary Certification Authority |
| ValidFrom                         | 2006-05-23 17:01:29 |
| ValidTo                           | 2016-05-23 17:11:29 |
| Signature                         | 01e446b33b457f7513877e5f43de468ecb8abdb64741bccccc7491d8ce395195a4a6b547c0efd2da7b8f5711f4328c7ccd3fee42da04214af7c843884a6f5cca14fc4bd19f4cbdd4556ecc02be0da6888f8609baa425bde8b0f0fa8b714e67b0cb82a8d78e55f737ebf03e88efe4e08afd1c6e2e61414875b4b02c1d28d8490fd715f02473253ccc880cde284c6554fe5eae8cea19ad2c51b29b3a47f53c80350117e24987d6544afb4bab07bcbf7d79cfbf35005cbb9ecffc82891b39a05197b6dec0b307ff449644c0342a195cabeef03bec294eb513c537857e75d5b4d60d066eb5d26c237167eaf1718eaf4e74aa0cf9ecbf4c58fa5e909b6d39cb86883f8b1ca81632d5fe6db9f1f8b3ead791f6364778c0272a15c768d6f4c5fc4f4ec8673f102d409ff11ec96148e7a703fc31730cf04688fe56da492995ef09daa3e5beef60ecd954a0599c28bd54ef66157f874c84dba60e95672e517b3439b641c28c846826dc240209e7818e0a972defeea7b998a60f818dc710b5e1ed982f486f53854964789bec5dac970b5526c3efba8dc8d1a52f5a7f936b611a339b18b8a26210de24ea76e12f43ebecdd7c12342489da2855aee5754e312b6763b6a8d7ab730a03cec5ea593fc7eb2a45aea8625b2f009939abb45f73c308ec80118f470e8f2a1343e191066255bbffba3da9a93d260faeca7d628b155589d694344dd665 |
| SignatureAlgorithmOID             | 1.2.840.113549.1.1.5 |
| IsCertificateAuthority            | True |
| SerialNumber                      | 610c120600000000001b |
| Version                           | 3 |

{{< /details >}}
#### Imports
{{< details "Expand" >}}
* ntoskrnl.exe
* HAL.dll

{{< /details >}}
#### Imported Functions
{{< details "Expand" >}}
* RtlInitUnicodeString
* ZwClose
* ZwMapViewOfSection
* ObReferenceObjectByHandle
* ZwOpenSection
* IoDeleteSymbolicLink
* IofCompleteRequest
* MmIsAddressValid
* ZwUnmapViewOfSection
* IoCreateSymbolicLink
* IoCreateDevice
* __C_specific_handler
* IoDeleteDevice
* HalTranslateBusAddress

{{< /details >}}
#### Exported Functions
{{< details "Expand" >}}

{{< /details >}}

#### Sections
{{< details "Expand" >}}
* .text
* .rdata
* .data
* .pdata
* INIT

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
        "SHA256": "3ca71e85908ff67368e4dc00253f5691b9e6d50c966e7784143d75fb92aa3448",
        "SHA384": "d9d366f9328f2b55ee19a32cc5fd5148b81d764282fe5dc196c872ae249caa51d2c212ef39f33945dfe0cda81925e326"
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
        "SHA256": "cbdc9a0ad785d0c2013211746b42234e18bdc7d54a7a260647badc1c9e712ed4",
        "SHA384": "dcec542f242317863d0b3d23947e17d6982e381003831777b07ed75b46fb18bd0392a89c9beb6862981cd05f3f2fb77b"
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
        "SHA256": "4783380498acf592286ef2dea0fcc5bdea3f54d5e374d3e3497df9d5f662cfb6",
        "SHA384": "4f428f115cf3d008248f15f32007fc7c54bd454e1b48b765776b4c87c23ab8818d8fbcbb3646d35eca012b025260a3b8"
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
        "SHA256": "5b81998ed98b343c04134c336e03f3051779eae0e9f882e8339593d18556375d",
        "SHA384": "db0076cad41a0ef4ea68754ef6905bd5ff772adcb745b05c0060344e43588abc95952dc3ad272f5a8f17b206e4089aca"
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
        "SHA256": "ef14ea05bb066ee9f4188196dd69cd769b283ac4d7555db52f5e76922d3456e1",
        "SHA384": "6e7450a139856aeda6fa6284ff89b3752a9b646e096b4d33dd7e8e727742a2111481531581c0aa2cda0338e22cfdbad3"
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
| Filename           |  |
| Creation Timestamp           | 2005-05-25 00:39:12 |
| MD5                | [b971b79bdca77e8755e615909a1c7a9f](https://www.virustotal.com/gui/file/b971b79bdca77e8755e615909a1c7a9f) |
| SHA1               | [398e8209e5c5fdcb6c287c5f9561e91887caca7d](https://www.virustotal.com/gui/file/398e8209e5c5fdcb6c287c5f9561e91887caca7d) |
| SHA256             | [5da0ffe33987f8d5fb9c151f0eff29b99f42233b27efcad596add27bdc5c88ff](https://www.virustotal.com/gui/file/5da0ffe33987f8d5fb9c151f0eff29b99f42233b27efcad596add27bdc5c88ff) |
| Authentihash MD5   | [a17d227444e090ff69e24fcb6d43162b](https://www.virustotal.com/gui/search/authentihash%253Aa17d227444e090ff69e24fcb6d43162b) |
| Authentihash SHA1  | [43d3a3c1f7b14cfcc051cae2534dbbbb4c7fc120](https://www.virustotal.com/gui/search/authentihash%253A43d3a3c1f7b14cfcc051cae2534dbbbb4c7fc120) |
| Authentihash SHA256| [b8eb26b6f79020ae988e4fb752dc06e1b6779749bf4f8df2872fc2b92bab8020](https://www.virustotal.com/gui/search/authentihash%253Ab8eb26b6f79020ae988e4fb752dc06e1b6779749bf4f8df2872fc2b92bab8020) |
| RichPEHeaderHash MD5   | [deb9c1e252f598099d70d2b33a313da3](https://www.virustotal.com/gui/search/rich_pe_header_hash%253Adeb9c1e252f598099d70d2b33a313da3) |
| RichPEHeaderHash SHA1  | [f0c2801e0091ed6f5e10ea7045e911aa90030290](https://www.virustotal.com/gui/search/rich_pe_header_hash%253Af0c2801e0091ed6f5e10ea7045e911aa90030290) |
| RichPEHeaderHash SHA256| [914fb9761d50c3fa2ecf9fbd8af3735f9b8d6c4903e067c8af9546e79b6f22c7](https://www.virustotal.com/gui/search/rich_pe_header_hash%253A914fb9761d50c3fa2ecf9fbd8af3735f9b8d6c4903e067c8af9546e79b6f22c7) |

{{< button "https://github.com/magicsword-io/LOLDrivers/raw/main/drivers/b971b79bdca77e8755e615909a1c7a9f.bin" "Download" >}} 

#### Certificates

{{< details "Expand" >}}
###### Certificate 0400000000012019c19066
| Field                             | Value                      |
|-----------------------------------|----------------------------|
| ToBeSigned (TBS) MD5              | 42023b9487cafe46c1b6a49c369a362e  |
| ToBeSigned (TBS) SHA1             | 7c7b524d269334b9f073c32e888e09544c6acd98 |
| ToBeSigned (TBS) SHA256           | b7126567833f3daa4085ff41e73112daad3d1e3808a942c1936520e2d6c46c78 |
| Subject                           | OU=Timestamping CA, O=GlobalSign, CN=GlobalSign Timestamping CA |
| ValidFrom                         | 2009-03-18 11:00:00 |
| ValidTo                           | 2028-01-28 12:00:00 |
| Signature                         | 5df6cb2b0d0140849f857a43706ae0c5e7aa0600d76713c9089131654f14a8a905dc389e6aa0300abd8dc78028ee4245ca94f3de5845a9803204f5595c6a70003927944df5b44634e81c5331b2b35416e9cc42abd5d959301cfb462725b88723b1e8758824831ec876377b01494548a4ede25dd27c9ca2dc2dba105a126265abae00c710343bcb72bd14240cdcc37627b4a7fee15829f20e169f91391d89a6e60f1c878ce258ac927e243eaaec14e73a33348bc63bac83ab0f14627aba1a2d4d4b1bc530f00b92797d3c78e0f8e6d215965999392b3061e8b8f8c0a1e9221411787dc4dc89bec0bb94e172aeebb540404fef171e585ed0a88996ac9228e9babf |
| SignatureAlgorithmOID             | 1.2.840.113549.1.1.5 |
| IsCertificateAuthority            | True |
| SerialNumber                      | 0400000000012019c19066 |
| Version                           | 3 |
###### Certificate 01000000000125b0b4cc01
| Field                             | Value                      |
|-----------------------------------|----------------------------|
| ToBeSigned (TBS) MD5              | e3369c8e5aec0504b3a50455f615d9f9  |
| ToBeSigned (TBS) SHA1             | 13c244a894b40ecd18aaf97c362f20385bd005a7 |
| ToBeSigned (TBS) SHA256           | 26da721a670c72836926032fee6920118bfb9bff89cc8d0ce30d9452c33f2532 |
| Subject                           | C=BE, O=GlobalSign NV, CN=GlobalSign Time Stamping Authority |
| ValidFrom                         | 2009-12-21 09:32:56 |
| ValidTo                           | 2020-12-22 09:32:56 |
| Signature                         | bc89ecfee63655935c79d4117a86808f17b693b26d9b91a1561811c655eaf608edad9b9ef52b81c8bbdd607b1b47991e6d403e1d80c213d58e04052fdbe7ae529e688472a1e54a603cf89bd52f46d8c3b2b79353ac9b6c432424d1f1fce9562e3411581843eaefff34746ca0c06c7fad031969881e9560cabbbd0cbb76efc724b081c63831cf36ad0c38b89020849b2e8f28b99ff6ca9427cdac396157e0e3955a9c769230f5dea6973d721c2a6032a8334d8635338a5cf3a4fdf7062ce16b4b30f5cbd34362f841b9de7d20cb058c8e2cf65f35fd338d42896508362ca389f45a858bb0b97bdb6ccba1f8d20e1bbb977cd12779be9d7c3be6a75634d8c991a9 |
| SignatureAlgorithmOID             | 1.2.840.113549.1.1.5 |
| IsCertificateAuthority            | False |
| SerialNumber                      | 01000000000125b0b4cc01 |
| Version                           | 3 |
###### Certificate 79c32d7ddd2458cf2eabe5b1b5c5290f
| Field                             | Value                      |
|-----------------------------------|----------------------------|
| ToBeSigned (TBS) MD5              | 5ba772ec00357ae706016510775c7a00  |
| ToBeSigned (TBS) SHA1             | eeb31b244ea14abae1e947ecdca0d6ae4720031b |
| ToBeSigned (TBS) SHA256           | c8e707c2615c26ac78ed06b42dd20bc8ff82bc5e02ddafe2c9af85755097691b |
| Subject                           | C=US, ST=California, L=Brea, O=EVGA, OU=Digital ID Class 3 , Microsoft Software Validation v2, CN=EVGA |
| ValidFrom                         | 2010-04-14 00:00:00 |
| ValidTo                           | 2012-04-15 23:59:59 |
| Signature                         | ba96817224593697c9135d803c5fc87767f2a7ed8fa0aa18eab4030a3daed18c55fb7eda8835d0488d18136c0db39d8edf3224790842cdf8580b35324631de717e9279d28d605285615341aeea10a73005d59cbe3138bebfa5003cbcf2971249423d820d6d252a18bf4dd124a1ac0c2f66015cbb23690e1b0fb9d5ce3f047663f1fb6735e54f09cfb6162da298bdc956490586cfdadee74a5766c187223e19112d22f59c7f3f325449afebc42689ec4c9399bd0d97397c37230804a4e5bc17e904008aa9c5972e2332302e57648006d057c9ed8c6384fb42d138971c86079b155c202733b837b3eef122c866ce3e6d8a8d9f1685e618cc2466d623d212b73df6 |
| SignatureAlgorithmOID             | 1.2.840.113549.1.1.5 |
| IsCertificateAuthority            | False |
| SerialNumber                      | 79c32d7ddd2458cf2eabe5b1b5c5290f |
| Version                           | 3 |
###### Certificate 655226e1b22e18e1590f2985ac22e75c
| Field                             | Value                      |
|-----------------------------------|----------------------------|
| ToBeSigned (TBS) MD5              | 650704c342850095f3288eaf791147d4  |
| ToBeSigned (TBS) SHA1             | 4cdc38c800761463749c3cbd94a12f32e49877bf |
| ToBeSigned (TBS) SHA256           | 07b8f662558ec85b71b43a79c6e94698144f4ced2308af21e7ba1e5d461da214 |
| Subject                           | C=US, O=VeriSign, Inc., OU=VeriSign Trust Network, OU=Terms of use at https://www.verisign.com/rpa (c)09, CN=VeriSign Class 3 Code Signing 2009,2 CA |
| ValidFrom                         | 2009-05-21 00:00:00 |
| ValidTo                           | 2019-05-20 23:59:59 |
| Signature                         | 8b03c0dd94d841a26169b015a878c730c6903c7e42f724b6e4837317047f04109ca1e2fa812febc0ca44e772e050b6551020836e9692e49a516ab43731dca52deb8c00c71d4fe74d32ba85f84ebefa675565f06abe7aca64381a101078457631f3867a030f60c2b35d9df68b6676821b59e183e5bd49a53856e5de41770e580f |
| SignatureAlgorithmOID             | 1.2.840.113549.1.1.5 |
| IsCertificateAuthority            | True |
| SerialNumber                      | 655226e1b22e18e1590f2985ac22e75c |
| Version                           | 3 |
###### Certificate 610c120600000000001b
| Field                             | Value                      |
|-----------------------------------|----------------------------|
| ToBeSigned (TBS) MD5              | 53c41bc1164e09e0cd1617a5bf913efd  |
| ToBeSigned (TBS) SHA1             | 93c03aac8951d494ecd5696b1c08658541b18727 |
| ToBeSigned (TBS) SHA256           | 40bddadac24dc61ca4fb5cab2a2bc5d876bc36808311039a7a3e1a4066f7489b |
| Subject                           | C=US, O=VeriSign, Inc., OU=Class 3 Public Primary Certification Authority |
| ValidFrom                         | 2006-05-23 17:01:29 |
| ValidTo                           | 2016-05-23 17:11:29 |
| Signature                         | 01e446b33b457f7513877e5f43de468ecb8abdb64741bccccc7491d8ce395195a4a6b547c0efd2da7b8f5711f4328c7ccd3fee42da04214af7c843884a6f5cca14fc4bd19f4cbdd4556ecc02be0da6888f8609baa425bde8b0f0fa8b714e67b0cb82a8d78e55f737ebf03e88efe4e08afd1c6e2e61414875b4b02c1d28d8490fd715f02473253ccc880cde284c6554fe5eae8cea19ad2c51b29b3a47f53c80350117e24987d6544afb4bab07bcbf7d79cfbf35005cbb9ecffc82891b39a05197b6dec0b307ff449644c0342a195cabeef03bec294eb513c537857e75d5b4d60d066eb5d26c237167eaf1718eaf4e74aa0cf9ecbf4c58fa5e909b6d39cb86883f8b1ca81632d5fe6db9f1f8b3ead791f6364778c0272a15c768d6f4c5fc4f4ec8673f102d409ff11ec96148e7a703fc31730cf04688fe56da492995ef09daa3e5beef60ecd954a0599c28bd54ef66157f874c84dba60e95672e517b3439b641c28c846826dc240209e7818e0a972defeea7b998a60f818dc710b5e1ed982f486f53854964789bec5dac970b5526c3efba8dc8d1a52f5a7f936b611a339b18b8a26210de24ea76e12f43ebecdd7c12342489da2855aee5754e312b6763b6a8d7ab730a03cec5ea593fc7eb2a45aea8625b2f009939abb45f73c308ec80118f470e8f2a1343e191066255bbffba3da9a93d260faeca7d628b155589d694344dd665 |
| SignatureAlgorithmOID             | 1.2.840.113549.1.1.5 |
| IsCertificateAuthority            | True |
| SerialNumber                      | 610c120600000000001b |
| Version                           | 3 |

{{< /details >}}
#### Imports
{{< details "Expand" >}}
* ntoskrnl.exe
* HAL.dll

{{< /details >}}
#### Imported Functions
{{< details "Expand" >}}
* RtlInitUnicodeString
* ZwClose
* ZwMapViewOfSection
* ObReferenceObjectByHandle
* ZwOpenSection
* IoDeleteSymbolicLink
* IofCompleteRequest
* MmIsAddressValid
* ZwUnmapViewOfSection
* IoCreateSymbolicLink
* IoCreateDevice
* __C_specific_handler
* IoDeleteDevice
* HalTranslateBusAddress

{{< /details >}}
#### Exported Functions
{{< details "Expand" >}}

{{< /details >}}

#### Sections
{{< details "Expand" >}}
* .text
* .rdata
* .data
* .pdata
* INIT

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
        "SHA256": "3ca71e85908ff67368e4dc00253f5691b9e6d50c966e7784143d75fb92aa3448",
        "SHA384": "d9d366f9328f2b55ee19a32cc5fd5148b81d764282fe5dc196c872ae249caa51d2c212ef39f33945dfe0cda81925e326"
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
        "SHA256": "cbdc9a0ad785d0c2013211746b42234e18bdc7d54a7a260647badc1c9e712ed4",
        "SHA384": "dcec542f242317863d0b3d23947e17d6982e381003831777b07ed75b46fb18bd0392a89c9beb6862981cd05f3f2fb77b"
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
        "SHA256": "4783380498acf592286ef2dea0fcc5bdea3f54d5e374d3e3497df9d5f662cfb6",
        "SHA384": "4f428f115cf3d008248f15f32007fc7c54bd454e1b48b765776b4c87c23ab8818d8fbcbb3646d35eca012b025260a3b8"
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
        "SHA256": "5b81998ed98b343c04134c336e03f3051779eae0e9f882e8339593d18556375d",
        "SHA384": "db0076cad41a0ef4ea68754ef6905bd5ff772adcb745b05c0060344e43588abc95952dc3ad272f5a8f17b206e4089aca"
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
        "SHA256": "ef14ea05bb066ee9f4188196dd69cd769b283ac4d7555db52f5e76922d3456e1",
        "SHA384": "6e7450a139856aeda6fa6284ff89b3752a9b646e096b4d33dd7e8e727742a2111481531581c0aa2cda0338e22cfdbad3"
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
| Filename           |  |
| Creation Timestamp           | 2013-03-10 23:32:06 |
| MD5                | [96c850e53caca0469e1c4604e6c1aad1](https://www.virustotal.com/gui/file/96c850e53caca0469e1c4604e6c1aad1) |
| SHA1               | [dbf3abdc85d6a0801c4af4cd1b77c44d5f57b03e](https://www.virustotal.com/gui/file/dbf3abdc85d6a0801c4af4cd1b77c44d5f57b03e) |
| SHA256             | [4eb1b9f3fe3c79f20c9cdeba92f6d6eb9b9ed15b546851e1f5338c0b7d36364b](https://www.virustotal.com/gui/file/4eb1b9f3fe3c79f20c9cdeba92f6d6eb9b9ed15b546851e1f5338c0b7d36364b) |
| Authentihash MD5   | [936e49d3eec0a2f433e9d0115a38a2b6](https://www.virustotal.com/gui/search/authentihash%253A936e49d3eec0a2f433e9d0115a38a2b6) |
| Authentihash SHA1  | [5717bf3e520accfff5ad9943e53a3b118fb67f2e](https://www.virustotal.com/gui/search/authentihash%253A5717bf3e520accfff5ad9943e53a3b118fb67f2e) |
| Authentihash SHA256| [918d2e68a724b58d37443aea159e70bf8b1b5ebb089c395cad1d62745ecdaa19](https://www.virustotal.com/gui/search/authentihash%253A918d2e68a724b58d37443aea159e70bf8b1b5ebb089c395cad1d62745ecdaa19) |
| RichPEHeaderHash MD5   | [59080883b71fd56bbf10ec0ae4b6bdd4](https://www.virustotal.com/gui/search/rich_pe_header_hash%253A59080883b71fd56bbf10ec0ae4b6bdd4) |
| RichPEHeaderHash SHA1  | [503a36a225568553cc9b05f63b3506c6ff21e12e](https://www.virustotal.com/gui/search/rich_pe_header_hash%253A503a36a225568553cc9b05f63b3506c6ff21e12e) |
| RichPEHeaderHash SHA256| [bc812d4ddc3ecfbf38c4d0d185e368fc58bac6e07f722db032bf6303daa7c946](https://www.virustotal.com/gui/search/rich_pe_header_hash%253Abc812d4ddc3ecfbf38c4d0d185e368fc58bac6e07f722db032bf6303daa7c946) |

{{< button "https://github.com/magicsword-io/LOLDrivers/raw/main/drivers/96c850e53caca0469e1c4604e6c1aad1.bin" "Download" >}} 

#### Certificates

{{< details "Expand" >}}
###### Certificate 0400000000012019c19066
| Field                             | Value                      |
|-----------------------------------|----------------------------|
| ToBeSigned (TBS) MD5              | 42023b9487cafe46c1b6a49c369a362e  |
| ToBeSigned (TBS) SHA1             | 7c7b524d269334b9f073c32e888e09544c6acd98 |
| ToBeSigned (TBS) SHA256           | b7126567833f3daa4085ff41e73112daad3d1e3808a942c1936520e2d6c46c78 |
| Subject                           | OU=Timestamping CA, O=GlobalSign, CN=GlobalSign Timestamping CA |
| ValidFrom                         | 2009-03-18 11:00:00 |
| ValidTo                           | 2028-01-28 12:00:00 |
| Signature                         | 5df6cb2b0d0140849f857a43706ae0c5e7aa0600d76713c9089131654f14a8a905dc389e6aa0300abd8dc78028ee4245ca94f3de5845a9803204f5595c6a70003927944df5b44634e81c5331b2b35416e9cc42abd5d959301cfb462725b88723b1e8758824831ec876377b01494548a4ede25dd27c9ca2dc2dba105a126265abae00c710343bcb72bd14240cdcc37627b4a7fee15829f20e169f91391d89a6e60f1c878ce258ac927e243eaaec14e73a33348bc63bac83ab0f14627aba1a2d4d4b1bc530f00b92797d3c78e0f8e6d215965999392b3061e8b8f8c0a1e9221411787dc4dc89bec0bb94e172aeebb540404fef171e585ed0a88996ac9228e9babf |
| SignatureAlgorithmOID             | 1.2.840.113549.1.1.5 |
| IsCertificateAuthority            | True |
| SerialNumber                      | 0400000000012019c19066 |
| Version                           | 3 |
###### Certificate 01000000000125b0b4cc01
| Field                             | Value                      |
|-----------------------------------|----------------------------|
| ToBeSigned (TBS) MD5              | e3369c8e5aec0504b3a50455f615d9f9  |
| ToBeSigned (TBS) SHA1             | 13c244a894b40ecd18aaf97c362f20385bd005a7 |
| ToBeSigned (TBS) SHA256           | 26da721a670c72836926032fee6920118bfb9bff89cc8d0ce30d9452c33f2532 |
| Subject                           | C=BE, O=GlobalSign NV, CN=GlobalSign Time Stamping Authority |
| ValidFrom                         | 2009-12-21 09:32:56 |
| ValidTo                           | 2020-12-22 09:32:56 |
| Signature                         | bc89ecfee63655935c79d4117a86808f17b693b26d9b91a1561811c655eaf608edad9b9ef52b81c8bbdd607b1b47991e6d403e1d80c213d58e04052fdbe7ae529e688472a1e54a603cf89bd52f46d8c3b2b79353ac9b6c432424d1f1fce9562e3411581843eaefff34746ca0c06c7fad031969881e9560cabbbd0cbb76efc724b081c63831cf36ad0c38b89020849b2e8f28b99ff6ca9427cdac396157e0e3955a9c769230f5dea6973d721c2a6032a8334d8635338a5cf3a4fdf7062ce16b4b30f5cbd34362f841b9de7d20cb058c8e2cf65f35fd338d42896508362ca389f45a858bb0b97bdb6ccba1f8d20e1bbb977cd12779be9d7c3be6a75634d8c991a9 |
| SignatureAlgorithmOID             | 1.2.840.113549.1.1.5 |
| IsCertificateAuthority            | False |
| SerialNumber                      | 01000000000125b0b4cc01 |
| Version                           | 3 |
###### Certificate 250ce8e030612e9f2b89f7054d7cf8fd
| Field                             | Value                      |
|-----------------------------------|----------------------------|
| ToBeSigned (TBS) MD5              | 918d9eb6a6cd36c531eceb926170a7e1  |
| ToBeSigned (TBS) SHA1             | 0ae95700d65e6f59715aa47048993ca7858e676a |
| ToBeSigned (TBS) SHA256           | 47c46e6eaa3780eace3d0d891346cd373359d246b21a957219dbab4c8f37c166 |
| Subject                           | C=US, O=VeriSign, Inc., OU=VeriSign Trust Network, OU=(c) 2006 VeriSign, Inc. , For authorized use only, CN=VeriSign Class 3 Public Primary Certification Authority , G5 |
| ValidFrom                         | 2006-11-08 00:00:00 |
| ValidTo                           | 2021-11-07 23:59:59 |
| Signature                         | 1302ddf8e88600f25af8f8200c59886207cecef74ef9bb59a198e5e138dd4ebc6618d3adeb18f20dc96d3e4a9420c33cbabd6554c6af44b310ad2c6b3eabd707b6b88163c5f95e2ee52a67cecd330c2ad7895603231fb3bee83a0859b4ec4535f78a5bff66cf50afc66d578d1978b7b9a2d157ea1f9a4bafbac98e127ec6bdff |
| SignatureAlgorithmOID             | 1.2.840.113549.1.1.5 |
| IsCertificateAuthority            | True |
| SerialNumber                      | 250ce8e030612e9f2b89f7054d7cf8fd |
| Version                           | 3 |
###### Certificate 610c120600000000001b
| Field                             | Value                      |
|-----------------------------------|----------------------------|
| ToBeSigned (TBS) MD5              | 53c41bc1164e09e0cd1617a5bf913efd  |
| ToBeSigned (TBS) SHA1             | 93c03aac8951d494ecd5696b1c08658541b18727 |
| ToBeSigned (TBS) SHA256           | 40bddadac24dc61ca4fb5cab2a2bc5d876bc36808311039a7a3e1a4066f7489b |
| Subject                           | C=US, O=VeriSign, Inc., OU=Class 3 Public Primary Certification Authority |
| ValidFrom                         | 2006-05-23 17:01:29 |
| ValidTo                           | 2016-05-23 17:11:29 |
| Signature                         | 01e446b33b457f7513877e5f43de468ecb8abdb64741bccccc7491d8ce395195a4a6b547c0efd2da7b8f5711f4328c7ccd3fee42da04214af7c843884a6f5cca14fc4bd19f4cbdd4556ecc02be0da6888f8609baa425bde8b0f0fa8b714e67b0cb82a8d78e55f737ebf03e88efe4e08afd1c6e2e61414875b4b02c1d28d8490fd715f02473253ccc880cde284c6554fe5eae8cea19ad2c51b29b3a47f53c80350117e24987d6544afb4bab07bcbf7d79cfbf35005cbb9ecffc82891b39a05197b6dec0b307ff449644c0342a195cabeef03bec294eb513c537857e75d5b4d60d066eb5d26c237167eaf1718eaf4e74aa0cf9ecbf4c58fa5e909b6d39cb86883f8b1ca81632d5fe6db9f1f8b3ead791f6364778c0272a15c768d6f4c5fc4f4ec8673f102d409ff11ec96148e7a703fc31730cf04688fe56da492995ef09daa3e5beef60ecd954a0599c28bd54ef66157f874c84dba60e95672e517b3439b641c28c846826dc240209e7818e0a972defeea7b998a60f818dc710b5e1ed982f486f53854964789bec5dac970b5526c3efba8dc8d1a52f5a7f936b611a339b18b8a26210de24ea76e12f43ebecdd7c12342489da2855aee5754e312b6763b6a8d7ab730a03cec5ea593fc7eb2a45aea8625b2f009939abb45f73c308ec80118f470e8f2a1343e191066255bbffba3da9a93d260faeca7d628b155589d694344dd665 |
| SignatureAlgorithmOID             | 1.2.840.113549.1.1.5 |
| IsCertificateAuthority            | True |
| SerialNumber                      | 610c120600000000001b |
| Version                           | 3 |
###### Certificate 26d7f5563eb3e42a81f7c715fcd2799d
| Field                             | Value                      |
|-----------------------------------|----------------------------|
| ToBeSigned (TBS) MD5              | e994671d8d440b7739cdd9775bbca72f  |
| ToBeSigned (TBS) SHA1             | ea9446b39b968aa6953e1bf74a36435759b3d2e3 |
| ToBeSigned (TBS) SHA256           | 37a9886a67c19d644c74505801f947d3b2756a5540cbd89a0c8d500511cb838d |
| Subject                           | C=US, ST=California, L=Brea, O=EVGA, OU=Digital ID Class 3 , Microsoft Software Validation v2, CN=EVGA |
| ValidFrom                         | 2012-02-29 00:00:00 |
| ValidTo                           | 2014-04-15 23:59:59 |
| Signature                         | d77d9dbdeea6d42d15335f0b16117963e49d39b89af081160a467824968e611f0947648a83375d1380acca6cbe1117f488b428bcab943b20dad29e72dd48e7d01b080b12c444727bba415a098799abd5e5673dd7eda91787920c3cc53aac068e0a3d1faef713c14f7ec6f68f69a33340b70e81083db2ce1daf45592063235d05232a1d3d8052fc3f102b2b71e1c46275eff3d4a2dc5ee0d5d727d180da205055a3709a32ad6bd11317b1f109e7c5eca18c8293c937ba6f76278bc306c10f0f1bc865cedcf2c2331e7a7f5c0bcfab91786b8ff848d8ef9c59937ddb94f6369884162148f882e7d0c4343538ad23aeb6ab3db0f6d125a8e2fe3889e40ed66bc66a |
| SignatureAlgorithmOID             | 1.2.840.113549.1.1.5 |
| IsCertificateAuthority            | False |
| SerialNumber                      | 26d7f5563eb3e42a81f7c715fcd2799d |
| Version                           | 3 |
###### Certificate 5200e5aa2556fc1a86ed96c9d44b33c7
| Field                             | Value                      |
|-----------------------------------|----------------------------|
| ToBeSigned (TBS) MD5              | b30c31a572b0409383ed3fbe17e56e81  |
| ToBeSigned (TBS) SHA1             | 4843a82ed3b1f2bfbee9671960e1940c942f688d |
| ToBeSigned (TBS) SHA256           | 03cda47a6e654ed85d932714fc09ce4874600eda29ec6628cfbaeb155cab78c9 |
| Subject                           | C=US, O=VeriSign, Inc., OU=VeriSign Trust Network, OU=Terms of use at https://www.verisign.com/rpa (c)10, CN=VeriSign Class 3 Code Signing 2010 CA |
| ValidFrom                         | 2010-02-08 00:00:00 |
| ValidTo                           | 2020-02-07 23:59:59 |
| Signature                         | 5622e634a4c461cb48b901ad56a8640fd98c91c4bbcc0ce5ad7aa0227fdf47384a2d6cd17f711a7cec70a9b1f04fe40f0c53fa155efe749849248581261c911447b04c638cbba134d4c645e80d85267303d0a98c646ddc7192e645056015595139fc58146bfed4a4ed796b080c4172e737220609be23e93f449a1ee9619dccb1905cfc3dd28dac423d6536d4b43d40288f9b10cf2326cc4b20cb901f5d8c4c34ca3cd8e537d66fa520bd34eb26d9ae0de7c59af7a1b42191336f86e858bb257c740e58fe751b633fce317c9b8f1b969ec55376845b9cad91faaced93ba5dc82153c2825363af120d5087111b3d5452968a2c9c3d921a089a052ec793a54891d3 |
| SignatureAlgorithmOID             | 1.2.840.113549.1.1.5 |
| IsCertificateAuthority            | True |
| SerialNumber                      | 5200e5aa2556fc1a86ed96c9d44b33c7 |
| Version                           | 3 |

{{< /details >}}
#### Imports
{{< details "Expand" >}}
* ntoskrnl.exe
* HAL.dll

{{< /details >}}
#### Imported Functions
{{< details "Expand" >}}
* RtlInitUnicodeString
* ZwClose
* ZwMapViewOfSection
* ObReferenceObjectByHandle
* ZwOpenSection
* MmMapIoSpace
* IoDeleteSymbolicLink
* IofCompleteRequest
* ZwUnmapViewOfSection
* MmUnmapIoSpace
* IoCreateSymbolicLink
* IoCreateDevice
* __C_specific_handler
* IoDeleteDevice
* HalTranslateBusAddress

{{< /details >}}
#### Exported Functions
{{< details "Expand" >}}

{{< /details >}}

#### Sections
{{< details "Expand" >}}
* .text
* .rdata
* .data
* .pdata
* INIT

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
        "SHA256": "3ca71e85908ff67368e4dc00253f5691b9e6d50c966e7784143d75fb92aa3448",
        "SHA384": "d9d366f9328f2b55ee19a32cc5fd5148b81d764282fe5dc196c872ae249caa51d2c212ef39f33945dfe0cda81925e326"
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
        "SHA256": "cbdc9a0ad785d0c2013211746b42234e18bdc7d54a7a260647badc1c9e712ed4",
        "SHA384": "dcec542f242317863d0b3d23947e17d6982e381003831777b07ed75b46fb18bd0392a89c9beb6862981cd05f3f2fb77b"
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
        "SHA256": "4783380498acf592286ef2dea0fcc5bdea3f54d5e374d3e3497df9d5f662cfb6",
        "SHA384": "4f428f115cf3d008248f15f32007fc7c54bd454e1b48b765776b4c87c23ab8818d8fbcbb3646d35eca012b025260a3b8"
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
        "SHA256": "5b81998ed98b343c04134c336e03f3051779eae0e9f882e8339593d18556375d",
        "SHA384": "db0076cad41a0ef4ea68754ef6905bd5ff772adcb745b05c0060344e43588abc95952dc3ad272f5a8f17b206e4089aca"
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
        "SHA256": "ef14ea05bb066ee9f4188196dd69cd769b283ac4d7555db52f5e76922d3456e1",
        "SHA384": "6e7450a139856aeda6fa6284ff89b3752a9b646e096b4d33dd7e8e727742a2111481531581c0aa2cda0338e22cfdbad3"
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
| Filename           |  |
| Creation Timestamp           | 2005-05-25 00:39:12 |
| MD5                | [cb22776d06f1e81cc87faeb0245acde8](https://www.virustotal.com/gui/file/cb22776d06f1e81cc87faeb0245acde8) |
| SHA1               | [8347487b32b993da87275e3d44ff3683c8130d33](https://www.virustotal.com/gui/file/8347487b32b993da87275e3d44ff3683c8130d33) |
| SHA256             | [a6c05b10a5c090b743a61fa225b09e390e2dd2bd6cb4fd96b987f1e0d3f2124a](https://www.virustotal.com/gui/file/a6c05b10a5c090b743a61fa225b09e390e2dd2bd6cb4fd96b987f1e0d3f2124a) |
| Authentihash MD5   | [a17d227444e090ff69e24fcb6d43162b](https://www.virustotal.com/gui/search/authentihash%253Aa17d227444e090ff69e24fcb6d43162b) |
| Authentihash SHA1  | [43d3a3c1f7b14cfcc051cae2534dbbbb4c7fc120](https://www.virustotal.com/gui/search/authentihash%253A43d3a3c1f7b14cfcc051cae2534dbbbb4c7fc120) |
| Authentihash SHA256| [b8eb26b6f79020ae988e4fb752dc06e1b6779749bf4f8df2872fc2b92bab8020](https://www.virustotal.com/gui/search/authentihash%253Ab8eb26b6f79020ae988e4fb752dc06e1b6779749bf4f8df2872fc2b92bab8020) |
| RichPEHeaderHash MD5   | [deb9c1e252f598099d70d2b33a313da3](https://www.virustotal.com/gui/search/rich_pe_header_hash%253Adeb9c1e252f598099d70d2b33a313da3) |
| RichPEHeaderHash SHA1  | [f0c2801e0091ed6f5e10ea7045e911aa90030290](https://www.virustotal.com/gui/search/rich_pe_header_hash%253Af0c2801e0091ed6f5e10ea7045e911aa90030290) |
| RichPEHeaderHash SHA256| [914fb9761d50c3fa2ecf9fbd8af3735f9b8d6c4903e067c8af9546e79b6f22c7](https://www.virustotal.com/gui/search/rich_pe_header_hash%253A914fb9761d50c3fa2ecf9fbd8af3735f9b8d6c4903e067c8af9546e79b6f22c7) |

{{< button "https://github.com/magicsword-io/LOLDrivers/raw/main/drivers/cb22776d06f1e81cc87faeb0245acde8.bin" "Download" >}} 

#### Certificates

{{< details "Expand" >}}
###### Certificate 040000000000f97faa2e1e
| Field                             | Value                      |
|-----------------------------------|----------------------------|
| ToBeSigned (TBS) MD5              | 59466cb0c1788b2f251fce3495837102  |
| ToBeSigned (TBS) SHA1             | c5cfc5f6a131a3a77c3905c9893c99bb1b2baa0b |
| ToBeSigned (TBS) SHA256           | eedda02668f7636eeec69429a7164cc47ca3de0539122d37f5b8078df7ee56db |
| Subject                           | CN=GlobalSign RootSign Partners CA, OU=RootSign Partners CA, O=GlobalSign nv,sa, C=BE |
| ValidFrom                         | 2003-12-16 13:00:00 |
| ValidTo                           | 2014-01-27 11:00:00 |
| Signature                         | 5c2f2e674a26b3e7b53f353cdda003ed569af9443752163065c7d14ea20f8db7b6b6678ee74cec8d95bee6cea7227874acd7f87499b3f7ce8b1338d596cc8d76c52f38b23aae61be0b8799e321626423398d84f6858df777ffb03806f07ec1485fb5ee582606660522749283a7dbb5f992e3e8c3192c2e63efbb1fdff9f70747660d0789977ef8332c9ecbae143df11cdfa3f179afc8928f9471c4d144c554db1eb50b0aa942a3afd643391dee8f9398585bbe6e9c0bf563ec5e99c2f954fa010746da0db06424cf8ed1061d4f3ca26377455ba4bc5fb080bb31e00b54015c161d724ed52a6947d11b667e5f016ef135916be02efeb045d81627b5c58bc2da53 |
| SignatureAlgorithmOID             | 1.2.840.113549.1.1.5 |
| IsCertificateAuthority            | True |
| SerialNumber                      | 040000000000f97faa2e1e |
| Version                           | 3 |
###### Certificate 0400000000011092eb8295
| Field                             | Value                      |
|-----------------------------------|----------------------------|
| ToBeSigned (TBS) MD5              | 11d73a3638fc78e0bac6c459feadcc42  |
| ToBeSigned (TBS) SHA1             | 6636f7dcf81b370b919966f9063295ec84422f91 |
| ToBeSigned (TBS) SHA256           | 1eb5fc1d2e3254b1e3c4587a6efed87ee65306525e684b4cfa4b51893cfe86a3 |
| Subject                           | O=GlobalSign, CN=GlobalSign Time Stamping Authority, emailAddress=timestampinfo@globalsign.com |
| ValidFrom                         | 2007-02-05 09:00:00 |
| ValidTo                           | 2014-01-27 09:00:00 |
| Signature                         | 649b07caaccc411e37ef6f349cb5e8ca48f9daeafaf7172e5cad193b7311ec5adbfd7b213161c092515bb166b07c64d8fe10b471a8bc9e75379c5f6ff2da0437b8ecc003e256b7785995581d7a7c3e18d74c32bdf91ee723457fdee08d65825b45fd64c66fc3d7ea12411d0c395ef696f8c3cd9e1fff51886976988b8eb42788821ad63c7aabb04eb73ee8d434d2c1a439533cb2747b15373054a6ebb924cc2f084b4364f14aaf8d9ce8546cb2dbdc3bb1c722849f558e72a8b2a8f6f0ff03c996ebab8273dabe45561936fdba6cbc71f0d3c7c376d7e4bce2a1a67200cfbdb200ed92aa39ab09d16e3953862ad43b517398b754e9972d9977ee123e3642257f |
| SignatureAlgorithmOID             | 1.2.840.113549.1.1.5 |
| IsCertificateAuthority            | True |
| SerialNumber                      | 0400000000011092eb8295 |
| Version                           | 3 |
###### Certificate 4191a15a3978dfcf496566381d4c75c2
| Field                             | Value                      |
|-----------------------------------|----------------------------|
| ToBeSigned (TBS) MD5              | 41011f8d0e7c7a6408334ca387914c61  |
| ToBeSigned (TBS) SHA1             | c7fc1727f5b75a6421a1f95c73bbdb23580c48e5 |
| ToBeSigned (TBS) SHA256           | 88dd3952638ee82738c03168e6fd863fe4eab1059ee5e2926ad8cb587c255dc0 |
| Subject                           | C=US, O=VeriSign, Inc., OU=VeriSign Trust Network, OU=Terms of use at https://www.verisign.com/rpa (c)04, CN=VeriSign Class 3 Code Signing 2004 CA |
| ValidFrom                         | 2004-07-16 00:00:00 |
| ValidTo                           | 2014-07-15 23:59:59 |
| Signature                         | ae3a17b84a7b55fa6455ec40a4ed494190999c89bcaf2e1dca7823f91c190f7feb68bc32d98838dedc3fd389b43fb18296f1a45abaed2e26d3de7c016e000a00a4069211480940f91c1879672324e0bbd5e150ae1bf50edde02e81cd80a36c524f9175558aba22f2d2ea4175882f63557d1e545a9559cad93481c05f5ef67ab5 |
| SignatureAlgorithmOID             | 1.2.840.113549.1.1.5 |
| IsCertificateAuthority            | True |
| SerialNumber                      | 4191a15a3978dfcf496566381d4c75c2 |
| Version                           | 3 |
###### Certificate 546ea040bf5075ce0a5c01d4c6ded19d
| Field                             | Value                      |
|-----------------------------------|----------------------------|
| ToBeSigned (TBS) MD5              | 8f51b4e16b87e1cc89b9d0c997227546  |
| ToBeSigned (TBS) SHA1             | 8f3cdd2b86ae03653f0612911a2f01a9dca49a22 |
| ToBeSigned (TBS) SHA256           | c7f57b7287c808d2713aba9e368fe387b5825bfbda1bd1824f374beaa8e30be9 |
| Subject                           | C=US, ST=California, L=Brea, O=EVGA, OU=Digital ID Class 3 , Microsoft Software Validation v2, CN=EVGA |
| ValidFrom                         | 2008-04-16 00:00:00 |
| ValidTo                           | 2010-04-16 23:59:59 |
| Signature                         | 13a3b8caa6bd8d63308898b0c92b79574e5d122a3ecba9758ec450b7c8c848ee5bc486db6370a8dfeb4c96c2c25512f7a3e759cc57a4d92f1a44fba15ca0c1156d22c49251b4e6a01bb93e4a62522ee5af4286c759c01c66fa5ce4452a4f112d03560bfa9737a3d0f3008b3cc48f2042b4428643f1efb4b99a34d0545c9934f1a6f35819e469430b74ba475a2135660948131cf24c9b1fb84580a1fd63eb3218d282e4f7caf77f4adbecb51e4b8237937eda0b7fcc20fc2273bf38282ee69ae6730b21c5314bcdc3f2e3a1e6f6c3ccb2139800f69d3f2fadc235080214f1c9b11e6a8f2165a45e15cca3c3542c2bac7225208a84828456d2e93cfe8315b092a1 |
| SignatureAlgorithmOID             | 1.2.840.113549.1.1.5 |
| IsCertificateAuthority            | False |
| SerialNumber                      | 546ea040bf5075ce0a5c01d4c6ded19d |
| Version                           | 3 |
###### Certificate 610c120600000000001b
| Field                             | Value                      |
|-----------------------------------|----------------------------|
| ToBeSigned (TBS) MD5              | 53c41bc1164e09e0cd1617a5bf913efd  |
| ToBeSigned (TBS) SHA1             | 93c03aac8951d494ecd5696b1c08658541b18727 |
| ToBeSigned (TBS) SHA256           | 40bddadac24dc61ca4fb5cab2a2bc5d876bc36808311039a7a3e1a4066f7489b |
| Subject                           | C=US, O=VeriSign, Inc., OU=Class 3 Public Primary Certification Authority |
| ValidFrom                         | 2006-05-23 17:01:29 |
| ValidTo                           | 2016-05-23 17:11:29 |
| Signature                         | 01e446b33b457f7513877e5f43de468ecb8abdb64741bccccc7491d8ce395195a4a6b547c0efd2da7b8f5711f4328c7ccd3fee42da04214af7c843884a6f5cca14fc4bd19f4cbdd4556ecc02be0da6888f8609baa425bde8b0f0fa8b714e67b0cb82a8d78e55f737ebf03e88efe4e08afd1c6e2e61414875b4b02c1d28d8490fd715f02473253ccc880cde284c6554fe5eae8cea19ad2c51b29b3a47f53c80350117e24987d6544afb4bab07bcbf7d79cfbf35005cbb9ecffc82891b39a05197b6dec0b307ff449644c0342a195cabeef03bec294eb513c537857e75d5b4d60d066eb5d26c237167eaf1718eaf4e74aa0cf9ecbf4c58fa5e909b6d39cb86883f8b1ca81632d5fe6db9f1f8b3ead791f6364778c0272a15c768d6f4c5fc4f4ec8673f102d409ff11ec96148e7a703fc31730cf04688fe56da492995ef09daa3e5beef60ecd954a0599c28bd54ef66157f874c84dba60e95672e517b3439b641c28c846826dc240209e7818e0a972defeea7b998a60f818dc710b5e1ed982f486f53854964789bec5dac970b5526c3efba8dc8d1a52f5a7f936b611a339b18b8a26210de24ea76e12f43ebecdd7c12342489da2855aee5754e312b6763b6a8d7ab730a03cec5ea593fc7eb2a45aea8625b2f009939abb45f73c308ec80118f470e8f2a1343e191066255bbffba3da9a93d260faeca7d628b155589d694344dd665 |
| SignatureAlgorithmOID             | 1.2.840.113549.1.1.5 |
| IsCertificateAuthority            | True |
| SerialNumber                      | 610c120600000000001b |
| Version                           | 3 |

{{< /details >}}
#### Imports
{{< details "Expand" >}}
* ntoskrnl.exe
* HAL.dll

{{< /details >}}
#### Imported Functions
{{< details "Expand" >}}
* RtlInitUnicodeString
* ZwClose
* ZwMapViewOfSection
* ObReferenceObjectByHandle
* ZwOpenSection
* IoDeleteSymbolicLink
* IofCompleteRequest
* MmIsAddressValid
* ZwUnmapViewOfSection
* IoCreateSymbolicLink
* IoCreateDevice
* __C_specific_handler
* IoDeleteDevice
* HalTranslateBusAddress

{{< /details >}}
#### Exported Functions
{{< details "Expand" >}}

{{< /details >}}

#### Sections
{{< details "Expand" >}}
* .text
* .rdata
* .data
* .pdata
* INIT

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
        "SHA256": "3ca71e85908ff67368e4dc00253f5691b9e6d50c966e7784143d75fb92aa3448",
        "SHA384": "d9d366f9328f2b55ee19a32cc5fd5148b81d764282fe5dc196c872ae249caa51d2c212ef39f33945dfe0cda81925e326"
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
        "SHA256": "cbdc9a0ad785d0c2013211746b42234e18bdc7d54a7a260647badc1c9e712ed4",
        "SHA384": "dcec542f242317863d0b3d23947e17d6982e381003831777b07ed75b46fb18bd0392a89c9beb6862981cd05f3f2fb77b"
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
        "SHA256": "4783380498acf592286ef2dea0fcc5bdea3f54d5e374d3e3497df9d5f662cfb6",
        "SHA384": "4f428f115cf3d008248f15f32007fc7c54bd454e1b48b765776b4c87c23ab8818d8fbcbb3646d35eca012b025260a3b8"
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
        "SHA256": "5b81998ed98b343c04134c336e03f3051779eae0e9f882e8339593d18556375d",
        "SHA384": "db0076cad41a0ef4ea68754ef6905bd5ff772adcb745b05c0060344e43588abc95952dc3ad272f5a8f17b206e4089aca"
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
        "SHA256": "ef14ea05bb066ee9f4188196dd69cd769b283ac4d7555db52f5e76922d3456e1",
        "SHA384": "6e7450a139856aeda6fa6284ff89b3752a9b646e096b4d33dd7e8e727742a2111481531581c0aa2cda0338e22cfdbad3"
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
| Filename           |  |
| Creation Timestamp           | 2013-03-10 23:32:06 |
| MD5                | [1440c0da81c700bd61142bc569477d81](https://www.virustotal.com/gui/file/1440c0da81c700bd61142bc569477d81) |
| SHA1               | [4a2bb97d395634b67194856d79a1ee5209aa06a7](https://www.virustotal.com/gui/file/4a2bb97d395634b67194856d79a1ee5209aa06a7) |
| SHA256             | [7fc01f25c4c18a6c539cda38fdbf34b2ff02a15ffd1d93a7215e1f48f76fb3be](https://www.virustotal.com/gui/file/7fc01f25c4c18a6c539cda38fdbf34b2ff02a15ffd1d93a7215e1f48f76fb3be) |
| Authentihash MD5   | [936e49d3eec0a2f433e9d0115a38a2b6](https://www.virustotal.com/gui/search/authentihash%253A936e49d3eec0a2f433e9d0115a38a2b6) |
| Authentihash SHA1  | [5717bf3e520accfff5ad9943e53a3b118fb67f2e](https://www.virustotal.com/gui/search/authentihash%253A5717bf3e520accfff5ad9943e53a3b118fb67f2e) |
| Authentihash SHA256| [918d2e68a724b58d37443aea159e70bf8b1b5ebb089c395cad1d62745ecdaa19](https://www.virustotal.com/gui/search/authentihash%253A918d2e68a724b58d37443aea159e70bf8b1b5ebb089c395cad1d62745ecdaa19) |
| RichPEHeaderHash MD5   | [59080883b71fd56bbf10ec0ae4b6bdd4](https://www.virustotal.com/gui/search/rich_pe_header_hash%253A59080883b71fd56bbf10ec0ae4b6bdd4) |
| RichPEHeaderHash SHA1  | [503a36a225568553cc9b05f63b3506c6ff21e12e](https://www.virustotal.com/gui/search/rich_pe_header_hash%253A503a36a225568553cc9b05f63b3506c6ff21e12e) |
| RichPEHeaderHash SHA256| [bc812d4ddc3ecfbf38c4d0d185e368fc58bac6e07f722db032bf6303daa7c946](https://www.virustotal.com/gui/search/rich_pe_header_hash%253Abc812d4ddc3ecfbf38c4d0d185e368fc58bac6e07f722db032bf6303daa7c946) |

{{< button "https://github.com/magicsword-io/LOLDrivers/raw/main/drivers/1440c0da81c700bd61142bc569477d81.bin" "Download" >}} 

#### Certificates

{{< details "Expand" >}}
###### Certificate 0400000000012019c19066
| Field                             | Value                      |
|-----------------------------------|----------------------------|
| ToBeSigned (TBS) MD5              | 42023b9487cafe46c1b6a49c369a362e  |
| ToBeSigned (TBS) SHA1             | 7c7b524d269334b9f073c32e888e09544c6acd98 |
| ToBeSigned (TBS) SHA256           | b7126567833f3daa4085ff41e73112daad3d1e3808a942c1936520e2d6c46c78 |
| Subject                           | OU=Timestamping CA, O=GlobalSign, CN=GlobalSign Timestamping CA |
| ValidFrom                         | 2009-03-18 11:00:00 |
| ValidTo                           | 2028-01-28 12:00:00 |
| Signature                         | 5df6cb2b0d0140849f857a43706ae0c5e7aa0600d76713c9089131654f14a8a905dc389e6aa0300abd8dc78028ee4245ca94f3de5845a9803204f5595c6a70003927944df5b44634e81c5331b2b35416e9cc42abd5d959301cfb462725b88723b1e8758824831ec876377b01494548a4ede25dd27c9ca2dc2dba105a126265abae00c710343bcb72bd14240cdcc37627b4a7fee15829f20e169f91391d89a6e60f1c878ce258ac927e243eaaec14e73a33348bc63bac83ab0f14627aba1a2d4d4b1bc530f00b92797d3c78e0f8e6d215965999392b3061e8b8f8c0a1e9221411787dc4dc89bec0bb94e172aeebb540404fef171e585ed0a88996ac9228e9babf |
| SignatureAlgorithmOID             | 1.2.840.113549.1.1.5 |
| IsCertificateAuthority            | True |
| SerialNumber                      | 0400000000012019c19066 |
| Version                           | 3 |
###### Certificate 01000000000125b0b4cc01
| Field                             | Value                      |
|-----------------------------------|----------------------------|
| ToBeSigned (TBS) MD5              | e3369c8e5aec0504b3a50455f615d9f9  |
| ToBeSigned (TBS) SHA1             | 13c244a894b40ecd18aaf97c362f20385bd005a7 |
| ToBeSigned (TBS) SHA256           | 26da721a670c72836926032fee6920118bfb9bff89cc8d0ce30d9452c33f2532 |
| Subject                           | C=BE, O=GlobalSign NV, CN=GlobalSign Time Stamping Authority |
| ValidFrom                         | 2009-12-21 09:32:56 |
| ValidTo                           | 2020-12-22 09:32:56 |
| Signature                         | bc89ecfee63655935c79d4117a86808f17b693b26d9b91a1561811c655eaf608edad9b9ef52b81c8bbdd607b1b47991e6d403e1d80c213d58e04052fdbe7ae529e688472a1e54a603cf89bd52f46d8c3b2b79353ac9b6c432424d1f1fce9562e3411581843eaefff34746ca0c06c7fad031969881e9560cabbbd0cbb76efc724b081c63831cf36ad0c38b89020849b2e8f28b99ff6ca9427cdac396157e0e3955a9c769230f5dea6973d721c2a6032a8334d8635338a5cf3a4fdf7062ce16b4b30f5cbd34362f841b9de7d20cb058c8e2cf65f35fd338d42896508362ca389f45a858bb0b97bdb6ccba1f8d20e1bbb977cd12779be9d7c3be6a75634d8c991a9 |
| SignatureAlgorithmOID             | 1.2.840.113549.1.1.5 |
| IsCertificateAuthority            | False |
| SerialNumber                      | 01000000000125b0b4cc01 |
| Version                           | 3 |
###### Certificate 250ce8e030612e9f2b89f7054d7cf8fd
| Field                             | Value                      |
|-----------------------------------|----------------------------|
| ToBeSigned (TBS) MD5              | 918d9eb6a6cd36c531eceb926170a7e1  |
| ToBeSigned (TBS) SHA1             | 0ae95700d65e6f59715aa47048993ca7858e676a |
| ToBeSigned (TBS) SHA256           | 47c46e6eaa3780eace3d0d891346cd373359d246b21a957219dbab4c8f37c166 |
| Subject                           | C=US, O=VeriSign, Inc., OU=VeriSign Trust Network, OU=(c) 2006 VeriSign, Inc. , For authorized use only, CN=VeriSign Class 3 Public Primary Certification Authority , G5 |
| ValidFrom                         | 2006-11-08 00:00:00 |
| ValidTo                           | 2021-11-07 23:59:59 |
| Signature                         | 1302ddf8e88600f25af8f8200c59886207cecef74ef9bb59a198e5e138dd4ebc6618d3adeb18f20dc96d3e4a9420c33cbabd6554c6af44b310ad2c6b3eabd707b6b88163c5f95e2ee52a67cecd330c2ad7895603231fb3bee83a0859b4ec4535f78a5bff66cf50afc66d578d1978b7b9a2d157ea1f9a4bafbac98e127ec6bdff |
| SignatureAlgorithmOID             | 1.2.840.113549.1.1.5 |
| IsCertificateAuthority            | True |
| SerialNumber                      | 250ce8e030612e9f2b89f7054d7cf8fd |
| Version                           | 3 |
###### Certificate 610c120600000000001b
| Field                             | Value                      |
|-----------------------------------|----------------------------|
| ToBeSigned (TBS) MD5              | 53c41bc1164e09e0cd1617a5bf913efd  |
| ToBeSigned (TBS) SHA1             | 93c03aac8951d494ecd5696b1c08658541b18727 |
| ToBeSigned (TBS) SHA256           | 40bddadac24dc61ca4fb5cab2a2bc5d876bc36808311039a7a3e1a4066f7489b |
| Subject                           | C=US, O=VeriSign, Inc., OU=Class 3 Public Primary Certification Authority |
| ValidFrom                         | 2006-05-23 17:01:29 |
| ValidTo                           | 2016-05-23 17:11:29 |
| Signature                         | 01e446b33b457f7513877e5f43de468ecb8abdb64741bccccc7491d8ce395195a4a6b547c0efd2da7b8f5711f4328c7ccd3fee42da04214af7c843884a6f5cca14fc4bd19f4cbdd4556ecc02be0da6888f8609baa425bde8b0f0fa8b714e67b0cb82a8d78e55f737ebf03e88efe4e08afd1c6e2e61414875b4b02c1d28d8490fd715f02473253ccc880cde284c6554fe5eae8cea19ad2c51b29b3a47f53c80350117e24987d6544afb4bab07bcbf7d79cfbf35005cbb9ecffc82891b39a05197b6dec0b307ff449644c0342a195cabeef03bec294eb513c537857e75d5b4d60d066eb5d26c237167eaf1718eaf4e74aa0cf9ecbf4c58fa5e909b6d39cb86883f8b1ca81632d5fe6db9f1f8b3ead791f6364778c0272a15c768d6f4c5fc4f4ec8673f102d409ff11ec96148e7a703fc31730cf04688fe56da492995ef09daa3e5beef60ecd954a0599c28bd54ef66157f874c84dba60e95672e517b3439b641c28c846826dc240209e7818e0a972defeea7b998a60f818dc710b5e1ed982f486f53854964789bec5dac970b5526c3efba8dc8d1a52f5a7f936b611a339b18b8a26210de24ea76e12f43ebecdd7c12342489da2855aee5754e312b6763b6a8d7ab730a03cec5ea593fc7eb2a45aea8625b2f009939abb45f73c308ec80118f470e8f2a1343e191066255bbffba3da9a93d260faeca7d628b155589d694344dd665 |
| SignatureAlgorithmOID             | 1.2.840.113549.1.1.5 |
| IsCertificateAuthority            | True |
| SerialNumber                      | 610c120600000000001b |
| Version                           | 3 |
###### Certificate 26d7f5563eb3e42a81f7c715fcd2799d
| Field                             | Value                      |
|-----------------------------------|----------------------------|
| ToBeSigned (TBS) MD5              | e994671d8d440b7739cdd9775bbca72f  |
| ToBeSigned (TBS) SHA1             | ea9446b39b968aa6953e1bf74a36435759b3d2e3 |
| ToBeSigned (TBS) SHA256           | 37a9886a67c19d644c74505801f947d3b2756a5540cbd89a0c8d500511cb838d |
| Subject                           | C=US, ST=California, L=Brea, O=EVGA, OU=Digital ID Class 3 , Microsoft Software Validation v2, CN=EVGA |
| ValidFrom                         | 2012-02-29 00:00:00 |
| ValidTo                           | 2014-04-15 23:59:59 |
| Signature                         | d77d9dbdeea6d42d15335f0b16117963e49d39b89af081160a467824968e611f0947648a83375d1380acca6cbe1117f488b428bcab943b20dad29e72dd48e7d01b080b12c444727bba415a098799abd5e5673dd7eda91787920c3cc53aac068e0a3d1faef713c14f7ec6f68f69a33340b70e81083db2ce1daf45592063235d05232a1d3d8052fc3f102b2b71e1c46275eff3d4a2dc5ee0d5d727d180da205055a3709a32ad6bd11317b1f109e7c5eca18c8293c937ba6f76278bc306c10f0f1bc865cedcf2c2331e7a7f5c0bcfab91786b8ff848d8ef9c59937ddb94f6369884162148f882e7d0c4343538ad23aeb6ab3db0f6d125a8e2fe3889e40ed66bc66a |
| SignatureAlgorithmOID             | 1.2.840.113549.1.1.5 |
| IsCertificateAuthority            | False |
| SerialNumber                      | 26d7f5563eb3e42a81f7c715fcd2799d |
| Version                           | 3 |
###### Certificate 5200e5aa2556fc1a86ed96c9d44b33c7
| Field                             | Value                      |
|-----------------------------------|----------------------------|
| ToBeSigned (TBS) MD5              | b30c31a572b0409383ed3fbe17e56e81  |
| ToBeSigned (TBS) SHA1             | 4843a82ed3b1f2bfbee9671960e1940c942f688d |
| ToBeSigned (TBS) SHA256           | 03cda47a6e654ed85d932714fc09ce4874600eda29ec6628cfbaeb155cab78c9 |
| Subject                           | C=US, O=VeriSign, Inc., OU=VeriSign Trust Network, OU=Terms of use at https://www.verisign.com/rpa (c)10, CN=VeriSign Class 3 Code Signing 2010 CA |
| ValidFrom                         | 2010-02-08 00:00:00 |
| ValidTo                           | 2020-02-07 23:59:59 |
| Signature                         | 5622e634a4c461cb48b901ad56a8640fd98c91c4bbcc0ce5ad7aa0227fdf47384a2d6cd17f711a7cec70a9b1f04fe40f0c53fa155efe749849248581261c911447b04c638cbba134d4c645e80d85267303d0a98c646ddc7192e645056015595139fc58146bfed4a4ed796b080c4172e737220609be23e93f449a1ee9619dccb1905cfc3dd28dac423d6536d4b43d40288f9b10cf2326cc4b20cb901f5d8c4c34ca3cd8e537d66fa520bd34eb26d9ae0de7c59af7a1b42191336f86e858bb257c740e58fe751b633fce317c9b8f1b969ec55376845b9cad91faaced93ba5dc82153c2825363af120d5087111b3d5452968a2c9c3d921a089a052ec793a54891d3 |
| SignatureAlgorithmOID             | 1.2.840.113549.1.1.5 |
| IsCertificateAuthority            | True |
| SerialNumber                      | 5200e5aa2556fc1a86ed96c9d44b33c7 |
| Version                           | 3 |

{{< /details >}}
#### Imports
{{< details "Expand" >}}
* ntoskrnl.exe
* HAL.dll

{{< /details >}}
#### Imported Functions
{{< details "Expand" >}}
* RtlInitUnicodeString
* ZwClose
* ZwMapViewOfSection
* ObReferenceObjectByHandle
* ZwOpenSection
* MmMapIoSpace
* IoDeleteSymbolicLink
* IofCompleteRequest
* ZwUnmapViewOfSection
* MmUnmapIoSpace
* IoCreateSymbolicLink
* IoCreateDevice
* __C_specific_handler
* IoDeleteDevice
* HalTranslateBusAddress

{{< /details >}}
#### Exported Functions
{{< details "Expand" >}}

{{< /details >}}

#### Sections
{{< details "Expand" >}}
* .text
* .rdata
* .data
* .pdata
* INIT

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
        "SHA256": "3ca71e85908ff67368e4dc00253f5691b9e6d50c966e7784143d75fb92aa3448",
        "SHA384": "d9d366f9328f2b55ee19a32cc5fd5148b81d764282fe5dc196c872ae249caa51d2c212ef39f33945dfe0cda81925e326"
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
        "SHA256": "cbdc9a0ad785d0c2013211746b42234e18bdc7d54a7a260647badc1c9e712ed4",
        "SHA384": "dcec542f242317863d0b3d23947e17d6982e381003831777b07ed75b46fb18bd0392a89c9beb6862981cd05f3f2fb77b"
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
        "SHA256": "4783380498acf592286ef2dea0fcc5bdea3f54d5e374d3e3497df9d5f662cfb6",
        "SHA384": "4f428f115cf3d008248f15f32007fc7c54bd454e1b48b765776b4c87c23ab8818d8fbcbb3646d35eca012b025260a3b8"
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
        "SHA256": "5b81998ed98b343c04134c336e03f3051779eae0e9f882e8339593d18556375d",
        "SHA384": "db0076cad41a0ef4ea68754ef6905bd5ff772adcb745b05c0060344e43588abc95952dc3ad272f5a8f17b206e4089aca"
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
        "SHA256": "ef14ea05bb066ee9f4188196dd69cd769b283ac4d7555db52f5e76922d3456e1",
        "SHA384": "6e7450a139856aeda6fa6284ff89b3752a9b646e096b4d33dd7e8e727742a2111481531581c0aa2cda0338e22cfdbad3"
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
| Filename           |  |
| Creation Timestamp           | 2005-05-25 00:39:12 |
| MD5                | [70c2c29643ee1edd3bbcd2ef1ffc9a73](https://www.virustotal.com/gui/file/70c2c29643ee1edd3bbcd2ef1ffc9a73) |
| SHA1               | [62244c704b0f227444d3a515ea0dc1003418a028](https://www.virustotal.com/gui/file/62244c704b0f227444d3a515ea0dc1003418a028) |
| SHA256             | [67cd6166d791bdf74453e19c015b2cb1e85e41892c04580034b65f9f03fe2e79](https://www.virustotal.com/gui/file/67cd6166d791bdf74453e19c015b2cb1e85e41892c04580034b65f9f03fe2e79) |
| Authentihash MD5   | [a17d227444e090ff69e24fcb6d43162b](https://www.virustotal.com/gui/search/authentihash%253Aa17d227444e090ff69e24fcb6d43162b) |
| Authentihash SHA1  | [43d3a3c1f7b14cfcc051cae2534dbbbb4c7fc120](https://www.virustotal.com/gui/search/authentihash%253A43d3a3c1f7b14cfcc051cae2534dbbbb4c7fc120) |
| Authentihash SHA256| [b8eb26b6f79020ae988e4fb752dc06e1b6779749bf4f8df2872fc2b92bab8020](https://www.virustotal.com/gui/search/authentihash%253Ab8eb26b6f79020ae988e4fb752dc06e1b6779749bf4f8df2872fc2b92bab8020) |
| RichPEHeaderHash MD5   | [deb9c1e252f598099d70d2b33a313da3](https://www.virustotal.com/gui/search/rich_pe_header_hash%253Adeb9c1e252f598099d70d2b33a313da3) |
| RichPEHeaderHash SHA1  | [f0c2801e0091ed6f5e10ea7045e911aa90030290](https://www.virustotal.com/gui/search/rich_pe_header_hash%253Af0c2801e0091ed6f5e10ea7045e911aa90030290) |
| RichPEHeaderHash SHA256| [914fb9761d50c3fa2ecf9fbd8af3735f9b8d6c4903e067c8af9546e79b6f22c7](https://www.virustotal.com/gui/search/rich_pe_header_hash%253A914fb9761d50c3fa2ecf9fbd8af3735f9b8d6c4903e067c8af9546e79b6f22c7) |

{{< button "https://github.com/magicsword-io/LOLDrivers/raw/main/drivers/70c2c29643ee1edd3bbcd2ef1ffc9a73.bin" "Download" >}} 

#### Certificates

{{< details "Expand" >}}
###### Certificate 0400000000012019c19066
| Field                             | Value                      |
|-----------------------------------|----------------------------|
| ToBeSigned (TBS) MD5              | 42023b9487cafe46c1b6a49c369a362e  |
| ToBeSigned (TBS) SHA1             | 7c7b524d269334b9f073c32e888e09544c6acd98 |
| ToBeSigned (TBS) SHA256           | b7126567833f3daa4085ff41e73112daad3d1e3808a942c1936520e2d6c46c78 |
| Subject                           | OU=Timestamping CA, O=GlobalSign, CN=GlobalSign Timestamping CA |
| ValidFrom                         | 2009-03-18 11:00:00 |
| ValidTo                           | 2028-01-28 12:00:00 |
| Signature                         | 5df6cb2b0d0140849f857a43706ae0c5e7aa0600d76713c9089131654f14a8a905dc389e6aa0300abd8dc78028ee4245ca94f3de5845a9803204f5595c6a70003927944df5b44634e81c5331b2b35416e9cc42abd5d959301cfb462725b88723b1e8758824831ec876377b01494548a4ede25dd27c9ca2dc2dba105a126265abae00c710343bcb72bd14240cdcc37627b4a7fee15829f20e169f91391d89a6e60f1c878ce258ac927e243eaaec14e73a33348bc63bac83ab0f14627aba1a2d4d4b1bc530f00b92797d3c78e0f8e6d215965999392b3061e8b8f8c0a1e9221411787dc4dc89bec0bb94e172aeebb540404fef171e585ed0a88996ac9228e9babf |
| SignatureAlgorithmOID             | 1.2.840.113549.1.1.5 |
| IsCertificateAuthority            | True |
| SerialNumber                      | 0400000000012019c19066 |
| Version                           | 3 |
###### Certificate 01000000000125b0b4cc01
| Field                             | Value                      |
|-----------------------------------|----------------------------|
| ToBeSigned (TBS) MD5              | e3369c8e5aec0504b3a50455f615d9f9  |
| ToBeSigned (TBS) SHA1             | 13c244a894b40ecd18aaf97c362f20385bd005a7 |
| ToBeSigned (TBS) SHA256           | 26da721a670c72836926032fee6920118bfb9bff89cc8d0ce30d9452c33f2532 |
| Subject                           | C=BE, O=GlobalSign NV, CN=GlobalSign Time Stamping Authority |
| ValidFrom                         | 2009-12-21 09:32:56 |
| ValidTo                           | 2020-12-22 09:32:56 |
| Signature                         | bc89ecfee63655935c79d4117a86808f17b693b26d9b91a1561811c655eaf608edad9b9ef52b81c8bbdd607b1b47991e6d403e1d80c213d58e04052fdbe7ae529e688472a1e54a603cf89bd52f46d8c3b2b79353ac9b6c432424d1f1fce9562e3411581843eaefff34746ca0c06c7fad031969881e9560cabbbd0cbb76efc724b081c63831cf36ad0c38b89020849b2e8f28b99ff6ca9427cdac396157e0e3955a9c769230f5dea6973d721c2a6032a8334d8635338a5cf3a4fdf7062ce16b4b30f5cbd34362f841b9de7d20cb058c8e2cf65f35fd338d42896508362ca389f45a858bb0b97bdb6ccba1f8d20e1bbb977cd12779be9d7c3be6a75634d8c991a9 |
| SignatureAlgorithmOID             | 1.2.840.113549.1.1.5 |
| IsCertificateAuthority            | False |
| SerialNumber                      | 01000000000125b0b4cc01 |
| Version                           | 3 |
###### Certificate 79c32d7ddd2458cf2eabe5b1b5c5290f
| Field                             | Value                      |
|-----------------------------------|----------------------------|
| ToBeSigned (TBS) MD5              | 5ba772ec00357ae706016510775c7a00  |
| ToBeSigned (TBS) SHA1             | eeb31b244ea14abae1e947ecdca0d6ae4720031b |
| ToBeSigned (TBS) SHA256           | c8e707c2615c26ac78ed06b42dd20bc8ff82bc5e02ddafe2c9af85755097691b |
| Subject                           | C=US, ST=California, L=Brea, O=EVGA, OU=Digital ID Class 3 , Microsoft Software Validation v2, CN=EVGA |
| ValidFrom                         | 2010-04-14 00:00:00 |
| ValidTo                           | 2012-04-15 23:59:59 |
| Signature                         | ba96817224593697c9135d803c5fc87767f2a7ed8fa0aa18eab4030a3daed18c55fb7eda8835d0488d18136c0db39d8edf3224790842cdf8580b35324631de717e9279d28d605285615341aeea10a73005d59cbe3138bebfa5003cbcf2971249423d820d6d252a18bf4dd124a1ac0c2f66015cbb23690e1b0fb9d5ce3f047663f1fb6735e54f09cfb6162da298bdc956490586cfdadee74a5766c187223e19112d22f59c7f3f325449afebc42689ec4c9399bd0d97397c37230804a4e5bc17e904008aa9c5972e2332302e57648006d057c9ed8c6384fb42d138971c86079b155c202733b837b3eef122c866ce3e6d8a8d9f1685e618cc2466d623d212b73df6 |
| SignatureAlgorithmOID             | 1.2.840.113549.1.1.5 |
| IsCertificateAuthority            | False |
| SerialNumber                      | 79c32d7ddd2458cf2eabe5b1b5c5290f |
| Version                           | 3 |
###### Certificate 655226e1b22e18e1590f2985ac22e75c
| Field                             | Value                      |
|-----------------------------------|----------------------------|
| ToBeSigned (TBS) MD5              | 650704c342850095f3288eaf791147d4  |
| ToBeSigned (TBS) SHA1             | 4cdc38c800761463749c3cbd94a12f32e49877bf |
| ToBeSigned (TBS) SHA256           | 07b8f662558ec85b71b43a79c6e94698144f4ced2308af21e7ba1e5d461da214 |
| Subject                           | C=US, O=VeriSign, Inc., OU=VeriSign Trust Network, OU=Terms of use at https://www.verisign.com/rpa (c)09, CN=VeriSign Class 3 Code Signing 2009,2 CA |
| ValidFrom                         | 2009-05-21 00:00:00 |
| ValidTo                           | 2019-05-20 23:59:59 |
| Signature                         | 8b03c0dd94d841a26169b015a878c730c6903c7e42f724b6e4837317047f04109ca1e2fa812febc0ca44e772e050b6551020836e9692e49a516ab43731dca52deb8c00c71d4fe74d32ba85f84ebefa675565f06abe7aca64381a101078457631f3867a030f60c2b35d9df68b6676821b59e183e5bd49a53856e5de41770e580f |
| SignatureAlgorithmOID             | 1.2.840.113549.1.1.5 |
| IsCertificateAuthority            | True |
| SerialNumber                      | 655226e1b22e18e1590f2985ac22e75c |
| Version                           | 3 |
###### Certificate 610c120600000000001b
| Field                             | Value                      |
|-----------------------------------|----------------------------|
| ToBeSigned (TBS) MD5              | 53c41bc1164e09e0cd1617a5bf913efd  |
| ToBeSigned (TBS) SHA1             | 93c03aac8951d494ecd5696b1c08658541b18727 |
| ToBeSigned (TBS) SHA256           | 40bddadac24dc61ca4fb5cab2a2bc5d876bc36808311039a7a3e1a4066f7489b |
| Subject                           | C=US, O=VeriSign, Inc., OU=Class 3 Public Primary Certification Authority |
| ValidFrom                         | 2006-05-23 17:01:29 |
| ValidTo                           | 2016-05-23 17:11:29 |
| Signature                         | 01e446b33b457f7513877e5f43de468ecb8abdb64741bccccc7491d8ce395195a4a6b547c0efd2da7b8f5711f4328c7ccd3fee42da04214af7c843884a6f5cca14fc4bd19f4cbdd4556ecc02be0da6888f8609baa425bde8b0f0fa8b714e67b0cb82a8d78e55f737ebf03e88efe4e08afd1c6e2e61414875b4b02c1d28d8490fd715f02473253ccc880cde284c6554fe5eae8cea19ad2c51b29b3a47f53c80350117e24987d6544afb4bab07bcbf7d79cfbf35005cbb9ecffc82891b39a05197b6dec0b307ff449644c0342a195cabeef03bec294eb513c537857e75d5b4d60d066eb5d26c237167eaf1718eaf4e74aa0cf9ecbf4c58fa5e909b6d39cb86883f8b1ca81632d5fe6db9f1f8b3ead791f6364778c0272a15c768d6f4c5fc4f4ec8673f102d409ff11ec96148e7a703fc31730cf04688fe56da492995ef09daa3e5beef60ecd954a0599c28bd54ef66157f874c84dba60e95672e517b3439b641c28c846826dc240209e7818e0a972defeea7b998a60f818dc710b5e1ed982f486f53854964789bec5dac970b5526c3efba8dc8d1a52f5a7f936b611a339b18b8a26210de24ea76e12f43ebecdd7c12342489da2855aee5754e312b6763b6a8d7ab730a03cec5ea593fc7eb2a45aea8625b2f009939abb45f73c308ec80118f470e8f2a1343e191066255bbffba3da9a93d260faeca7d628b155589d694344dd665 |
| SignatureAlgorithmOID             | 1.2.840.113549.1.1.5 |
| IsCertificateAuthority            | True |
| SerialNumber                      | 610c120600000000001b |
| Version                           | 3 |

{{< /details >}}
#### Imports
{{< details "Expand" >}}
* ntoskrnl.exe
* HAL.dll

{{< /details >}}
#### Imported Functions
{{< details "Expand" >}}
* RtlInitUnicodeString
* ZwClose
* ZwMapViewOfSection
* ObReferenceObjectByHandle
* ZwOpenSection
* IoDeleteSymbolicLink
* IofCompleteRequest
* MmIsAddressValid
* ZwUnmapViewOfSection
* IoCreateSymbolicLink
* IoCreateDevice
* __C_specific_handler
* IoDeleteDevice
* HalTranslateBusAddress

{{< /details >}}
#### Exported Functions
{{< details "Expand" >}}

{{< /details >}}

#### Sections
{{< details "Expand" >}}
* .text
* .rdata
* .data
* .pdata
* INIT

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
        "SHA256": "3ca71e85908ff67368e4dc00253f5691b9e6d50c966e7784143d75fb92aa3448",
        "SHA384": "d9d366f9328f2b55ee19a32cc5fd5148b81d764282fe5dc196c872ae249caa51d2c212ef39f33945dfe0cda81925e326"
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
        "SHA256": "cbdc9a0ad785d0c2013211746b42234e18bdc7d54a7a260647badc1c9e712ed4",
        "SHA384": "dcec542f242317863d0b3d23947e17d6982e381003831777b07ed75b46fb18bd0392a89c9beb6862981cd05f3f2fb77b"
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
        "SHA256": "4783380498acf592286ef2dea0fcc5bdea3f54d5e374d3e3497df9d5f662cfb6",
        "SHA384": "4f428f115cf3d008248f15f32007fc7c54bd454e1b48b765776b4c87c23ab8818d8fbcbb3646d35eca012b025260a3b8"
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
        "SHA256": "5b81998ed98b343c04134c336e03f3051779eae0e9f882e8339593d18556375d",
        "SHA384": "db0076cad41a0ef4ea68754ef6905bd5ff772adcb745b05c0060344e43588abc95952dc3ad272f5a8f17b206e4089aca"
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
        "SHA256": "ef14ea05bb066ee9f4188196dd69cd769b283ac4d7555db52f5e76922d3456e1",
        "SHA384": "6e7450a139856aeda6fa6284ff89b3752a9b646e096b4d33dd7e8e727742a2111481531581c0aa2cda0338e22cfdbad3"
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
| Filename           |  |
| Creation Timestamp           | 2015-04-24 01:01:47 |
| MD5                | [ddb7da975d90b2a9c9c58e1af55f0285](https://www.virustotal.com/gui/file/ddb7da975d90b2a9c9c58e1af55f0285) |
| SHA1               | [977fd907b6a2509019d8ef4f6213039f2523f2b5](https://www.virustotal.com/gui/file/977fd907b6a2509019d8ef4f6213039f2523f2b5) |
| SHA256             | [d9a3dc47699949c8ec0c704346fb2ee86ff9010daa0dbac953cfa5f76b52fcd1](https://www.virustotal.com/gui/file/d9a3dc47699949c8ec0c704346fb2ee86ff9010daa0dbac953cfa5f76b52fcd1) |
| Authentihash MD5   | [cfe667280acf69d4b5d0e2dbc76510e4](https://www.virustotal.com/gui/search/authentihash%253Acfe667280acf69d4b5d0e2dbc76510e4) |
| Authentihash SHA1  | [b3249bacda6e43aa2c46c2af802c9ee0b7e2fd7b](https://www.virustotal.com/gui/search/authentihash%253Ab3249bacda6e43aa2c46c2af802c9ee0b7e2fd7b) |
| Authentihash SHA256| [3c9829a16eb85272b0e1a2917feffaab8ddb23e633b168b389669339a0cee0b5](https://www.virustotal.com/gui/search/authentihash%253A3c9829a16eb85272b0e1a2917feffaab8ddb23e633b168b389669339a0cee0b5) |
| RichPEHeaderHash MD5   | [ebe2ae976914018e88e9fc480e7b6269](https://www.virustotal.com/gui/search/rich_pe_header_hash%253Aebe2ae976914018e88e9fc480e7b6269) |
| RichPEHeaderHash SHA1  | [960715bfbccb53b6c4eccca3b232b25640e15b52](https://www.virustotal.com/gui/search/rich_pe_header_hash%253A960715bfbccb53b6c4eccca3b232b25640e15b52) |
| RichPEHeaderHash SHA256| [d755e9f3cb861f5227319238f1811265e332e36a922b9a25da38b122a791fdfa](https://www.virustotal.com/gui/search/rich_pe_header_hash%253Ad755e9f3cb861f5227319238f1811265e332e36a922b9a25da38b122a791fdfa) |

{{< button "https://github.com/magicsword-io/LOLDrivers/raw/main/drivers/ddb7da975d90b2a9c9c58e1af55f0285.bin" "Download" >}} 

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
###### Certificate 112106a081d33fd87ae5824cc16b52094e03
| Field                             | Value                      |
|-----------------------------------|----------------------------|
| ToBeSigned (TBS) MD5              | a0ac4d48fe852f7b3ed4e623d59a825f  |
| ToBeSigned (TBS) SHA1             | d4db9846bc4d7db142eeb364286f6de7c102420c |
| ToBeSigned (TBS) SHA256           | 78d2e41a13eb4e9171bae2d2adb192cf39210b5231f77cda936bcfbe8c003bdf |
| Subject                           | C=SG, O=GMO GlobalSign Pte Ltd, CN=GlobalSign TSA for MS Authenticode , G2 |
| ValidFrom                         | 2015-02-03 00:00:00 |
| ValidTo                           | 2026-03-03 00:00:00 |
| Signature                         | 8032dc078d1ca09c9d3c2ae83d218b59a14d7ecc44ce03be7eaabcc4e67b73bb4bf188da904e7537283863b9d72b0f54a956ce7739973073cd9bd9d905451c8da4b8035d4fd91c2e98e0e988e6ecd7057e562a7bf7165ba3ad8f972512841bb25c634a0ad2ef10544782843569289c0ce41f141624fa75dc74726e4ecae36a43afcf7d3648d1bde906912c2fa6c871fdcfbdd89d2198fcafdbde228cafa7f377ef9ddca3704b441af078851ef2a58c39b5dc881c37edad14f5070b26bdbe6d025eb1b8b0586c853a0df6ff5a270cc5de53e7543c564cc94e4c30f6f25cfb1a8cc282bead5991f61b4d557bcf5b01dcfd7ad36f235c32479b01f3c15114468a9b |
| SignatureAlgorithmOID             | 1.2.840.113549.1.1.5 |
| IsCertificateAuthority            | False |
| SerialNumber                      | 112106a081d33fd87ae5824cc16b52094e03 |
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
#### Imported Functions
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
* HalSetBusDataByOffset
* HalTranslateBusAddress
* HalGetBusDataByOffset

{{< /details >}}
#### Exported Functions
{{< details "Expand" >}}

{{< /details >}}

#### Sections
{{< details "Expand" >}}
* .text
* .rdata
* .data
* .pdata
* INIT

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
        "SHA256": "3ca71e85908ff67368e4dc00253f5691b9e6d50c966e7784143d75fb92aa3448",
        "SHA384": "d9d366f9328f2b55ee19a32cc5fd5148b81d764282fe5dc196c872ae249caa51d2c212ef39f33945dfe0cda81925e326"
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
        "SHA256": "cbdc9a0ad785d0c2013211746b42234e18bdc7d54a7a260647badc1c9e712ed4",
        "SHA384": "dcec542f242317863d0b3d23947e17d6982e381003831777b07ed75b46fb18bd0392a89c9beb6862981cd05f3f2fb77b"
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
        "SHA256": "4783380498acf592286ef2dea0fcc5bdea3f54d5e374d3e3497df9d5f662cfb6",
        "SHA384": "4f428f115cf3d008248f15f32007fc7c54bd454e1b48b765776b4c87c23ab8818d8fbcbb3646d35eca012b025260a3b8"
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
        "SHA256": "5b81998ed98b343c04134c336e03f3051779eae0e9f882e8339593d18556375d",
        "SHA384": "db0076cad41a0ef4ea68754ef6905bd5ff772adcb745b05c0060344e43588abc95952dc3ad272f5a8f17b206e4089aca"
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
        "SHA256": "ef14ea05bb066ee9f4188196dd69cd769b283ac4d7555db52f5e76922d3456e1",
        "SHA384": "6e7450a139856aeda6fa6284ff89b3752a9b646e096b4d33dd7e8e727742a2111481531581c0aa2cda0338e22cfdbad3"
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
| Filename           |  |
| Creation Timestamp           | 2016-09-30 06:03:17 |
| MD5                | [72acbdd8fac58b71b301980eab3ebfc8](https://www.virustotal.com/gui/file/72acbdd8fac58b71b301980eab3ebfc8) |
| SHA1               | [d57c732050d7160161e096a8b238cb05d89d1bb2](https://www.virustotal.com/gui/file/d57c732050d7160161e096a8b238cb05d89d1bb2) |
| SHA256             | [11208bbba148736309a8d2a4ab9ab6b8f22f2297547b100d8bdfd7d413fe98b2](https://www.virustotal.com/gui/file/11208bbba148736309a8d2a4ab9ab6b8f22f2297547b100d8bdfd7d413fe98b2) |
| Authentihash MD5   | [538e5e595c61d2ea8defb7b047784734](https://www.virustotal.com/gui/search/authentihash%253A538e5e595c61d2ea8defb7b047784734) |
| Authentihash SHA1  | [4a68c2d7a4c471e062a32c83a36eedb45a619683](https://www.virustotal.com/gui/search/authentihash%253A4a68c2d7a4c471e062a32c83a36eedb45a619683) |
| Authentihash SHA256| [478c36f8af7844a80e24c1822507beef6314519185717ec7ae224a0e04b2f330](https://www.virustotal.com/gui/search/authentihash%253A478c36f8af7844a80e24c1822507beef6314519185717ec7ae224a0e04b2f330) |
| RichPEHeaderHash MD5   | [ebe2ae976914018e88e9fc480e7b6269](https://www.virustotal.com/gui/search/rich_pe_header_hash%253Aebe2ae976914018e88e9fc480e7b6269) |
| RichPEHeaderHash SHA1  | [960715bfbccb53b6c4eccca3b232b25640e15b52](https://www.virustotal.com/gui/search/rich_pe_header_hash%253A960715bfbccb53b6c4eccca3b232b25640e15b52) |
| RichPEHeaderHash SHA256| [d755e9f3cb861f5227319238f1811265e332e36a922b9a25da38b122a791fdfa](https://www.virustotal.com/gui/search/rich_pe_header_hash%253Ad755e9f3cb861f5227319238f1811265e332e36a922b9a25da38b122a791fdfa) |

{{< button "https://github.com/magicsword-io/LOLDrivers/raw/main/drivers/72acbdd8fac58b71b301980eab3ebfc8.bin" "Download" >}} 

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
#### Imported Functions
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
#### Exported Functions
{{< details "Expand" >}}

{{< /details >}}

#### Sections
{{< details "Expand" >}}
* .text
* .rdata
* .data
* .pdata
* INIT

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
        "SHA256": "3ca71e85908ff67368e4dc00253f5691b9e6d50c966e7784143d75fb92aa3448",
        "SHA384": "d9d366f9328f2b55ee19a32cc5fd5148b81d764282fe5dc196c872ae249caa51d2c212ef39f33945dfe0cda81925e326"
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
        "SHA256": "cbdc9a0ad785d0c2013211746b42234e18bdc7d54a7a260647badc1c9e712ed4",
        "SHA384": "dcec542f242317863d0b3d23947e17d6982e381003831777b07ed75b46fb18bd0392a89c9beb6862981cd05f3f2fb77b"
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
        "SHA256": "4783380498acf592286ef2dea0fcc5bdea3f54d5e374d3e3497df9d5f662cfb6",
        "SHA384": "4f428f115cf3d008248f15f32007fc7c54bd454e1b48b765776b4c87c23ab8818d8fbcbb3646d35eca012b025260a3b8"
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
        "SHA256": "5b81998ed98b343c04134c336e03f3051779eae0e9f882e8339593d18556375d",
        "SHA384": "db0076cad41a0ef4ea68754ef6905bd5ff772adcb745b05c0060344e43588abc95952dc3ad272f5a8f17b206e4089aca"
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
        "SHA256": "ef14ea05bb066ee9f4188196dd69cd769b283ac4d7555db52f5e76922d3456e1",
        "SHA384": "6e7450a139856aeda6fa6284ff89b3752a9b646e096b4d33dd7e8e727742a2111481531581c0aa2cda0338e22cfdbad3"
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
| Filename           |  |
| Creation Timestamp           | 2013-03-10 23:32:06 |
| MD5                | [260eef181a9bf2849bfec54c1736613b](https://www.virustotal.com/gui/file/260eef181a9bf2849bfec54c1736613b) |
| SHA1               | [0f78974194b604122b1cd4e82768155f946f6d24](https://www.virustotal.com/gui/file/0f78974194b604122b1cd4e82768155f946f6d24) |
| SHA256             | [b749566057dee0439f54b0d38935e5939b5cb011c46d7022530f748ebc63efe5](https://www.virustotal.com/gui/file/b749566057dee0439f54b0d38935e5939b5cb011c46d7022530f748ebc63efe5) |
| Authentihash MD5   | [936e49d3eec0a2f433e9d0115a38a2b6](https://www.virustotal.com/gui/search/authentihash%253A936e49d3eec0a2f433e9d0115a38a2b6) |
| Authentihash SHA1  | [5717bf3e520accfff5ad9943e53a3b118fb67f2e](https://www.virustotal.com/gui/search/authentihash%253A5717bf3e520accfff5ad9943e53a3b118fb67f2e) |
| Authentihash SHA256| [918d2e68a724b58d37443aea159e70bf8b1b5ebb089c395cad1d62745ecdaa19](https://www.virustotal.com/gui/search/authentihash%253A918d2e68a724b58d37443aea159e70bf8b1b5ebb089c395cad1d62745ecdaa19) |
| RichPEHeaderHash MD5   | [59080883b71fd56bbf10ec0ae4b6bdd4](https://www.virustotal.com/gui/search/rich_pe_header_hash%253A59080883b71fd56bbf10ec0ae4b6bdd4) |
| RichPEHeaderHash SHA1  | [503a36a225568553cc9b05f63b3506c6ff21e12e](https://www.virustotal.com/gui/search/rich_pe_header_hash%253A503a36a225568553cc9b05f63b3506c6ff21e12e) |
| RichPEHeaderHash SHA256| [bc812d4ddc3ecfbf38c4d0d185e368fc58bac6e07f722db032bf6303daa7c946](https://www.virustotal.com/gui/search/rich_pe_header_hash%253Abc812d4ddc3ecfbf38c4d0d185e368fc58bac6e07f722db032bf6303daa7c946) |

{{< button "https://github.com/magicsword-io/LOLDrivers/raw/main/drivers/260eef181a9bf2849bfec54c1736613b.bin" "Download" >}} 

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
###### Certificate 1121405c1f0ed258882be54d8686ba11ea45
| Field                             | Value                      |
|-----------------------------------|----------------------------|
| ToBeSigned (TBS) MD5              | b95cbc184d388718612d5933f7b36770  |
| ToBeSigned (TBS) SHA1             | ff124c5d160710720108616ffee99bbe090ed363 |
| ToBeSigned (TBS) SHA256           | 13027620255363f07bbf85ae7d0dc06c07d8b0f4368b12f983ee3f4fce605733 |
| Subject                           | C=SG, O=GMO GlobalSign Pte Ltd, CN=GlobalSign TSA for MS Authenticode , G1 |
| ValidFrom                         | 2013-08-23 00:00:00 |
| ValidTo                           | 2024-09-23 00:00:00 |
| Signature                         | 0231142e5857644185e8af12753c881cc35eec2ce9a13cf5baaa531db9d12963dc436786d439dadec6c9ffbe4585f4a4d7c151ea18ee40585ee67bcca241291338c8ea21169cce90a62efba6cad994df401df902182bbef65d4f9fff9a48dbc50509ca80cea0f9dc4bc323e6038fb4b4af5b71296191181a6b7af2fd0dd1cd7d5e98ebba705ee5f4ea43de353dc514818adb3e105ebb72faa1a093ab031cc1653c91138b045d2bc4b9161bcc55c50ce8abe743c9b28328a5531347ab3964b91cea3430b176009521f1d43da8fda00032d76e983ca69c3b0b83becbb8bb2a268c59b8b9aeaf26ace234a2dc210d810b3813f745a3e3dbc4aca16d1bb7e5615cd7 |
| SignatureAlgorithmOID             | 1.2.840.113549.1.1.5 |
| IsCertificateAuthority            | False |
| SerialNumber                      | 1121405c1f0ed258882be54d8686ba11ea45 |
| Version                           | 3 |
###### Certificate 1121a559b50ef9848661f0faeb7421bbdd2c
| Field                             | Value                      |
|-----------------------------------|----------------------------|
| ToBeSigned (TBS) MD5              | 3a98a18e8636f2a01e49e2a6d116c360  |
| ToBeSigned (TBS) SHA1             | a2938150e46525adcec2e3a2348824bc1cf532b2 |
| ToBeSigned (TBS) SHA256           | 01a2e2d31d0a4f3005753cce5972b5da2a7c08b0750fb6947e0fd231e64ae7ec |
| Subject                           | C=TW, ST=Taiwan, L=New Taipei City, O=MICRO,STAR INTERNATIONAL CO., LTD., OU=MICRO,STAR INTERNATIONAL CO., LTD., CN=MICRO,STAR INTERNATIONAL CO., LTD. |
| ValidFrom                         | 2011-08-30 06:46:09 |
| ValidTo                           | 2014-08-30 06:46:09 |
| Signature                         | 87bf57ab7ffd7e005076b34b14ddd924045ec7e389871661794f1ece1bef10e050893b28236cb650af1415f8cd95e86c2052d93311d73e0bbe6fb1c22ddea438a93c8b18bd4b8c0f81ad07032efb46d406bbaa730dd3ac92cbf0d9cc711a397a0e0320b213a5161e6be83ec69967a712b463129ea56d5a8ecd3ff8901be09dfaa0a0f10e879b307863e1b1c3a3149ac73bc3f3160db7012229b57bced6d47b875878663642a8cddd03da1e7f236b8cf16713a5e0f4c892aaca77a8c7dab41d84567e2bbf09b336a2824e0e18d54d199e6e024d2630bb210cd24a9ef4b377be0429e2ecc9bf8478a8c6a78c686e26f29c95925baee85e4bbb97b6eecffe44a25e |
| SignatureAlgorithmOID             | 1.2.840.113549.1.1.5 |
| IsCertificateAuthority            | False |
| SerialNumber                      | 1121a559b50ef9848661f0faeb7421bbdd2c |
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
#### Imported Functions
{{< details "Expand" >}}
* RtlInitUnicodeString
* ZwClose
* ZwMapViewOfSection
* ObReferenceObjectByHandle
* ZwOpenSection
* MmMapIoSpace
* IoDeleteSymbolicLink
* IofCompleteRequest
* ZwUnmapViewOfSection
* MmUnmapIoSpace
* IoCreateSymbolicLink
* IoCreateDevice
* __C_specific_handler
* IoDeleteDevice
* HalTranslateBusAddress

{{< /details >}}
#### Exported Functions
{{< details "Expand" >}}

{{< /details >}}

#### Sections
{{< details "Expand" >}}
* .text
* .rdata
* .data
* .pdata
* INIT

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
        "SHA256": "3ca71e85908ff67368e4dc00253f5691b9e6d50c966e7784143d75fb92aa3448",
        "SHA384": "d9d366f9328f2b55ee19a32cc5fd5148b81d764282fe5dc196c872ae249caa51d2c212ef39f33945dfe0cda81925e326"
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
        "SHA256": "cbdc9a0ad785d0c2013211746b42234e18bdc7d54a7a260647badc1c9e712ed4",
        "SHA384": "dcec542f242317863d0b3d23947e17d6982e381003831777b07ed75b46fb18bd0392a89c9beb6862981cd05f3f2fb77b"
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
        "SHA256": "4783380498acf592286ef2dea0fcc5bdea3f54d5e374d3e3497df9d5f662cfb6",
        "SHA384": "4f428f115cf3d008248f15f32007fc7c54bd454e1b48b765776b4c87c23ab8818d8fbcbb3646d35eca012b025260a3b8"
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
        "SHA256": "5b81998ed98b343c04134c336e03f3051779eae0e9f882e8339593d18556375d",
        "SHA384": "db0076cad41a0ef4ea68754ef6905bd5ff772adcb745b05c0060344e43588abc95952dc3ad272f5a8f17b206e4089aca"
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
        "SHA256": "ef14ea05bb066ee9f4188196dd69cd769b283ac4d7555db52f5e76922d3456e1",
        "SHA384": "6e7450a139856aeda6fa6284ff89b3752a9b646e096b4d33dd7e8e727742a2111481531581c0aa2cda0338e22cfdbad3"
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
| Filename           |  |
| Creation Timestamp           | 2011-09-06 06:24:50 |
| MD5                | [aa55dd14064cb808613d09195e3ba749](https://www.virustotal.com/gui/file/aa55dd14064cb808613d09195e3ba749) |
| SHA1               | [604870e76e55078dfb8055d49ae8565ed6177f7c](https://www.virustotal.com/gui/file/604870e76e55078dfb8055d49ae8565ed6177f7c) |
| SHA256             | [3ac8e54be2804f5fa60d0d23a11ba323fba078a942c96279425aabad935b8236](https://www.virustotal.com/gui/file/3ac8e54be2804f5fa60d0d23a11ba323fba078a942c96279425aabad935b8236) |
| Authentihash MD5   | [55466195f0b2f4afc4243b43a806e6d9](https://www.virustotal.com/gui/search/authentihash%253A55466195f0b2f4afc4243b43a806e6d9) |
| Authentihash SHA1  | [38b353d8480885de5dcf299deca99ce4f26a1d20](https://www.virustotal.com/gui/search/authentihash%253A38b353d8480885de5dcf299deca99ce4f26a1d20) |
| Authentihash SHA256| [5182caf10de9cec0740ecde5a081c21cdc100d7eb328ffe6f3f63183889fec6b](https://www.virustotal.com/gui/search/authentihash%253A5182caf10de9cec0740ecde5a081c21cdc100d7eb328ffe6f3f63183889fec6b) |
| RichPEHeaderHash MD5   | [59080883b71fd56bbf10ec0ae4b6bdd4](https://www.virustotal.com/gui/search/rich_pe_header_hash%253A59080883b71fd56bbf10ec0ae4b6bdd4) |
| RichPEHeaderHash SHA1  | [503a36a225568553cc9b05f63b3506c6ff21e12e](https://www.virustotal.com/gui/search/rich_pe_header_hash%253A503a36a225568553cc9b05f63b3506c6ff21e12e) |
| RichPEHeaderHash SHA256| [bc812d4ddc3ecfbf38c4d0d185e368fc58bac6e07f722db032bf6303daa7c946](https://www.virustotal.com/gui/search/rich_pe_header_hash%253Abc812d4ddc3ecfbf38c4d0d185e368fc58bac6e07f722db032bf6303daa7c946) |

{{< button "https://github.com/magicsword-io/LOLDrivers/raw/main/drivers/aa55dd14064cb808613d09195e3ba749.bin" "Download" >}} 

#### Certificates

{{< details "Expand" >}}
###### Certificate 0400000000012019c19066
| Field                             | Value                      |
|-----------------------------------|----------------------------|
| ToBeSigned (TBS) MD5              | 42023b9487cafe46c1b6a49c369a362e  |
| ToBeSigned (TBS) SHA1             | 7c7b524d269334b9f073c32e888e09544c6acd98 |
| ToBeSigned (TBS) SHA256           | b7126567833f3daa4085ff41e73112daad3d1e3808a942c1936520e2d6c46c78 |
| Subject                           | OU=Timestamping CA, O=GlobalSign, CN=GlobalSign Timestamping CA |
| ValidFrom                         | 2009-03-18 11:00:00 |
| ValidTo                           | 2028-01-28 12:00:00 |
| Signature                         | 5df6cb2b0d0140849f857a43706ae0c5e7aa0600d76713c9089131654f14a8a905dc389e6aa0300abd8dc78028ee4245ca94f3de5845a9803204f5595c6a70003927944df5b44634e81c5331b2b35416e9cc42abd5d959301cfb462725b88723b1e8758824831ec876377b01494548a4ede25dd27c9ca2dc2dba105a126265abae00c710343bcb72bd14240cdcc37627b4a7fee15829f20e169f91391d89a6e60f1c878ce258ac927e243eaaec14e73a33348bc63bac83ab0f14627aba1a2d4d4b1bc530f00b92797d3c78e0f8e6d215965999392b3061e8b8f8c0a1e9221411787dc4dc89bec0bb94e172aeebb540404fef171e585ed0a88996ac9228e9babf |
| SignatureAlgorithmOID             | 1.2.840.113549.1.1.5 |
| IsCertificateAuthority            | True |
| SerialNumber                      | 0400000000012019c19066 |
| Version                           | 3 |
###### Certificate 01000000000125b0b4cc01
| Field                             | Value                      |
|-----------------------------------|----------------------------|
| ToBeSigned (TBS) MD5              | e3369c8e5aec0504b3a50455f615d9f9  |
| ToBeSigned (TBS) SHA1             | 13c244a894b40ecd18aaf97c362f20385bd005a7 |
| ToBeSigned (TBS) SHA256           | 26da721a670c72836926032fee6920118bfb9bff89cc8d0ce30d9452c33f2532 |
| Subject                           | C=BE, O=GlobalSign NV, CN=GlobalSign Time Stamping Authority |
| ValidFrom                         | 2009-12-21 09:32:56 |
| ValidTo                           | 2020-12-22 09:32:56 |
| Signature                         | bc89ecfee63655935c79d4117a86808f17b693b26d9b91a1561811c655eaf608edad9b9ef52b81c8bbdd607b1b47991e6d403e1d80c213d58e04052fdbe7ae529e688472a1e54a603cf89bd52f46d8c3b2b79353ac9b6c432424d1f1fce9562e3411581843eaefff34746ca0c06c7fad031969881e9560cabbbd0cbb76efc724b081c63831cf36ad0c38b89020849b2e8f28b99ff6ca9427cdac396157e0e3955a9c769230f5dea6973d721c2a6032a8334d8635338a5cf3a4fdf7062ce16b4b30f5cbd34362f841b9de7d20cb058c8e2cf65f35fd338d42896508362ca389f45a858bb0b97bdb6ccba1f8d20e1bbb977cd12779be9d7c3be6a75634d8c991a9 |
| SignatureAlgorithmOID             | 1.2.840.113549.1.1.5 |
| IsCertificateAuthority            | False |
| SerialNumber                      | 01000000000125b0b4cc01 |
| Version                           | 3 |
###### Certificate 79c32d7ddd2458cf2eabe5b1b5c5290f
| Field                             | Value                      |
|-----------------------------------|----------------------------|
| ToBeSigned (TBS) MD5              | 5ba772ec00357ae706016510775c7a00  |
| ToBeSigned (TBS) SHA1             | eeb31b244ea14abae1e947ecdca0d6ae4720031b |
| ToBeSigned (TBS) SHA256           | c8e707c2615c26ac78ed06b42dd20bc8ff82bc5e02ddafe2c9af85755097691b |
| Subject                           | C=US, ST=California, L=Brea, O=EVGA, OU=Digital ID Class 3 , Microsoft Software Validation v2, CN=EVGA |
| ValidFrom                         | 2010-04-14 00:00:00 |
| ValidTo                           | 2012-04-15 23:59:59 |
| Signature                         | ba96817224593697c9135d803c5fc87767f2a7ed8fa0aa18eab4030a3daed18c55fb7eda8835d0488d18136c0db39d8edf3224790842cdf8580b35324631de717e9279d28d605285615341aeea10a73005d59cbe3138bebfa5003cbcf2971249423d820d6d252a18bf4dd124a1ac0c2f66015cbb23690e1b0fb9d5ce3f047663f1fb6735e54f09cfb6162da298bdc956490586cfdadee74a5766c187223e19112d22f59c7f3f325449afebc42689ec4c9399bd0d97397c37230804a4e5bc17e904008aa9c5972e2332302e57648006d057c9ed8c6384fb42d138971c86079b155c202733b837b3eef122c866ce3e6d8a8d9f1685e618cc2466d623d212b73df6 |
| SignatureAlgorithmOID             | 1.2.840.113549.1.1.5 |
| IsCertificateAuthority            | False |
| SerialNumber                      | 79c32d7ddd2458cf2eabe5b1b5c5290f |
| Version                           | 3 |
###### Certificate 655226e1b22e18e1590f2985ac22e75c
| Field                             | Value                      |
|-----------------------------------|----------------------------|
| ToBeSigned (TBS) MD5              | 650704c342850095f3288eaf791147d4  |
| ToBeSigned (TBS) SHA1             | 4cdc38c800761463749c3cbd94a12f32e49877bf |
| ToBeSigned (TBS) SHA256           | 07b8f662558ec85b71b43a79c6e94698144f4ced2308af21e7ba1e5d461da214 |
| Subject                           | C=US, O=VeriSign, Inc., OU=VeriSign Trust Network, OU=Terms of use at https://www.verisign.com/rpa (c)09, CN=VeriSign Class 3 Code Signing 2009,2 CA |
| ValidFrom                         | 2009-05-21 00:00:00 |
| ValidTo                           | 2019-05-20 23:59:59 |
| Signature                         | 8b03c0dd94d841a26169b015a878c730c6903c7e42f724b6e4837317047f04109ca1e2fa812febc0ca44e772e050b6551020836e9692e49a516ab43731dca52deb8c00c71d4fe74d32ba85f84ebefa675565f06abe7aca64381a101078457631f3867a030f60c2b35d9df68b6676821b59e183e5bd49a53856e5de41770e580f |
| SignatureAlgorithmOID             | 1.2.840.113549.1.1.5 |
| IsCertificateAuthority            | True |
| SerialNumber                      | 655226e1b22e18e1590f2985ac22e75c |
| Version                           | 3 |
###### Certificate 610c120600000000001b
| Field                             | Value                      |
|-----------------------------------|----------------------------|
| ToBeSigned (TBS) MD5              | 53c41bc1164e09e0cd1617a5bf913efd  |
| ToBeSigned (TBS) SHA1             | 93c03aac8951d494ecd5696b1c08658541b18727 |
| ToBeSigned (TBS) SHA256           | 40bddadac24dc61ca4fb5cab2a2bc5d876bc36808311039a7a3e1a4066f7489b |
| Subject                           | C=US, O=VeriSign, Inc., OU=Class 3 Public Primary Certification Authority |
| ValidFrom                         | 2006-05-23 17:01:29 |
| ValidTo                           | 2016-05-23 17:11:29 |
| Signature                         | 01e446b33b457f7513877e5f43de468ecb8abdb64741bccccc7491d8ce395195a4a6b547c0efd2da7b8f5711f4328c7ccd3fee42da04214af7c843884a6f5cca14fc4bd19f4cbdd4556ecc02be0da6888f8609baa425bde8b0f0fa8b714e67b0cb82a8d78e55f737ebf03e88efe4e08afd1c6e2e61414875b4b02c1d28d8490fd715f02473253ccc880cde284c6554fe5eae8cea19ad2c51b29b3a47f53c80350117e24987d6544afb4bab07bcbf7d79cfbf35005cbb9ecffc82891b39a05197b6dec0b307ff449644c0342a195cabeef03bec294eb513c537857e75d5b4d60d066eb5d26c237167eaf1718eaf4e74aa0cf9ecbf4c58fa5e909b6d39cb86883f8b1ca81632d5fe6db9f1f8b3ead791f6364778c0272a15c768d6f4c5fc4f4ec8673f102d409ff11ec96148e7a703fc31730cf04688fe56da492995ef09daa3e5beef60ecd954a0599c28bd54ef66157f874c84dba60e95672e517b3439b641c28c846826dc240209e7818e0a972defeea7b998a60f818dc710b5e1ed982f486f53854964789bec5dac970b5526c3efba8dc8d1a52f5a7f936b611a339b18b8a26210de24ea76e12f43ebecdd7c12342489da2855aee5754e312b6763b6a8d7ab730a03cec5ea593fc7eb2a45aea8625b2f009939abb45f73c308ec80118f470e8f2a1343e191066255bbffba3da9a93d260faeca7d628b155589d694344dd665 |
| SignatureAlgorithmOID             | 1.2.840.113549.1.1.5 |
| IsCertificateAuthority            | True |
| SerialNumber                      | 610c120600000000001b |
| Version                           | 3 |

{{< /details >}}
#### Imports
{{< details "Expand" >}}
* ntoskrnl.exe
* HAL.dll

{{< /details >}}
#### Imported Functions
{{< details "Expand" >}}
* RtlInitUnicodeString
* ZwClose
* ZwMapViewOfSection
* ObReferenceObjectByHandle
* ZwOpenSection
* MmMapIoSpace
* IoDeleteSymbolicLink
* IofCompleteRequest
* ZwUnmapViewOfSection
* MmUnmapIoSpace
* IoCreateSymbolicLink
* IoCreateDevice
* __C_specific_handler
* IoDeleteDevice
* HalTranslateBusAddress

{{< /details >}}
#### Exported Functions
{{< details "Expand" >}}

{{< /details >}}

#### Sections
{{< details "Expand" >}}
* .text
* .rdata
* .data
* .pdata
* INIT

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
        "SHA256": "3ca71e85908ff67368e4dc00253f5691b9e6d50c966e7784143d75fb92aa3448",
        "SHA384": "d9d366f9328f2b55ee19a32cc5fd5148b81d764282fe5dc196c872ae249caa51d2c212ef39f33945dfe0cda81925e326"
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
        "SHA256": "cbdc9a0ad785d0c2013211746b42234e18bdc7d54a7a260647badc1c9e712ed4",
        "SHA384": "dcec542f242317863d0b3d23947e17d6982e381003831777b07ed75b46fb18bd0392a89c9beb6862981cd05f3f2fb77b"
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
        "SHA256": "4783380498acf592286ef2dea0fcc5bdea3f54d5e374d3e3497df9d5f662cfb6",
        "SHA384": "4f428f115cf3d008248f15f32007fc7c54bd454e1b48b765776b4c87c23ab8818d8fbcbb3646d35eca012b025260a3b8"
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
        "SHA256": "5b81998ed98b343c04134c336e03f3051779eae0e9f882e8339593d18556375d",
        "SHA384": "db0076cad41a0ef4ea68754ef6905bd5ff772adcb745b05c0060344e43588abc95952dc3ad272f5a8f17b206e4089aca"
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
        "SHA256": "ef14ea05bb066ee9f4188196dd69cd769b283ac4d7555db52f5e76922d3456e1",
        "SHA384": "6e7450a139856aeda6fa6284ff89b3752a9b646e096b4d33dd7e8e727742a2111481531581c0aa2cda0338e22cfdbad3"
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
| Filename           |  |
| Creation Timestamp           | 2013-03-10 23:32:06 |
| MD5                | [710b290a00598fbb1bcc49b30174b2c9](https://www.virustotal.com/gui/file/710b290a00598fbb1bcc49b30174b2c9) |
| SHA1               | [1e6c2763f97e4275bba581de880124d64666a2fe](https://www.virustotal.com/gui/file/1e6c2763f97e4275bba581de880124d64666a2fe) |
| SHA256             | [bbbeb5020b58e6942ec7dec0d1d518e95fc12ddae43f54ef0829d3393c6afd63](https://www.virustotal.com/gui/file/bbbeb5020b58e6942ec7dec0d1d518e95fc12ddae43f54ef0829d3393c6afd63) |
| Authentihash MD5   | [936e49d3eec0a2f433e9d0115a38a2b6](https://www.virustotal.com/gui/search/authentihash%253A936e49d3eec0a2f433e9d0115a38a2b6) |
| Authentihash SHA1  | [5717bf3e520accfff5ad9943e53a3b118fb67f2e](https://www.virustotal.com/gui/search/authentihash%253A5717bf3e520accfff5ad9943e53a3b118fb67f2e) |
| Authentihash SHA256| [918d2e68a724b58d37443aea159e70bf8b1b5ebb089c395cad1d62745ecdaa19](https://www.virustotal.com/gui/search/authentihash%253A918d2e68a724b58d37443aea159e70bf8b1b5ebb089c395cad1d62745ecdaa19) |
| RichPEHeaderHash MD5   | [59080883b71fd56bbf10ec0ae4b6bdd4](https://www.virustotal.com/gui/search/rich_pe_header_hash%253A59080883b71fd56bbf10ec0ae4b6bdd4) |
| RichPEHeaderHash SHA1  | [503a36a225568553cc9b05f63b3506c6ff21e12e](https://www.virustotal.com/gui/search/rich_pe_header_hash%253A503a36a225568553cc9b05f63b3506c6ff21e12e) |
| RichPEHeaderHash SHA256| [bc812d4ddc3ecfbf38c4d0d185e368fc58bac6e07f722db032bf6303daa7c946](https://www.virustotal.com/gui/search/rich_pe_header_hash%253Abc812d4ddc3ecfbf38c4d0d185e368fc58bac6e07f722db032bf6303daa7c946) |

{{< button "https://github.com/magicsword-io/LOLDrivers/raw/main/drivers/710b290a00598fbb1bcc49b30174b2c9.bin" "Download" >}} 

#### Certificates

{{< details "Expand" >}}
###### Certificate 0400000000012019c19066
| Field                             | Value                      |
|-----------------------------------|----------------------------|
| ToBeSigned (TBS) MD5              | 42023b9487cafe46c1b6a49c369a362e  |
| ToBeSigned (TBS) SHA1             | 7c7b524d269334b9f073c32e888e09544c6acd98 |
| ToBeSigned (TBS) SHA256           | b7126567833f3daa4085ff41e73112daad3d1e3808a942c1936520e2d6c46c78 |
| Subject                           | OU=Timestamping CA, O=GlobalSign, CN=GlobalSign Timestamping CA |
| ValidFrom                         | 2009-03-18 11:00:00 |
| ValidTo                           | 2028-01-28 12:00:00 |
| Signature                         | 5df6cb2b0d0140849f857a43706ae0c5e7aa0600d76713c9089131654f14a8a905dc389e6aa0300abd8dc78028ee4245ca94f3de5845a9803204f5595c6a70003927944df5b44634e81c5331b2b35416e9cc42abd5d959301cfb462725b88723b1e8758824831ec876377b01494548a4ede25dd27c9ca2dc2dba105a126265abae00c710343bcb72bd14240cdcc37627b4a7fee15829f20e169f91391d89a6e60f1c878ce258ac927e243eaaec14e73a33348bc63bac83ab0f14627aba1a2d4d4b1bc530f00b92797d3c78e0f8e6d215965999392b3061e8b8f8c0a1e9221411787dc4dc89bec0bb94e172aeebb540404fef171e585ed0a88996ac9228e9babf |
| SignatureAlgorithmOID             | 1.2.840.113549.1.1.5 |
| IsCertificateAuthority            | True |
| SerialNumber                      | 0400000000012019c19066 |
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
###### Certificate 01000000000125b0b4cc01
| Field                             | Value                      |
|-----------------------------------|----------------------------|
| ToBeSigned (TBS) MD5              | e3369c8e5aec0504b3a50455f615d9f9  |
| ToBeSigned (TBS) SHA1             | 13c244a894b40ecd18aaf97c362f20385bd005a7 |
| ToBeSigned (TBS) SHA256           | 26da721a670c72836926032fee6920118bfb9bff89cc8d0ce30d9452c33f2532 |
| Subject                           | C=BE, O=GlobalSign NV, CN=GlobalSign Time Stamping Authority |
| ValidFrom                         | 2009-12-21 09:32:56 |
| ValidTo                           | 2020-12-22 09:32:56 |
| Signature                         | bc89ecfee63655935c79d4117a86808f17b693b26d9b91a1561811c655eaf608edad9b9ef52b81c8bbdd607b1b47991e6d403e1d80c213d58e04052fdbe7ae529e688472a1e54a603cf89bd52f46d8c3b2b79353ac9b6c432424d1f1fce9562e3411581843eaefff34746ca0c06c7fad031969881e9560cabbbd0cbb76efc724b081c63831cf36ad0c38b89020849b2e8f28b99ff6ca9427cdac396157e0e3955a9c769230f5dea6973d721c2a6032a8334d8635338a5cf3a4fdf7062ce16b4b30f5cbd34362f841b9de7d20cb058c8e2cf65f35fd338d42896508362ca389f45a858bb0b97bdb6ccba1f8d20e1bbb977cd12779be9d7c3be6a75634d8c991a9 |
| SignatureAlgorithmOID             | 1.2.840.113549.1.1.5 |
| IsCertificateAuthority            | False |
| SerialNumber                      | 01000000000125b0b4cc01 |
| Version                           | 3 |
###### Certificate 1121a559b50ef9848661f0faeb7421bbdd2c
| Field                             | Value                      |
|-----------------------------------|----------------------------|
| ToBeSigned (TBS) MD5              | 3a98a18e8636f2a01e49e2a6d116c360  |
| ToBeSigned (TBS) SHA1             | a2938150e46525adcec2e3a2348824bc1cf532b2 |
| ToBeSigned (TBS) SHA256           | 01a2e2d31d0a4f3005753cce5972b5da2a7c08b0750fb6947e0fd231e64ae7ec |
| Subject                           | C=TW, ST=Taiwan, L=New Taipei City, O=MICRO,STAR INTERNATIONAL CO., LTD., OU=MICRO,STAR INTERNATIONAL CO., LTD., CN=MICRO,STAR INTERNATIONAL CO., LTD. |
| ValidFrom                         | 2011-08-30 06:46:09 |
| ValidTo                           | 2014-08-30 06:46:09 |
| Signature                         | 87bf57ab7ffd7e005076b34b14ddd924045ec7e389871661794f1ece1bef10e050893b28236cb650af1415f8cd95e86c2052d93311d73e0bbe6fb1c22ddea438a93c8b18bd4b8c0f81ad07032efb46d406bbaa730dd3ac92cbf0d9cc711a397a0e0320b213a5161e6be83ec69967a712b463129ea56d5a8ecd3ff8901be09dfaa0a0f10e879b307863e1b1c3a3149ac73bc3f3160db7012229b57bced6d47b875878663642a8cddd03da1e7f236b8cf16713a5e0f4c892aaca77a8c7dab41d84567e2bbf09b336a2824e0e18d54d199e6e024d2630bb210cd24a9ef4b377be0429e2ecc9bf8478a8c6a78c686e26f29c95925baee85e4bbb97b6eecffe44a25e |
| SignatureAlgorithmOID             | 1.2.840.113549.1.1.5 |
| IsCertificateAuthority            | False |
| SerialNumber                      | 1121a559b50ef9848661f0faeb7421bbdd2c |
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
#### Imported Functions
{{< details "Expand" >}}
* RtlInitUnicodeString
* ZwClose
* ZwMapViewOfSection
* ObReferenceObjectByHandle
* ZwOpenSection
* MmMapIoSpace
* IoDeleteSymbolicLink
* IofCompleteRequest
* ZwUnmapViewOfSection
* MmUnmapIoSpace
* IoCreateSymbolicLink
* IoCreateDevice
* __C_specific_handler
* IoDeleteDevice
* HalTranslateBusAddress

{{< /details >}}
#### Exported Functions
{{< details "Expand" >}}

{{< /details >}}

#### Sections
{{< details "Expand" >}}
* .text
* .rdata
* .data
* .pdata
* INIT

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
        "SHA256": "3ca71e85908ff67368e4dc00253f5691b9e6d50c966e7784143d75fb92aa3448",
        "SHA384": "d9d366f9328f2b55ee19a32cc5fd5148b81d764282fe5dc196c872ae249caa51d2c212ef39f33945dfe0cda81925e326"
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
        "SHA256": "cbdc9a0ad785d0c2013211746b42234e18bdc7d54a7a260647badc1c9e712ed4",
        "SHA384": "dcec542f242317863d0b3d23947e17d6982e381003831777b07ed75b46fb18bd0392a89c9beb6862981cd05f3f2fb77b"
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
        "SHA256": "4783380498acf592286ef2dea0fcc5bdea3f54d5e374d3e3497df9d5f662cfb6",
        "SHA384": "4f428f115cf3d008248f15f32007fc7c54bd454e1b48b765776b4c87c23ab8818d8fbcbb3646d35eca012b025260a3b8"
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
        "SHA256": "5b81998ed98b343c04134c336e03f3051779eae0e9f882e8339593d18556375d",
        "SHA384": "db0076cad41a0ef4ea68754ef6905bd5ff772adcb745b05c0060344e43588abc95952dc3ad272f5a8f17b206e4089aca"
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
        "SHA256": "ef14ea05bb066ee9f4188196dd69cd769b283ac4d7555db52f5e76922d3456e1",
        "SHA384": "6e7450a139856aeda6fa6284ff89b3752a9b646e096b4d33dd7e8e727742a2111481531581c0aa2cda0338e22cfdbad3"
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

*last_updated:* 2025-03-03

{{< /column >}}
{{< /block >}}
