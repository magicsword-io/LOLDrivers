+++

description = ""
title = "e7fd8ffc-ab37-4a7b-8dc9-fc7432fbacae"
weight = 10
displayTitle = "driver_4d8bc539.sys"
+++


{{< block "grid-1" >}}
{{< column "mt-2 pt-1">}}


# driver_4d8bc539.sys ![:inline](/images/twitter_verified.png)  ![:inline](/images/elmo.gif) 

### Description

Sophos, from time to time, has observed a threat actor deploy variants of Poortry on different machines within a single estate during an attack. These variants contain the same payload, but signed with a different certificate than the driver first seen used during the attack.
- **UUID**: e7fd8ffc-ab37-4a7b-8dc9-fc7432fbacae
- **Created**: 2024-09-10
- **Author**: Michael Haag
- **Acknowledgement**:  | [](https://twitter.com/)

{{< button "https://github.com/magicsword-io/LOLDrivers/raw/main/drivers/cf42cc217c139298641901aad4e5db08.bin" "Download" >}}{{< button "https://www.magicsword.io/premium" "Block" "red" >}}
{{< tip "warning" >}}
This download link contains the malicious driver!

{{< /tip >}}

### Commands

```
sc.exe create driver_bfcbc010.sys binPath=C:\windows\temp\driver_bfcbc010.sys type=kernel &amp;&amp; sc.exe start driver_bfcbc010.sys
```


| Use Case | Privileges | Operating System | 
|:---- | ---- | ---- |
| Elevate privileges | kernel | Windows 10 |



### Detections


{{< block "grid-3" >}}
{{< column >}}
#### YARA 🏹
{{< details "Expand" >}}

{{< button "https://github.com/magicsword-io/LOLDrivers/tree/main/detections/yara/yara-rules_mal_drivers_strict.yar" "Exact Match" >}}{{< tip >}}with header and size limitation{{< /tip >}} 

{{< button "https://github.com/magicsword-io/LOLDrivers/tree/main/detections/yara/yara-rules_mal_drivers.yar" "Threat Hunting" >}}{{< tip >}}without header and size limitation{{< /tip >}} 



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
<li><a href="https://news.sophos.com/en-us/2024/08/27/burnt-cigar-2/">https://news.sophos.com/en-us/2024/08/27/burnt-cigar-2/</a></li>
<br>


### Known Vulnerable Samples

| Property           | Value |
|:-------------------|:------|
| Filename           |  |
| Creation Timestamp           | 2023-12-13 14:38:41 |
| MD5                | [cf42cc217c139298641901aad4e5db08](https://www.virustotal.com/gui/file/cf42cc217c139298641901aad4e5db08) |
| SHA1               | [01a606df49cc2ea19242519b51f7f17d2ba38be2](https://www.virustotal.com/gui/file/01a606df49cc2ea19242519b51f7f17d2ba38be2) |
| SHA256             | [4d8bc539ca7c72e552b7065d2a84fef43b75a46a53c82b50556c2984e0a86a9e](https://www.virustotal.com/gui/file/4d8bc539ca7c72e552b7065d2a84fef43b75a46a53c82b50556c2984e0a86a9e) |
| Authentihash MD5   | [cd675d9c1e9c0991690f08ab8bc50916](https://www.virustotal.com/gui/search/authentihash%253Acd675d9c1e9c0991690f08ab8bc50916) |
| Authentihash SHA1  | [4e261a9ca84fd163618e13fe60739229af607d05](https://www.virustotal.com/gui/search/authentihash%253A4e261a9ca84fd163618e13fe60739229af607d05) |
| Authentihash SHA256| [0dc9021f0c02e18f4c3357da42630adf515655b9473f93385c5c157efd5da4ac](https://www.virustotal.com/gui/search/authentihash%253A0dc9021f0c02e18f4c3357da42630adf515655b9473f93385c5c157efd5da4ac) |
| RichPEHeaderHash MD5   | [ffdf660eb1ebf020a1d0a55a90712dfb](https://www.virustotal.com/gui/search/rich_pe_header_hash%253Affdf660eb1ebf020a1d0a55a90712dfb) |
| RichPEHeaderHash SHA1  | [3e905e3d061d0d59de61fcf39c994fcb0ec1bab3](https://www.virustotal.com/gui/search/rich_pe_header_hash%253A3e905e3d061d0d59de61fcf39c994fcb0ec1bab3) |
| RichPEHeaderHash SHA256| [2b3f99a94b7a7132854be769e27b331419c53989ef42f686d6f5ba09ddefefd6](https://www.virustotal.com/gui/search/rich_pe_header_hash%253A2b3f99a94b7a7132854be769e27b331419c53989ef42f686d6f5ba09ddefefd6) |

{{< button "https://github.com/magicsword-io/LOLDrivers/raw/main/drivers/cf42cc217c139298641901aad4e5db08.bin" "Download" >}} 

#### Certificates

{{< details "Expand" >}}
###### Certificate 1cb2d523a6bf7a066642c578de1c9be4
| Field                             | Value                      |
|-----------------------------------|----------------------------|
| ToBeSigned (TBS) MD5              | 65742dda29af02ee39af8b3c11f7469b  |
| ToBeSigned (TBS) SHA1             | 521f7a1f51ac74d4f29c599aa9dff8d466158438 |
| ToBeSigned (TBS) SHA256           | 33a7dcdd20164cdfa97f1af890a17ec28047093c116185a42dbcb77ceaabc769 |
| Subject                           | C=CN, ST=Guangdong, L=Shenzhen, O=Shenzhen Huanan Xingfa Electronic Equipment Firm, CN=Shenzhen Huanan Xingfa Electronic Equipment Firm |
| ValidFrom                         | 2013-07-10 00:00:00 |
| ValidTo                           | 2014-07-10 23:59:59 |
| Signature                         | 453f89c72c0f43e9a0bea7aee4cc94137f22b1eed4c9970976ba0a64af4f248e9ed746472c54431e740ade4be5d3cf00a1b0e2138a54a137e2c5ca5d1485acfd4ce5deaf6bb98c4da4b98ed3f68123044bafa8fca57eecbe17acf2299a4c79ed76673280a7f930381406ecce5afad5aa28af71d68f48fff2b8f5944687e941ed507bfbe4b9b1a5075aa9493c083cabcad2e564e52fed0427eebce1880094f83c8a049638b826dbc9ab313354e9fc7938e6c57ad7450514abec83f28229b6ff7a208e6b3e9b059f2c439e2ecb0e143858a7748bcfc7750111a5a7dbb30f32906cafabd4f23c80f3752296e54b3aebef6b381ad065e070a271876ee77bad0d42e0 |
| SignatureAlgorithmOID             | 1.2.840.113549.1.1.5 |
| IsCertificateAuthority            | False |
| SerialNumber                      | 1cb2d523a6bf7a066642c578de1c9be4 |
| Version                           | 3 |
###### Certificate 47974d7873a5bcab0d2fb370192fce5e
| Field                             | Value                      |
|-----------------------------------|----------------------------|
| ToBeSigned (TBS) MD5              | e3a93dc2a8a8a668fdbb286bfe9afab5  |
| ToBeSigned (TBS) SHA1             | 95795d2aa2a554a423bc8c6e5b0a016d14887d35 |
| ToBeSigned (TBS) SHA256           | d8844186775bddbccaf3dc017064df7d760fd4b85c5d07561a3efd7da950f89e |
| Subject                           | C=US, O=Thawte, Inc., CN=Thawte Code Signing CA , G2 |
| ValidFrom                         | 2010-02-08 00:00:00 |
| ValidTo                           | 2020-02-07 23:59:59 |
| Signature                         | 56fe535ce1c79ebca7ed7e536d6a144b518c405e805faaa4e82fef38c804c9ca3ecfdf3a584eb0d4b663c52957fa02059a454d68db2a1bd4343d9f00c35acb9549a56ee1b0c5fc414d414a6fd377c8d7388de419de18f31f1565836d450c53f90a9a2ea55dbf6f32811892196a5500ad631c52067e55d92968ae4a7c189a79886b2323d827382a298776cafbc7b662231fed7a564cdd9c325bf53d0c4618953b2a2368836441d9006d0f1924156872bdc571676eac4cdb90eb51a51a6207d0be6a00473c722fec4f613e7385ce5a0ab7bac01c1375e3223928dd6d1d09469d4fbae8408191c6a4ce94721b01cf2a6e15679589ae7db7b7cdf90a3d75b66b3c25 |
| SignatureAlgorithmOID             | 1.2.840.113549.1.1.5 |
| IsCertificateAuthority            | True |
| SerialNumber                      | 47974d7873a5bcab0d2fb370192fce5e |
| Version                           | 3 |
###### Certificate 611fb0a400000000001d
| Field                             | Value                      |
|-----------------------------------|----------------------------|
| ToBeSigned (TBS) MD5              | a3f222107d4e1085e73b5b589c2f480b  |
| ToBeSigned (TBS) SHA1             | b94aa26cd77c48d91a53ac44506cbd255e1d362c |
| ToBeSigned (TBS) SHA256           | a39ed0d6fd4eb1a6f7fed60f726e23eae668b7591bc004644625d22c701213fa |
| Subject                           | C=US, O=thawte, Inc., OU=Certification Services Division, OU=(c) 2006 thawte, Inc. , For authorized use only, CN=thawte Primary Root CA |
| ValidFrom                         | 2011-02-22 19:31:57 |
| ValidTo                           | 2021-02-22 19:41:57 |
| Signature                         | 2dcc71b5e8ba94ff5ee64467007b6afc412c3ee70e41855ab12a932ba95b89f2f72b499c8003f297b8e760a80ed7fd5de545467594f4ed1c9de166228b61fb29f2c6a8bdf387c98f7f47e1c058b64a1aa2e7f718606969e083069e26c775c40c0d79da746b52b9fae8ea3359b9bb18dd291a14dfd36a37277a9da0dacffffc22c4faf009ff33e93e17ba1cc742cfce2743d30c0c5581303db96060ce02ece19ee81ddc852ce0a18d966d95ac17a4713ea16741b6281d2ce3b615e5b7e5a2f6256d86e320acf9f8314f8e629b9833376d6af735523e90feb03b5fc5b852a9e06ea0479a279e97aea24a9e531939ec357ec659de3ae0aaf533f06abda0821812dea18c4570ca2bd62e959145995a5c240049bd23b30ceca43df5b9e1d1b1825a38eea3fba1ab483a8c5dffa065223fd3d3fe4990db1446a3852e8a554b09ab38b2ab63a008d1fdad48e273d812bcc26ca516fad09ac05e38383a2b718e553aac42197a1f0d4220e7ab5d8c6880524ca1c0d488d02321fb901309007b4937afa9df486022abf4f6c2363bf8513c34bbc586e43ae19f4b90fe5461024b159c34176aa94b8d4cb69d2326c83af1d6b805cdda1d6240183a2f1b41cd3a993a0aa9d1d77eb8c4aff7b8c980105ed55df6ce7a9a02c50f6381efb564e9fc5bd8d2619a68c37cf9c78df91e87d5fa2cf816ae9dab068fc86dc741cda14e84e3dac26ebcfb |
| SignatureAlgorithmOID             | 1.2.840.113549.1.1.5 |
| IsCertificateAuthority            | True |
| SerialNumber                      | 611fb0a400000000001d |
| Version                           | 3 |
###### Certificate 0e9b188ef9d02de7efdb50e20840185a
| Field                             | Value                      |
|-----------------------------------|----------------------------|
| ToBeSigned (TBS) MD5              | 21a266bd49f2778b24d13d95641ea6ac  |
| ToBeSigned (TBS) SHA1             | 21319f341fdf06bf6a104427afa8b7823b1ea7f3 |
| ToBeSigned (TBS) SHA256           | e933dc68ee65abd1f9b1aa6738eff60a6895d3d8cc4accf0c69069aa3decd757 |
| Subject                           | C=US, O=DigiCert Inc, OU=www.digicert.com, CN=DigiCert Trusted Root G4 |
| ValidFrom                         | 2022-08-01 00:00:00 |
| ValidTo                           | 2031-11-09 23:59:59 |
| Signature                         | 70a0bf435c55e7385fa0a3741b3db616d7f7bf5707bd9aaca1872cec855ea91abb22f8871a695422eda488776dbd1a14f4134a7a2f2db738eff4ff80b9f8a1f7f272de24bc5203c84ed02adefa2d56cff9f4f7ac307a9a8bb25ed4cfd143449b4321eb9672a148b499cb9d4fa7060313772744d4e77fe859a8f0bf2f0ba6e9f2343cecf703c787a8d24c401935466a6954b0b8a1568eeca4d53de8b1dcfd1cd8f4775a5c548c6fefa1503dfc760968849f6fcadb208d35601c0203cb20b0ac58a00e4063c59822c1b259f5556bcf27ab6c76ce6f232df47e716a236b22ff12b8542d277ed83ad9f0b68796fd5bd15cac18c34d9f73b701a99f57aa5e28e2b994 |
| SignatureAlgorithmOID             | 1.2.840.113549.1.1.12 |
| IsCertificateAuthority            | True |
| SerialNumber                      | 0e9b188ef9d02de7efdb50e20840185a |
| Version                           | 3 |
###### Certificate 073637b724547cd847acfd28662a5e5b
| Field                             | Value                      |
|-----------------------------------|----------------------------|
| ToBeSigned (TBS) MD5              | e4b8ad9932ff9205f580cf8fb2afbb86  |
| ToBeSigned (TBS) SHA1             | 5301f7044d78bf94dd2b6e4871083a17fdba1dcc |
| ToBeSigned (TBS) SHA256           | c3d01499a5d1d2f71e0f44e78fbfa4b8aadb43dd4f226401e0c1d7a6d53357fa |
| Subject                           | C=US, O=DigiCert, Inc., CN=DigiCert Trusted G4 RSA4096 SHA256 TimeStamping CA |
| ValidFrom                         | 2022-03-23 00:00:00 |
| ValidTo                           | 2037-03-22 23:59:59 |
| Signature                         | 7d598ec093b66f98a94422017e66d6d82142e1b0182e104d13cf3053cebf18fbc7505de24b29fb708a0daa2969fc69c1cf1d07e93e60c8d80be55c5bd76d87fa842025343167cdb612966fc4504c621d0c0882a816bda956cf15738d012225ce95693f4777fb727414d7ffab4f8a2c7aab85cd435fed60b6aa4f91669e2c9ee08aace5fd8cbc6426876c92bd9d7cd0700a7cefa8bc754fba5af7a910b25de9ff285489f0d58a717665daccf072a323fac0278244ae99271bab241e26c1b7de2aebf69eb1799981a35686ab0a45c9dfc48da0e798fbfba69d72afc4c7c1c16a71d9c6138009c4b69fcd878724bb4fa349b9776691f1729ce94b0252a7377e9353ac3b1d08490f94cd397addff256399272c3d3f6ba7f166c341cd4fb6409b212140d0b71324cddc1d783ae49eade5347192d7266be43873aba6014fbd3f3b78ad4cadfbc4957bed0a5f33398741787a38e99ce1dd23fd1d28d3c7f9e8f1985ffb2bd87ef2469d752c1e272c26db6f157b1e198b36b893d4e6f2179959ca70f037bf9800df20164f27fb606716a166badd55c03a2986b098a02bed9541b73ad5159831b462090f0abd81d913febfa4d1f357d9bc04fa82de32df0489f000cd5dc2f9d0237f000be4760226d9f0657642a6298709472be67f1aa4850ffc9896f655542b1f80fac0f20e2be5d6fba92f44154ae7130e1ddb37381aa12bf6edd67cfc |
| SignatureAlgorithmOID             | 1.2.840.113549.1.1.11 |
| IsCertificateAuthority            | True |
| SerialNumber                      | 073637b724547cd847acfd28662a5e5b |
| Version                           | 3 |
###### Certificate 0544aff3949d0839a6bfdb3f5fe56116
| Field                             | Value                      |
|-----------------------------------|----------------------------|
| ToBeSigned (TBS) MD5              | 7630cbd02cc6732394e9fdfe99d0d8f8  |
| ToBeSigned (TBS) SHA1             | bc1890d694f9d392c4cbae6a174e35d70e7ec8b1 |
| ToBeSigned (TBS) SHA256           | 594a02de632b3a08ed6644c36994025e57f35bc8e7bd16cec5d347883390d1d8 |
| Subject                           | C=US, O=DigiCert, Inc., CN=DigiCert Timestamp 2023 |
| ValidFrom                         | 2023-07-14 00:00:00 |
| ValidTo                           | 2034-10-13 23:59:59 |
| Signature                         | 811ad6dea0a9b59817bc708d4f8a3c689cd825ffcb2ce4cdea5d2292ec8c2202a9b8cf80a8d9e7e3c5ed26828a712f18dd4eb6de6cd7e1609c2beded3d488eb86bba7c5dbdc26137684977a3eb90aa12d72785f38e1e92dac240389f5dc8a02e2578259d2a057a842998b657798fdb26562bb0f3a7bd370cd898764f56b952c2b69d38a981e76d415c8c69d1b92bc4c67bcf9cfa78e2931a76a26975d350e44412be200d9ea944d0f8e54977085a21c5b4cf98951a54bab9bcc16919bacf16f28337346eb04126ddde5a974f338dd48d777d7545a1a558266a0345ded950b5508caf56bd4cc5e146c528d3ade7430070decc989e198903ead49137ef4d52f3c96021c45647edda114b8c32c388e658e2b6db3ef95fb042d68fe31791d1aac055e386bfac272c41d09a334aa836d4b972967e977938485fcac2dc3d32df75d636675a89f8f6a7c7e54f353c00bdbe9c2a6c7901dcda44e63ade383b075e3958f47c733155a08011cb140c7eaebcfea4eb7965aa68d622ca3beb9a8235572816cb69f2329ab2d2d83ab8b146866bba17fdc4776c156caeabaf733ae84946b7d57fccb638c0d8ec1cf5b6a1b8432cdf4e4c7d1e6870c0770ad402e05c60bb28ff38e5525ad6ac1722234ef4ecd317fb506bff07771f71974441c9b846d36c327c582f674765e51b73b699f96b2c0646ef411ef0f05fe0dbd9ad908044af8010418a |
| SignatureAlgorithmOID             | 1.2.840.113549.1.1.11 |
| IsCertificateAuthority            | False |
| SerialNumber                      | 0544aff3949d0839a6bfdb3f5fe56116 |
| Version                           | 3 |

{{< /details >}}
#### Imports
{{< details "Expand" >}}
* NETIO.SYS
* ntoskrnl.exe
* HAL.dll
* ntoskrnl.exe
* HAL.dll

{{< /details >}}
#### Imported Functions
{{< details "Expand" >}}
* WskDeregister
* RtlInitUnicodeString
* KeStallExecutionProcessor
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
* .vmp0
* .vmp1
* .vmp2
* .reloc

{{< /details >}}
#### Signature
{{< details "Expand" >}}
```
{
  "Certificates": [
    {
      "IsCertificateAuthority": false,
      "SerialNumber": "1cb2d523a6bf7a066642c578de1c9be4",
      "Signature": "453f89c72c0f43e9a0bea7aee4cc94137f22b1eed4c9970976ba0a64af4f248e9ed746472c54431e740ade4be5d3cf00a1b0e2138a54a137e2c5ca5d1485acfd4ce5deaf6bb98c4da4b98ed3f68123044bafa8fca57eecbe17acf2299a4c79ed76673280a7f930381406ecce5afad5aa28af71d68f48fff2b8f5944687e941ed507bfbe4b9b1a5075aa9493c083cabcad2e564e52fed0427eebce1880094f83c8a049638b826dbc9ab313354e9fc7938e6c57ad7450514abec83f28229b6ff7a208e6b3e9b059f2c439e2ecb0e143858a7748bcfc7750111a5a7dbb30f32906cafabd4f23c80f3752296e54b3aebef6b381ad065e070a271876ee77bad0d42e0",
      "SignatureAlgorithmOID": "1.2.840.113549.1.1.5",
      "Subject": "C=CN, ST=Guangdong, L=Shenzhen, O=Shenzhen Huanan Xingfa Electronic Equipment Firm, CN=Shenzhen Huanan Xingfa Electronic Equipment Firm",
      "TBS": {
        "MD5": "65742dda29af02ee39af8b3c11f7469b",
        "SHA1": "521f7a1f51ac74d4f29c599aa9dff8d466158438",
        "SHA256": "33a7dcdd20164cdfa97f1af890a17ec28047093c116185a42dbcb77ceaabc769",
        "SHA384": "c6ee18c1175e124cc37ceeb72251230868f8fe48e2052a1984b6b1b0975039de150f9a7cad5969f44d504ec0357ec8b1"
      },
      "ValidFrom": "2013-07-10 00:00:00",
      "ValidTo": "2014-07-10 23:59:59",
      "Version": 3
    },
    {
      "IsCertificateAuthority": true,
      "SerialNumber": "47974d7873a5bcab0d2fb370192fce5e",
      "Signature": "56fe535ce1c79ebca7ed7e536d6a144b518c405e805faaa4e82fef38c804c9ca3ecfdf3a584eb0d4b663c52957fa02059a454d68db2a1bd4343d9f00c35acb9549a56ee1b0c5fc414d414a6fd377c8d7388de419de18f31f1565836d450c53f90a9a2ea55dbf6f32811892196a5500ad631c52067e55d92968ae4a7c189a79886b2323d827382a298776cafbc7b662231fed7a564cdd9c325bf53d0c4618953b2a2368836441d9006d0f1924156872bdc571676eac4cdb90eb51a51a6207d0be6a00473c722fec4f613e7385ce5a0ab7bac01c1375e3223928dd6d1d09469d4fbae8408191c6a4ce94721b01cf2a6e15679589ae7db7b7cdf90a3d75b66b3c25",
      "SignatureAlgorithmOID": "1.2.840.113549.1.1.5",
      "Subject": "C=US, O=Thawte, Inc., CN=Thawte Code Signing CA , G2",
      "TBS": {
        "MD5": "e3a93dc2a8a8a668fdbb286bfe9afab5",
        "SHA1": "95795d2aa2a554a423bc8c6e5b0a016d14887d35",
        "SHA256": "d8844186775bddbccaf3dc017064df7d760fd4b85c5d07561a3efd7da950f89e",
        "SHA384": "78d972495720b43a6470b18ae1226bcca20707628087717a9364c14ca053ba264e6d149718b103542d9942200138a69d"
      },
      "ValidFrom": "2010-02-08 00:00:00",
      "ValidTo": "2020-02-07 23:59:59",
      "Version": 3
    },
    {
      "IsCertificateAuthority": true,
      "SerialNumber": "611fb0a400000000001d",
      "Signature": "2dcc71b5e8ba94ff5ee64467007b6afc412c3ee70e41855ab12a932ba95b89f2f72b499c8003f297b8e760a80ed7fd5de545467594f4ed1c9de166228b61fb29f2c6a8bdf387c98f7f47e1c058b64a1aa2e7f718606969e083069e26c775c40c0d79da746b52b9fae8ea3359b9bb18dd291a14dfd36a37277a9da0dacffffc22c4faf009ff33e93e17ba1cc742cfce2743d30c0c5581303db96060ce02ece19ee81ddc852ce0a18d966d95ac17a4713ea16741b6281d2ce3b615e5b7e5a2f6256d86e320acf9f8314f8e629b9833376d6af735523e90feb03b5fc5b852a9e06ea0479a279e97aea24a9e531939ec357ec659de3ae0aaf533f06abda0821812dea18c4570ca2bd62e959145995a5c240049bd23b30ceca43df5b9e1d1b1825a38eea3fba1ab483a8c5dffa065223fd3d3fe4990db1446a3852e8a554b09ab38b2ab63a008d1fdad48e273d812bcc26ca516fad09ac05e38383a2b718e553aac42197a1f0d4220e7ab5d8c6880524ca1c0d488d02321fb901309007b4937afa9df486022abf4f6c2363bf8513c34bbc586e43ae19f4b90fe5461024b159c34176aa94b8d4cb69d2326c83af1d6b805cdda1d6240183a2f1b41cd3a993a0aa9d1d77eb8c4aff7b8c980105ed55df6ce7a9a02c50f6381efb564e9fc5bd8d2619a68c37cf9c78df91e87d5fa2cf816ae9dab068fc86dc741cda14e84e3dac26ebcfb",
      "SignatureAlgorithmOID": "1.2.840.113549.1.1.5",
      "Subject": "C=US, O=thawte, Inc., OU=Certification Services Division, OU=(c) 2006 thawte, Inc. , For authorized use only, CN=thawte Primary Root CA",
      "TBS": {
        "MD5": "a3f222107d4e1085e73b5b589c2f480b",
        "SHA1": "b94aa26cd77c48d91a53ac44506cbd255e1d362c",
        "SHA256": "a39ed0d6fd4eb1a6f7fed60f726e23eae668b7591bc004644625d22c701213fa",
        "SHA384": "64b7643e4146016cbf83c911eb67e4601b6bb8d66f8ee8dcee67b815f91770d86ab23678b984430f22a963e5484881b7"
      },
      "ValidFrom": "2011-02-22 19:31:57",
      "ValidTo": "2021-02-22 19:41:57",
      "Version": 3
    },
    {
      "IsCertificateAuthority": true,
      "SerialNumber": "0e9b188ef9d02de7efdb50e20840185a",
      "Signature": "70a0bf435c55e7385fa0a3741b3db616d7f7bf5707bd9aaca1872cec855ea91abb22f8871a695422eda488776dbd1a14f4134a7a2f2db738eff4ff80b9f8a1f7f272de24bc5203c84ed02adefa2d56cff9f4f7ac307a9a8bb25ed4cfd143449b4321eb9672a148b499cb9d4fa7060313772744d4e77fe859a8f0bf2f0ba6e9f2343cecf703c787a8d24c401935466a6954b0b8a1568eeca4d53de8b1dcfd1cd8f4775a5c548c6fefa1503dfc760968849f6fcadb208d35601c0203cb20b0ac58a00e4063c59822c1b259f5556bcf27ab6c76ce6f232df47e716a236b22ff12b8542d277ed83ad9f0b68796fd5bd15cac18c34d9f73b701a99f57aa5e28e2b994",
      "SignatureAlgorithmOID": "1.2.840.113549.1.1.12",
      "Subject": "C=US, O=DigiCert Inc, OU=www.digicert.com, CN=DigiCert Trusted Root G4",
      "TBS": {
        "MD5": "21a266bd49f2778b24d13d95641ea6ac",
        "SHA1": "21319f341fdf06bf6a104427afa8b7823b1ea7f3",
        "SHA256": "e933dc68ee65abd1f9b1aa6738eff60a6895d3d8cc4accf0c69069aa3decd757",
        "SHA384": "11533efd6b326a4e065a936de300fe0586a479f93d569d2403bd62c7ad35f1b2199daee3adb510f429c4fc97b4b024e3"
      },
      "ValidFrom": "2022-08-01 00:00:00",
      "ValidTo": "2031-11-09 23:59:59",
      "Version": 3
    },
    {
      "IsCertificateAuthority": true,
      "SerialNumber": "073637b724547cd847acfd28662a5e5b",
      "Signature": "7d598ec093b66f98a94422017e66d6d82142e1b0182e104d13cf3053cebf18fbc7505de24b29fb708a0daa2969fc69c1cf1d07e93e60c8d80be55c5bd76d87fa842025343167cdb612966fc4504c621d0c0882a816bda956cf15738d012225ce95693f4777fb727414d7ffab4f8a2c7aab85cd435fed60b6aa4f91669e2c9ee08aace5fd8cbc6426876c92bd9d7cd0700a7cefa8bc754fba5af7a910b25de9ff285489f0d58a717665daccf072a323fac0278244ae99271bab241e26c1b7de2aebf69eb1799981a35686ab0a45c9dfc48da0e798fbfba69d72afc4c7c1c16a71d9c6138009c4b69fcd878724bb4fa349b9776691f1729ce94b0252a7377e9353ac3b1d08490f94cd397addff256399272c3d3f6ba7f166c341cd4fb6409b212140d0b71324cddc1d783ae49eade5347192d7266be43873aba6014fbd3f3b78ad4cadfbc4957bed0a5f33398741787a38e99ce1dd23fd1d28d3c7f9e8f1985ffb2bd87ef2469d752c1e272c26db6f157b1e198b36b893d4e6f2179959ca70f037bf9800df20164f27fb606716a166badd55c03a2986b098a02bed9541b73ad5159831b462090f0abd81d913febfa4d1f357d9bc04fa82de32df0489f000cd5dc2f9d0237f000be4760226d9f0657642a6298709472be67f1aa4850ffc9896f655542b1f80fac0f20e2be5d6fba92f44154ae7130e1ddb37381aa12bf6edd67cfc",
      "SignatureAlgorithmOID": "1.2.840.113549.1.1.11",
      "Subject": "C=US, O=DigiCert, Inc., CN=DigiCert Trusted G4 RSA4096 SHA256 TimeStamping CA",
      "TBS": {
        "MD5": "e4b8ad9932ff9205f580cf8fb2afbb86",
        "SHA1": "5301f7044d78bf94dd2b6e4871083a17fdba1dcc",
        "SHA256": "c3d01499a5d1d2f71e0f44e78fbfa4b8aadb43dd4f226401e0c1d7a6d53357fa",
        "SHA384": "84b5f399da5a4f4387269adfd951ef7d2197c29552ed2d2e449060664c3825d6bdb2acc3e563d999e54652f7384f445e"
      },
      "ValidFrom": "2022-03-23 00:00:00",
      "ValidTo": "2037-03-22 23:59:59",
      "Version": 3
    },
    {
      "IsCertificateAuthority": false,
      "SerialNumber": "0544aff3949d0839a6bfdb3f5fe56116",
      "Signature": "811ad6dea0a9b59817bc708d4f8a3c689cd825ffcb2ce4cdea5d2292ec8c2202a9b8cf80a8d9e7e3c5ed26828a712f18dd4eb6de6cd7e1609c2beded3d488eb86bba7c5dbdc26137684977a3eb90aa12d72785f38e1e92dac240389f5dc8a02e2578259d2a057a842998b657798fdb26562bb0f3a7bd370cd898764f56b952c2b69d38a981e76d415c8c69d1b92bc4c67bcf9cfa78e2931a76a26975d350e44412be200d9ea944d0f8e54977085a21c5b4cf98951a54bab9bcc16919bacf16f28337346eb04126ddde5a974f338dd48d777d7545a1a558266a0345ded950b5508caf56bd4cc5e146c528d3ade7430070decc989e198903ead49137ef4d52f3c96021c45647edda114b8c32c388e658e2b6db3ef95fb042d68fe31791d1aac055e386bfac272c41d09a334aa836d4b972967e977938485fcac2dc3d32df75d636675a89f8f6a7c7e54f353c00bdbe9c2a6c7901dcda44e63ade383b075e3958f47c733155a08011cb140c7eaebcfea4eb7965aa68d622ca3beb9a8235572816cb69f2329ab2d2d83ab8b146866bba17fdc4776c156caeabaf733ae84946b7d57fccb638c0d8ec1cf5b6a1b8432cdf4e4c7d1e6870c0770ad402e05c60bb28ff38e5525ad6ac1722234ef4ecd317fb506bff07771f71974441c9b846d36c327c582f674765e51b73b699f96b2c0646ef411ef0f05fe0dbd9ad908044af8010418a",
      "SignatureAlgorithmOID": "1.2.840.113549.1.1.11",
      "Subject": "C=US, O=DigiCert, Inc., CN=DigiCert Timestamp 2023",
      "TBS": {
        "MD5": "7630cbd02cc6732394e9fdfe99d0d8f8",
        "SHA1": "bc1890d694f9d392c4cbae6a174e35d70e7ec8b1",
        "SHA256": "594a02de632b3a08ed6644c36994025e57f35bc8e7bd16cec5d347883390d1d8",
        "SHA384": "31d9fb75262762d17046f31e5c54509f58a295d505e411019544000b64f607b44b3346b708fa50d48f199dba56f0c0b1"
      },
      "ValidFrom": "2023-07-14 00:00:00",
      "ValidTo": "2034-10-13 23:59:59",
      "Version": 3
    }
  ],
  "CertificatesInfo": "",
  "Signer": [
    {
      "Issuer": "C=US, O=Thawte, Inc., CN=Thawte Code Signing CA , G2",
      "SerialNumber": "1cb2d523a6bf7a066642c578de1c9be4",
      "Version": 1
    }
  ],
  "SignerInfo": ""
}
```

{{< /details >}}
-----



[*source*](https://github.com/magicsword-io/LOLDrivers/tree/main/yaml/e7fd8ffc-ab37-4a7b-8dc9-fc7432fbacae.yaml)

*last_updated:* 2025-03-03

{{< /column >}}
{{< /block >}}
