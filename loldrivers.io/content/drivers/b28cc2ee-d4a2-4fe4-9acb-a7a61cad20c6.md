+++

description = ""
title = "b28cc2ee-d4a2-4fe4-9acb-a7a61cad20c6"
weight = 10
displayTitle = "WiseUnlo.sys"
+++


{{< block "grid-1" >}}
{{< column "mt-2 pt-1">}}


# WiseUnlo.sys ![:inline](/images/twitter_verified.png) 

### Description

WiseUnlo.sys is a vulnerable driver and more information will be added as found.
- **UUID**: b28cc2ee-d4a2-4fe4-9acb-a7a61cad20c6
- **Created**: 2023-01-09
- **Author**: Michael Haag
- **Acknowledgement**:  | [](https://twitter.com/)

{{< button "https://github.com/magicsword-io/LOLDrivers/raw/main/drivers/33b3842172f21ba22982bfb6bffbda27.bin" "Download" >}}{{< button "https://www.magicsword.io/premium" "Block" "red" >}}
{{< tip "warning" >}}
This download link contains the vulnerable driver!

{{< /tip >}}

### Commands

```
sc.exe create WiseUnlo.sys binPath=C:\windows\temp\WiseUnlo.sys type=kernel &amp;&amp; sc.exe start WiseUnlo.sys
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
<li><a href="https://learn.microsoft.com/en-us/windows/security/threat-protection/windows-defender-application-control/microsoft-recommended-driver-block-rules">https://learn.microsoft.com/en-us/windows/security/threat-protection/windows-defender-application-control/microsoft-recommended-driver-block-rules</a></li>
<br>


### Known Vulnerable Samples

| Property           | Value |
|:-------------------|:------|
| Filename           |  |
| Creation Timestamp           | 2015-05-11 01:36:47 |
| MD5                | [33b3842172f21ba22982bfb6bffbda27](https://www.virustotal.com/gui/file/33b3842172f21ba22982bfb6bffbda27) |
| SHA1               | [c201d5d0ab945095c3b1a356b3b228af1aa652fc](https://www.virustotal.com/gui/file/c201d5d0ab945095c3b1a356b3b228af1aa652fc) |
| SHA256             | [9d530642aeb6524691d06b9e02a84e3487c9cdd86c264b105035d925c984823a](https://www.virustotal.com/gui/file/9d530642aeb6524691d06b9e02a84e3487c9cdd86c264b105035d925c984823a) |
| Authentihash MD5   | [8df54f216312cc14d959dcb858702b01](https://www.virustotal.com/gui/search/authentihash%253A8df54f216312cc14d959dcb858702b01) |
| Authentihash SHA1  | [7f921e6701f0cc33c6852ab7f79455b9ad9c8eac](https://www.virustotal.com/gui/search/authentihash%253A7f921e6701f0cc33c6852ab7f79455b9ad9c8eac) |
| Authentihash SHA256| [c10c70be4e36fa9c98a4796c2b03db86398e2b07018550b7f0d58edabc553ad2](https://www.virustotal.com/gui/search/authentihash%253Ac10c70be4e36fa9c98a4796c2b03db86398e2b07018550b7f0d58edabc553ad2) |
| RichPEHeaderHash MD5   | [c35062e4107cf5b1678dc60ad794c5bb](https://www.virustotal.com/gui/search/rich_pe_header_hash%253Ac35062e4107cf5b1678dc60ad794c5bb) |
| RichPEHeaderHash SHA1  | [b2bb35d38360088084f26094de08e1ab820c7ac6](https://www.virustotal.com/gui/search/rich_pe_header_hash%253Ab2bb35d38360088084f26094de08e1ab820c7ac6) |
| RichPEHeaderHash SHA256| [d6dff08654727de4a812f75583c88322f68fccfdd9df4f67c49c9484448c3359](https://www.virustotal.com/gui/search/rich_pe_header_hash%253Ad6dff08654727de4a812f75583c88322f68fccfdd9df4f67c49c9484448c3359) |
| Company           | WiseCleaner.com |
| Description       | WiseUnlo |
| Product           | WiseUnlo |
| OriginalFilename  | WiseUnlo.sys |

{{< button "https://github.com/magicsword-io/LOLDrivers/raw/main/drivers/33b3842172f21ba22982bfb6bffbda27.bin" "Download" >}} 

#### Certificates

{{< details "Expand" >}}
###### Certificate 57c76f616cbd9aeb18b22862a09d94dc
| Field                             | Value                      |
|-----------------------------------|----------------------------|
| ToBeSigned (TBS) MD5              | d3b63256734014c7a7f5e01a335af2ac  |
| ToBeSigned (TBS) SHA1             | b7c7ae11be35f9788e341a5b868b4b599b1d6763 |
| ToBeSigned (TBS) SHA256           | 0114225eea0b2816e2fe11ce39f522a5f7a4a0bdd6887016b9671308b6260937 |
| Subject                           | C=CN, ST=BeiJing, L=BeiJing, O=Lespeed Technology Ltd., CN=Lespeed Technology Ltd. |
| ValidFrom                         | 2015-05-07 00:00:00 |
| ValidTo                           | 2017-05-14 23:59:59 |
| Signature                         | a13032767aa0a7cf1bc7a580da80f4d20642b0b4b8160fc23d16d38d05fb4f65e792f2e47e29b3c720e247248144275fb0b63e8cfde47b3e15019edb71e9c59f88f2455bbf111dae971157ac862767d607307491183199c65837c588ca898d4019d0b5cc09c34c73ed5500f4158a5522b7f53d4e334d6af3d69915f55b688f5d8956d7048b19a7cf20c571e79df0e13af35b33796d0bff926814d3e8d984b9228db9b3ef9be929d62a1cca4c1e0c50e5bc8525d5431f0e380a7b46166def3b594ea0f73e2e8bb3f9af2a044ccf888e6b23185047d87fd349ed4a93a9d1a639c4122714c4046b4c6f2eb8cc667ae78ecbee2e477affffcb16f5e4a34a72dc1946 |
| SignatureAlgorithmOID             | 1.2.840.113549.1.1.5 |
| IsCertificateAuthority            | False |
| SerialNumber                      | 57c76f616cbd9aeb18b22862a09d94dc |
| Version                           | 3 |
###### Certificate 611993e400000000001c
| Field                             | Value                      |
|-----------------------------------|----------------------------|
| ToBeSigned (TBS) MD5              | 78a717e082dcc1cda3458d917e677d14  |
| ToBeSigned (TBS) SHA1             | 4a872e0e51f9b304469cd1dedb496ee9b8b983a4 |
| ToBeSigned (TBS) SHA256           | 317fa1d234ebc49040ebc5e8746f8997471496051b185a91bdd9dfbb23fab5f8 |
| Subject                           | C=US, O=VeriSign, Inc., OU=VeriSign Trust Network, OU=(c) 2006 VeriSign, Inc. , For authorized use only, CN=VeriSign Class 3 Public Primary Certification Authority , G5 |
| ValidFrom                         | 2011-02-22 19:25:17 |
| ValidTo                           | 2021-02-22 19:35:17 |
| Signature                         | 812a82168c34672be503eb347b8ca2a3508af45586f11e8c8eae7dee0319ce72951848ad6211fd20fd3f4706015ae2e06f8c152c4e3c6a506c0b36a3cf7a0d9c42bc5cf819d560e369e6e22341678c6883762b8f93a32ab57fbe59fba9c9b2268fcaa2f3821b983e919527978661ee5b5d076bcd86a8e26580a8e215e2b2be23056aba0cf347934daca48c077939c061123a050d89a3ec9f578984fbecca7c47661491d8b60f195de6b84aacbc47c8714396e63220a5dc7786fd3ce38b71db7b9b03fcb71d3264eb1652a043a3fa2ead59924e7cc7f233424838513a7c38c71b242228401e1a461f17db18f7f027356cb863d9cdb9645d2ba55eefc629b4f2c7f821cc04ba57fd01b6abc667f9e7d3997ff4f522fa72f5fdff3a1c423aa1f98018a5ee8d1cd4669e4501feaaeefffb178f30f7f1cd29c59decb5d549003d85b8cbbb933a276a49c030ae66c9f723283276f9a48356c848ce5a96aaa0cc0cc47fb48e97af6de35427c39f86c0d6e473089705dbd054625e0348c2d59f7fa7668cd09db04fd4d3985f4b7ac97fb22952d01280c70f54b61e67cdc6a06c110384d34875e72afeb03b6e0a3aa66b769905a3f177686133144706fc537f52bd92145c4a246a678caf8d90aad0f679211b93267cc3ce1ebd883892ae45c6196a4950b305f8ae59378a6a250394b1598150e8ba8380b72335f476b9671d5918ad208d94 |
| SignatureAlgorithmOID             | 1.2.840.113549.1.1.5 |
| IsCertificateAuthority            | True |
| SerialNumber                      | 611993e400000000001c |
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

{{< /details >}}
#### Imported Functions
{{< details "Expand" >}}
* IoDeleteDevice
* IoDeleteSymbolicLink
* RtlInitUnicodeString
* DbgPrint
* IoCreateFile
* IoFreeIrp
* KeSetEvent
* KeWaitForSingleObject
* IofCallDriver
* KeInitializeEvent
* ObfDereferenceObject
* IoAllocateIrp
* IoGetRelatedDeviceObject
* ObReferenceObjectByHandle
* IoFileObjectType
* RtlAssert
* ZwClose
* IofCompleteRequest
* IoCreateSymbolicLink
* IoCreateDevice

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
* .rsrc

{{< /details >}}
#### Signature
{{< details "Expand" >}}
```
{
  "Certificates": [
    {
      "IsCertificateAuthority": false,
      "SerialNumber": "57c76f616cbd9aeb18b22862a09d94dc",
      "Signature": "a13032767aa0a7cf1bc7a580da80f4d20642b0b4b8160fc23d16d38d05fb4f65e792f2e47e29b3c720e247248144275fb0b63e8cfde47b3e15019edb71e9c59f88f2455bbf111dae971157ac862767d607307491183199c65837c588ca898d4019d0b5cc09c34c73ed5500f4158a5522b7f53d4e334d6af3d69915f55b688f5d8956d7048b19a7cf20c571e79df0e13af35b33796d0bff926814d3e8d984b9228db9b3ef9be929d62a1cca4c1e0c50e5bc8525d5431f0e380a7b46166def3b594ea0f73e2e8bb3f9af2a044ccf888e6b23185047d87fd349ed4a93a9d1a639c4122714c4046b4c6f2eb8cc667ae78ecbee2e477affffcb16f5e4a34a72dc1946",
      "SignatureAlgorithmOID": "1.2.840.113549.1.1.5",
      "Subject": "C=CN, ST=BeiJing, L=BeiJing, O=Lespeed Technology Ltd., CN=Lespeed Technology Ltd.",
      "TBS": {
        "MD5": "d3b63256734014c7a7f5e01a335af2ac",
        "SHA1": "b7c7ae11be35f9788e341a5b868b4b599b1d6763",
        "SHA256": "0114225eea0b2816e2fe11ce39f522a5f7a4a0bdd6887016b9671308b6260937",
        "SHA384": "38204a5ba53242499ba3fdd8579117d1a666070a872ecba8a05bc00a977b8c3ebfd0edb1148e2546f3f7dcfaf15d04d2"
      },
      "ValidFrom": "2015-05-07 00:00:00",
      "ValidTo": "2017-05-14 23:59:59",
      "Version": 3
    },
    {
      "IsCertificateAuthority": true,
      "SerialNumber": "611993e400000000001c",
      "Signature": "812a82168c34672be503eb347b8ca2a3508af45586f11e8c8eae7dee0319ce72951848ad6211fd20fd3f4706015ae2e06f8c152c4e3c6a506c0b36a3cf7a0d9c42bc5cf819d560e369e6e22341678c6883762b8f93a32ab57fbe59fba9c9b2268fcaa2f3821b983e919527978661ee5b5d076bcd86a8e26580a8e215e2b2be23056aba0cf347934daca48c077939c061123a050d89a3ec9f578984fbecca7c47661491d8b60f195de6b84aacbc47c8714396e63220a5dc7786fd3ce38b71db7b9b03fcb71d3264eb1652a043a3fa2ead59924e7cc7f233424838513a7c38c71b242228401e1a461f17db18f7f027356cb863d9cdb9645d2ba55eefc629b4f2c7f821cc04ba57fd01b6abc667f9e7d3997ff4f522fa72f5fdff3a1c423aa1f98018a5ee8d1cd4669e4501feaaeefffb178f30f7f1cd29c59decb5d549003d85b8cbbb933a276a49c030ae66c9f723283276f9a48356c848ce5a96aaa0cc0cc47fb48e97af6de35427c39f86c0d6e473089705dbd054625e0348c2d59f7fa7668cd09db04fd4d3985f4b7ac97fb22952d01280c70f54b61e67cdc6a06c110384d34875e72afeb03b6e0a3aa66b769905a3f177686133144706fc537f52bd92145c4a246a678caf8d90aad0f679211b93267cc3ce1ebd883892ae45c6196a4950b305f8ae59378a6a250394b1598150e8ba8380b72335f476b9671d5918ad208d94",
      "SignatureAlgorithmOID": "1.2.840.113549.1.1.5",
      "Subject": "C=US, O=VeriSign, Inc., OU=VeriSign Trust Network, OU=(c) 2006 VeriSign, Inc. , For authorized use only, CN=VeriSign Class 3 Public Primary Certification Authority , G5",
      "TBS": {
        "MD5": "78a717e082dcc1cda3458d917e677d14",
        "SHA1": "4a872e0e51f9b304469cd1dedb496ee9b8b983a4",
        "SHA256": "317fa1d234ebc49040ebc5e8746f8997471496051b185a91bdd9dfbb23fab5f8",
        "SHA384": "b71052da4eb9157c8c1a5d7f55df19d69b9128598b72fcca608e5b7cc7d64c43c5504b9c86355a6dc22ee40c88cc385c"
      },
      "ValidFrom": "2011-02-22 19:25:17",
      "ValidTo": "2021-02-22 19:35:17",
      "Version": 3
    },
    {
      "IsCertificateAuthority": true,
      "SerialNumber": "5200e5aa2556fc1a86ed96c9d44b33c7",
      "Signature": "5622e634a4c461cb48b901ad56a8640fd98c91c4bbcc0ce5ad7aa0227fdf47384a2d6cd17f711a7cec70a9b1f04fe40f0c53fa155efe749849248581261c911447b04c638cbba134d4c645e80d85267303d0a98c646ddc7192e645056015595139fc58146bfed4a4ed796b080c4172e737220609be23e93f449a1ee9619dccb1905cfc3dd28dac423d6536d4b43d40288f9b10cf2326cc4b20cb901f5d8c4c34ca3cd8e537d66fa520bd34eb26d9ae0de7c59af7a1b42191336f86e858bb257c740e58fe751b633fce317c9b8f1b969ec55376845b9cad91faaced93ba5dc82153c2825363af120d5087111b3d5452968a2c9c3d921a089a052ec793a54891d3",
      "SignatureAlgorithmOID": "1.2.840.113549.1.1.5",
      "Subject": "C=US, O=VeriSign, Inc., OU=VeriSign Trust Network, OU=Terms of use at https://www.verisign.com/rpa (c)10, CN=VeriSign Class 3 Code Signing 2010 CA",
      "TBS": {
        "MD5": "b30c31a572b0409383ed3fbe17e56e81",
        "SHA1": "4843a82ed3b1f2bfbee9671960e1940c942f688d",
        "SHA256": "03cda47a6e654ed85d932714fc09ce4874600eda29ec6628cfbaeb155cab78c9",
        "SHA384": "bbda8407c4f9fc4e54d772f1c7fb9d30bc97e1f97ecd51c443063d1fa0644e266328781776cd5c44896c457c75f4d7da"
      },
      "ValidFrom": "2010-02-08 00:00:00",
      "ValidTo": "2020-02-07 23:59:59",
      "Version": 3
    }
  ],
  "CertificatesInfo": "",
  "Signer": [
    {
      "Issuer": "C=US, O=VeriSign, Inc., OU=VeriSign Trust Network, OU=Terms of use at https://www.verisign.com/rpa (c)10, CN=VeriSign Class 3 Code Signing 2010 CA",
      "SerialNumber": "57c76f616cbd9aeb18b22862a09d94dc",
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
| Creation Timestamp           | 2017-06-29 01:22:02 |
| MD5                | [e626956c883c7ff3aeb0414570135a58](https://www.virustotal.com/gui/file/e626956c883c7ff3aeb0414570135a58) |
| SHA1               | [70bb3b831880e058524735b14f2a0f1a72916a4c](https://www.virustotal.com/gui/file/70bb3b831880e058524735b14f2a0f1a72916a4c) |
| SHA256             | [786f0ba14567a7e19192645ad4e40bee6df259abf2fbdfda35b6a38f8493d6cc](https://www.virustotal.com/gui/file/786f0ba14567a7e19192645ad4e40bee6df259abf2fbdfda35b6a38f8493d6cc) |
| Authentihash MD5   | [4e4d97955557f085f4e1fe4cbba82321](https://www.virustotal.com/gui/search/authentihash%253A4e4d97955557f085f4e1fe4cbba82321) |
| Authentihash SHA1  | [131a7703dbaf36bcf7034e8690a7046e9eb52d2b](https://www.virustotal.com/gui/search/authentihash%253A131a7703dbaf36bcf7034e8690a7046e9eb52d2b) |
| Authentihash SHA256| [8a844a8d993db0ee1159b096aee959e32bb9155edd9167b1e6aad2e4019202dd](https://www.virustotal.com/gui/search/authentihash%253A8a844a8d993db0ee1159b096aee959e32bb9155edd9167b1e6aad2e4019202dd) |
| RichPEHeaderHash MD5   | [90cb984cab66f2e7b36cce65ed28b399](https://www.virustotal.com/gui/search/rich_pe_header_hash%253A90cb984cab66f2e7b36cce65ed28b399) |
| RichPEHeaderHash SHA1  | [72b29313b8c3e72489d006710e4f341b9dd15f24](https://www.virustotal.com/gui/search/rich_pe_header_hash%253A72b29313b8c3e72489d006710e4f341b9dd15f24) |
| RichPEHeaderHash SHA256| [c882845cce4f8b835749bf56874a8a88d627bd1b225cb03363005b84f8e6c00b](https://www.virustotal.com/gui/search/rich_pe_header_hash%253Ac882845cce4f8b835749bf56874a8a88d627bd1b225cb03363005b84f8e6c00b) |
| Company           | WiseCleaner.com |
| Description       | WiseUnlo |
| Product           | WiseUnlo |
| OriginalFilename  | WiseUnlo.sys |

{{< button "https://github.com/magicsword-io/LOLDrivers/raw/main/drivers/e626956c883c7ff3aeb0414570135a58.bin" "Download" >}} 

#### Certificates

{{< details "Expand" >}}
###### Certificate 6dd472eb02ae0406e3dd843f5fe145e1
| Field                             | Value                      |
|-----------------------------------|----------------------------|
| ToBeSigned (TBS) MD5              | e3898a5cae592360ce7bfdf5ff3fb13f  |
| ToBeSigned (TBS) SHA1             | 217c51b90dbb7f0528e8ba170d227f647fbc995b |
| ToBeSigned (TBS) SHA256           | 3a9b4006a9e125b4458344389c86dfb4f6728848b9871654c615a138514d02ec |
| Subject                           | C=GB, ST=Greater Manchester, L=Salford, O=COMODO CA Limited, CN=COMODO RSA Extended Validation Code Signing CA |
| ValidFrom                         | 2014-12-03 00:00:00 |
| ValidTo                           | 2029-12-02 23:59:59 |
| Signature                         | 664eecb716776f11e81b5d6a4ed9f28b6cb15628408bc031c49948233df80ee88097ef6d200b1f13c486fb173415e18e54f7c2b8007315e028d9dabafa8254c2f7ebbfc336d0309fe5a11c94dfef7ce8f62c78a2accf266a15a11531d6313498bd534fc48483a3c4965c3dd8fed6f954ff67936df83e2b6b2ca2087c5648813218b26eac90c1dbe4de398b86e5c7184059a4df9647bab27fb1f8570f858074380e3a58621efe52e3e6ae530986fe8f9bdb5656cc07b089c104f1530b6c6f77ecb21fecf65b4043600f1bab1854b410048ef80ee9cb83b17af2344e6a544ce9832ae9b030251cce628e0eeb85e629feb14ae3f2ae3c91f54ca1bec8170e5cbb424de31a8a92cd3e207edde975b1ea1f745c9e54c29437b261dd0716597f968016e099b5d26eb0c9230615acd123f4338bce75f0c186d3ffe12efa904ffe46f9bbdb4fbbb7fed10d2b04f1d2d195852c8a2eb88556f2c38452a1e933b1eb50c8a1b09fe3c38b3a879ee755d3d36d3417300d68220bd5b9ed733572c3eda737cde343ae45cd34bf28ca8762ed43a4affacb31cb215861465eb6c67aa61e532aa8f85c511f3a5a100f28c0e4748b74c604aaf84b26280a3289db9d2a60716ac3964e16b963bf6195678c4b2ebbb04e83e94d31e58e2722f53c267b4491d3d45af0d37cf438be149a990e8bb15beae48b0f119d7742821c5c3ad4daab882f8d573054 |
| SignatureAlgorithmOID             | 1.2.840.113549.1.1.12 |
| IsCertificateAuthority            | True |
| SerialNumber                      | 6dd472eb02ae0406e3dd843f5fe145e1 |
| Version                           | 3 |
###### Certificate 61185486000000000024
| Field                             | Value                      |
|-----------------------------------|----------------------------|
| ToBeSigned (TBS) MD5              | ad73330abdd8883ba17ac2572100221e  |
| ToBeSigned (TBS) SHA1             | 3770402ce3d71f9823386167aa35a7c862f409d3 |
| ToBeSigned (TBS) SHA256           | 04bc415adcb4ef7df32b9dfe199d92a4078cbd132fd5173961211e7f75385491 |
| Subject                           | C=GB, ST=Greater Manchester, L=Salford, O=COMODO CA Limited, CN=COMODO RSA Certification Authority |
| ValidFrom                         | 2011-04-11 22:06:20 |
| ValidTo                           | 2021-04-11 22:16:20 |
| Signature                         | 81980792fe6f325fd9d24bf57dd971e0fdfc169205b4ce67f5cc4bd4c7109854fa521b48582f73bf19d937a0ad33f351052379d9b277648aebbdc3b39db7b1e637d1d2597e41d98fb314ab15774d6cda40245bb207b8582c4b0c2b5351b3df2eb976ac69c9c2ed64377b8d217accdc9fbc172804cc2547242a85cc56e639398775181f46f6910faa46fa4de64754e2322c76eefbcdbd62e1962429064b0cfe344ae9101d74e57a2f954bcc6ebafdd7355f91e45942defb008e08f151512d62258415081911864061d52553232c297738cc58d38c5fbc19b866064c6310dbb2ac306c16bc8bbcd21bc603131546a550f49a9684bb721038db519ad4c55327cbbf28159e086b3d3f4cc00c911cbf19848b3751a0199d8555c55da56479ef10a5ebf4231cda6fe32e7d17b037761f4d8dc102411f363e067bc5b7602d416251dedde4512da7de81f4c3e0e0e9c31680dd9c497d17cfcb556307d66952f4a49d248dbe1bc98099874548cb49c5ed703500267ca70f7532f7ed088ff0bca560a022d5331efbe5022c95a607f4be14de704c8ea97e41dea9d95064866f9424f7abf683955d0d45d18c238c030a13e40eb943030a4367b3107446e46dbd65de4541867072040bbaddba591f571393b00bedb1144169d3090459c7368e7db64b9df120fcd0f18bbd68ca3eb131cf43d066f5a3ddafb1dcc3178cfa3128c73e4927ab6a1b |
| SignatureAlgorithmOID             | 1.2.840.113549.1.1.5 |
| IsCertificateAuthority            | True |
| SerialNumber                      | 61185486000000000024 |
| Version                           | 3 |
###### Certificate 2e4a279bde2eb688e8ab30f5904fa875
| Field                             | Value                      |
|-----------------------------------|----------------------------|
| ToBeSigned (TBS) MD5              | 99de6e0504f17e876cb9d36fc42080c4  |
| ToBeSigned (TBS) SHA1             | dd527101c981e893497468a612193e679a2a53d6 |
| ToBeSigned (TBS) SHA256           | d17e9d0bab1868e8d3e98517951899c58c639fd37ce9be228caf626ee91a1e5f |
| Subject                           | serialNumber=91110101593898951F, ??=CN, ??=Private Organization, C=CN, postalCode=100028, ST=Beijing Shi, L=Beijing, ??=Chaoyang District, ??=Room 1610, Haocheng Building, No.9 Building, No.6 Courtyard, Zuojiazhuang Middle Street, O=Lespeed Technology Co., Ltd, CN=Lespeed Technology Co., Ltd |
| ValidFrom                         | 2020-07-09 00:00:00 |
| ValidTo                           | 2023-07-09 23:59:59 |
| Signature                         | 0813de16aad5aae2206ec189ee90af05a8a8b9d096e6812c419f8a6320ea5936e3089eb2abf2022a5e946464d9a3cb09d0b041ce8dd90c37d791f5e3fdafa755ad2fd7fbd7da760fa4bbaeba655509ad015c5f37df20229360fb596ebb7a91b644f7a86ef28c4f8d16debe8666f4d6ebefd7d4a4d5d8c3b96d36c54ebc0386ae680dd469dc252893eca2fba6929f4e589974cf6cb1d33fa8270b67d606dc4118ee320a1cb2894a7ea655dbf42f9ef9c2e204a736a62e326ef85afad054c8f38506b050580120383f3136b33f8f6160bddabbe9cdc3c9d130d2915a5987951d7237bb2480172bb326256efa866a88f4e4432b844a69892ea38c560dde939f18d7 |
| SignatureAlgorithmOID             | 1.2.840.113549.1.1.11 |
| IsCertificateAuthority            | False |
| SerialNumber                      | 2e4a279bde2eb688e8ab30f5904fa875 |
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
* IoDeleteDevice
* KeSetEvent
* IoCreateFile
* KeInitializeEvent
* IoFileObjectType
* KeGetCurrentThread
* ZwClose
* IofCompleteRequest
* IoGetRelatedDeviceObject
* KeWaitForSingleObject
* IoFreeIrp
* IoAllocateIrp
* IoCreateSymbolicLink
* ObfDereferenceObject
* IoCreateDevice
* DbgPrint
* IofCallDriver
* ObReferenceObjectByHandle
* IoDeleteSymbolicLink
* KeGetCurrentIrql

{{< /details >}}
#### Exported Functions
{{< details "Expand" >}}

{{< /details >}}

#### Sections
{{< details "Expand" >}}
* .text
* .rdata
* INIT
* .rsrc
* .reloc

{{< /details >}}
#### Signature
{{< details "Expand" >}}
```
{
  "Certificates": [
    {
      "IsCertificateAuthority": false,
      "SerialNumber": "57c76f616cbd9aeb18b22862a09d94dc",
      "Signature": "a13032767aa0a7cf1bc7a580da80f4d20642b0b4b8160fc23d16d38d05fb4f65e792f2e47e29b3c720e247248144275fb0b63e8cfde47b3e15019edb71e9c59f88f2455bbf111dae971157ac862767d607307491183199c65837c588ca898d4019d0b5cc09c34c73ed5500f4158a5522b7f53d4e334d6af3d69915f55b688f5d8956d7048b19a7cf20c571e79df0e13af35b33796d0bff926814d3e8d984b9228db9b3ef9be929d62a1cca4c1e0c50e5bc8525d5431f0e380a7b46166def3b594ea0f73e2e8bb3f9af2a044ccf888e6b23185047d87fd349ed4a93a9d1a639c4122714c4046b4c6f2eb8cc667ae78ecbee2e477affffcb16f5e4a34a72dc1946",
      "SignatureAlgorithmOID": "1.2.840.113549.1.1.5",
      "Subject": "C=CN, ST=BeiJing, L=BeiJing, O=Lespeed Technology Ltd., CN=Lespeed Technology Ltd.",
      "TBS": {
        "MD5": "d3b63256734014c7a7f5e01a335af2ac",
        "SHA1": "b7c7ae11be35f9788e341a5b868b4b599b1d6763",
        "SHA256": "0114225eea0b2816e2fe11ce39f522a5f7a4a0bdd6887016b9671308b6260937",
        "SHA384": "38204a5ba53242499ba3fdd8579117d1a666070a872ecba8a05bc00a977b8c3ebfd0edb1148e2546f3f7dcfaf15d04d2"
      },
      "ValidFrom": "2015-05-07 00:00:00",
      "ValidTo": "2017-05-14 23:59:59",
      "Version": 3
    },
    {
      "IsCertificateAuthority": true,
      "SerialNumber": "611993e400000000001c",
      "Signature": "812a82168c34672be503eb347b8ca2a3508af45586f11e8c8eae7dee0319ce72951848ad6211fd20fd3f4706015ae2e06f8c152c4e3c6a506c0b36a3cf7a0d9c42bc5cf819d560e369e6e22341678c6883762b8f93a32ab57fbe59fba9c9b2268fcaa2f3821b983e919527978661ee5b5d076bcd86a8e26580a8e215e2b2be23056aba0cf347934daca48c077939c061123a050d89a3ec9f578984fbecca7c47661491d8b60f195de6b84aacbc47c8714396e63220a5dc7786fd3ce38b71db7b9b03fcb71d3264eb1652a043a3fa2ead59924e7cc7f233424838513a7c38c71b242228401e1a461f17db18f7f027356cb863d9cdb9645d2ba55eefc629b4f2c7f821cc04ba57fd01b6abc667f9e7d3997ff4f522fa72f5fdff3a1c423aa1f98018a5ee8d1cd4669e4501feaaeefffb178f30f7f1cd29c59decb5d549003d85b8cbbb933a276a49c030ae66c9f723283276f9a48356c848ce5a96aaa0cc0cc47fb48e97af6de35427c39f86c0d6e473089705dbd054625e0348c2d59f7fa7668cd09db04fd4d3985f4b7ac97fb22952d01280c70f54b61e67cdc6a06c110384d34875e72afeb03b6e0a3aa66b769905a3f177686133144706fc537f52bd92145c4a246a678caf8d90aad0f679211b93267cc3ce1ebd883892ae45c6196a4950b305f8ae59378a6a250394b1598150e8ba8380b72335f476b9671d5918ad208d94",
      "SignatureAlgorithmOID": "1.2.840.113549.1.1.5",
      "Subject": "C=US, O=VeriSign, Inc., OU=VeriSign Trust Network, OU=(c) 2006 VeriSign, Inc. , For authorized use only, CN=VeriSign Class 3 Public Primary Certification Authority , G5",
      "TBS": {
        "MD5": "78a717e082dcc1cda3458d917e677d14",
        "SHA1": "4a872e0e51f9b304469cd1dedb496ee9b8b983a4",
        "SHA256": "317fa1d234ebc49040ebc5e8746f8997471496051b185a91bdd9dfbb23fab5f8",
        "SHA384": "b71052da4eb9157c8c1a5d7f55df19d69b9128598b72fcca608e5b7cc7d64c43c5504b9c86355a6dc22ee40c88cc385c"
      },
      "ValidFrom": "2011-02-22 19:25:17",
      "ValidTo": "2021-02-22 19:35:17",
      "Version": 3
    },
    {
      "IsCertificateAuthority": true,
      "SerialNumber": "5200e5aa2556fc1a86ed96c9d44b33c7",
      "Signature": "5622e634a4c461cb48b901ad56a8640fd98c91c4bbcc0ce5ad7aa0227fdf47384a2d6cd17f711a7cec70a9b1f04fe40f0c53fa155efe749849248581261c911447b04c638cbba134d4c645e80d85267303d0a98c646ddc7192e645056015595139fc58146bfed4a4ed796b080c4172e737220609be23e93f449a1ee9619dccb1905cfc3dd28dac423d6536d4b43d40288f9b10cf2326cc4b20cb901f5d8c4c34ca3cd8e537d66fa520bd34eb26d9ae0de7c59af7a1b42191336f86e858bb257c740e58fe751b633fce317c9b8f1b969ec55376845b9cad91faaced93ba5dc82153c2825363af120d5087111b3d5452968a2c9c3d921a089a052ec793a54891d3",
      "SignatureAlgorithmOID": "1.2.840.113549.1.1.5",
      "Subject": "C=US, O=VeriSign, Inc., OU=VeriSign Trust Network, OU=Terms of use at https://www.verisign.com/rpa (c)10, CN=VeriSign Class 3 Code Signing 2010 CA",
      "TBS": {
        "MD5": "b30c31a572b0409383ed3fbe17e56e81",
        "SHA1": "4843a82ed3b1f2bfbee9671960e1940c942f688d",
        "SHA256": "03cda47a6e654ed85d932714fc09ce4874600eda29ec6628cfbaeb155cab78c9",
        "SHA384": "bbda8407c4f9fc4e54d772f1c7fb9d30bc97e1f97ecd51c443063d1fa0644e266328781776cd5c44896c457c75f4d7da"
      },
      "ValidFrom": "2010-02-08 00:00:00",
      "ValidTo": "2020-02-07 23:59:59",
      "Version": 3
    }
  ],
  "CertificatesInfo": "",
  "Signer": [
    {
      "Issuer": "C=US, O=VeriSign, Inc., OU=VeriSign Trust Network, OU=Terms of use at https://www.verisign.com/rpa (c)10, CN=VeriSign Class 3 Code Signing 2010 CA",
      "SerialNumber": "57c76f616cbd9aeb18b22862a09d94dc",
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
| Creation Timestamp           | 2017-06-29 01:21:54 |
| MD5                | [9e0af1fe4d6dd2ca4721810ed1c930d6](https://www.virustotal.com/gui/file/9e0af1fe4d6dd2ca4721810ed1c930d6) |
| SHA1               | [5b4619596c89ed17ccbe92fd5c0a823033f2f1e1](https://www.virustotal.com/gui/file/5b4619596c89ed17ccbe92fd5c0a823033f2f1e1) |
| SHA256             | [48b1344e45e4de4dfb74ef918af5e0e403001c9061018e703261bbd72dc30548](https://www.virustotal.com/gui/file/48b1344e45e4de4dfb74ef918af5e0e403001c9061018e703261bbd72dc30548) |
| Authentihash MD5   | [6d1e6e5682f9a5e8a64dc8d2ec6ddfac](https://www.virustotal.com/gui/search/authentihash%253A6d1e6e5682f9a5e8a64dc8d2ec6ddfac) |
| Authentihash SHA1  | [49fb554b77c8d533e4a1ff30bbc60ef7f80b7055](https://www.virustotal.com/gui/search/authentihash%253A49fb554b77c8d533e4a1ff30bbc60ef7f80b7055) |
| Authentihash SHA256| [c36ace67f4e25f391e8709776348397e4fd3930e641b32c1b0da398e59199ca7](https://www.virustotal.com/gui/search/authentihash%253Ac36ace67f4e25f391e8709776348397e4fd3930e641b32c1b0da398e59199ca7) |
| RichPEHeaderHash MD5   | [8d3c5247eb754073fa6215b4e6b75923](https://www.virustotal.com/gui/search/rich_pe_header_hash%253A8d3c5247eb754073fa6215b4e6b75923) |
| RichPEHeaderHash SHA1  | [2810d5abd81048f341ced0b06c0d974c39795cce](https://www.virustotal.com/gui/search/rich_pe_header_hash%253A2810d5abd81048f341ced0b06c0d974c39795cce) |
| RichPEHeaderHash SHA256| [379e3e6bf0f81d613c578c7131d36935edbf8d462638cdd4a1dc6787444af023](https://www.virustotal.com/gui/search/rich_pe_header_hash%253A379e3e6bf0f81d613c578c7131d36935edbf8d462638cdd4a1dc6787444af023) |
| Company           | WiseCleaner.com |
| Description       | WiseUnlo |
| Product           | WiseUnlo |
| OriginalFilename  | WiseUnlo.sys |

{{< button "https://github.com/magicsword-io/LOLDrivers/raw/main/drivers/9e0af1fe4d6dd2ca4721810ed1c930d6.bin" "Download" >}} 

#### Certificates

{{< details "Expand" >}}
###### Certificate 61204db4000000000027
| Field                             | Value                      |
|-----------------------------------|----------------------------|
| ToBeSigned (TBS) MD5              | 8e3ffc222fbcebdbb8b23115ab259be7  |
| ToBeSigned (TBS) SHA1             | ee20bff28ffe13be731c294c90d6ded5aae0ec0e |
| ToBeSigned (TBS) SHA256           | 59826b69bc8c28118c96323b627da59aaca0b142cc5d8bad25a8fcfd399aa821 |
| Subject                           | C=US, O=DigiCert Inc, OU=www.digicert.com, CN=DigiCert High Assurance EV Root CA |
| ValidFrom                         | 2011-04-15 19:45:33 |
| ValidTo                           | 2021-04-15 19:55:33 |
| Signature                         | 208cc159ed6f9c6b2dc14a3e751d454c41501cbd80ead9b0928b062a133f53169e56396a8a63b6782479f57db8b947a10a96c2f6cbbda2669f06e1acd279090efd3cdcac020c70af3f1bec787ed4eb4b056026d973619121edb06863e09712ab6fa012edd99fd2da273cb3e456f9d1d4810f71bd427ca689dccdd5bd95a2abf193117de8ac3129a85d6670419dfc75c9d5b31a392ad08505508bac91cac493cb71a59da4946f580cfa6e20c40831b5859d7e81f9d23dca5b18856c0a86ec22091ba574344f7f28bc954aab1db698b05d09a477767eefa78e5d84f61824cbd16da6c3a19cc2107580ff9d32fde6cf433a82f7ce8fe1722a9b62b75fed951a395c2f946d48b7015f332fbbdc2d73348904420a1c8b79f9a3fa17effaa11a10dfe0b2c195eb5c0c05973b353e18884ddb6cbf24898dc8bdd89f7b393a24a0d5dfd1f34a1a97f6a66f7a1fb090a9b3ac013991d361b764f13e573803afce7ad2b590f5aedc3999d5b63c97eda6cb16c77d6b2a4c9094e64c54fd1ecd20ecce689c8758e96160beeb0ec9d5197d9fe978bd0eac2175078fa96ee08c6a2a6b9ce3e765bcbc2d3c6ddc04dc67453632af0481bca8006e614c95c55cd48e8e9f2fc13274bdbd11650307cdefb75e0257da86d41a2834af8849b2cfa5dd82566f68aa14e25954feffeaeeefea9270226081e32523c09fcc0f49b235aa58c33ac3d9169410 |
| SignatureAlgorithmOID             | 1.2.840.113549.1.1.5 |
| IsCertificateAuthority            | True |
| SerialNumber                      | 61204db4000000000027 |
| Version                           | 3 |
###### Certificate 0b847f536116fd6d5a31dbf8f6ad8aa1
| Field                             | Value                      |
|-----------------------------------|----------------------------|
| ToBeSigned (TBS) MD5              | c4a1cd15e009d0791fdb4d9e3612c0b7  |
| ToBeSigned (TBS) SHA1             | 64d8e05d4deddf634440d1e326aacfb4e06c9a0b |
| ToBeSigned (TBS) SHA256           | d34c5ac9e993a225771de09bbcf963e629669168ca2f57c2a0d0b91f0bb511c2 |
| Subject                           | ??=Private Organization, ??=CN, ??=Beijing, serialNumber=91110101593898951F, ??=Chaoyang District, ??=103, Unit C, Building 8, Yard 6, Zuojiazhuang Street, postalCode=100028, C=CN, ST=Beijing, L=Beijing, O=Beijing Lang Xingda Network Technology Co., Ltd, CN=Beijing Lang Xingda Network Technology Co., Ltd |
| ValidFrom                         | 2017-06-16 00:00:00 |
| ValidTo                           | 2019-12-31 12:00:00 |
| Signature                         | 036aa0d600d0e810dc9b7b5b6cb97acc0b21792e351c21236bd4f67a88c232ecde9e6fcd99c2933c5d4f24cb8ad45e6e39547a8a9df084ac43a89cb017cccda9430d89b932c5a8c8c3d1e7ebf997408739bd63d23d52b24bbd72bf3a4ad05363bb5515795ffc9d6328309273587abe0d5c4b60edb85e8ce73ba5caa6b0a1bf597e9691910cc996344537234eee6c64af497f1b29c4432e38d978d7f45822ef88ecd5462752beb2619ba4cbf88eb4be5b8ac2ba19eed2265ee342980ad7fb4f9767487867ce1d6f7f6d6ad0ce642879781ee23ef8e932fae775e511c2e4f07c5e60cf9d8362362cba51c61ff59f352cf8368c000ee3aa8c7a57dc7f3c7dd5a10a |
| SignatureAlgorithmOID             | 1.2.840.113549.1.1.5 |
| IsCertificateAuthority            | False |
| SerialNumber                      | 0b847f536116fd6d5a31dbf8f6ad8aa1 |
| Version                           | 3 |
###### Certificate 03019a023aff58b16bd6d5eae617f066
| Field                             | Value                      |
|-----------------------------------|----------------------------|
| ToBeSigned (TBS) MD5              | a752afee44f017e8d74e3f3eb7914ae3  |
| ToBeSigned (TBS) SHA1             | 8eca80a6b80e9c69dcef7745748524afb8019e2d |
| ToBeSigned (TBS) SHA256           | 82560fa7efec30b5ff82af643e6f3bf3d46868bbd5e7d76f93db185e9e3553a1 |
| Subject                           | C=US, O=DigiCert, CN=DigiCert Timestamp Responder |
| ValidFrom                         | 2014-10-22 00:00:00 |
| ValidTo                           | 2024-10-22 00:00:00 |
| Signature                         | 9d257e1b334db226815c9b86ce23200f8087e588ffffb1d46a2c31ed3a17197117cda91bbc5a1639009de36c84e45a40fbde06018c37fa9bb19d247efe20a457ad5bb79ab06026ea6957215d342f1f71b0839419056b359010a07b97c7f63fe7e21141a6bd62d9f0273d381d286f3a5209f0ec7062d3624bb0e073a692c0d38e31d82fe36d171306eee403b614abf38f43a7719d21dd14ca155d9241daf90f81d199740d26c40e7f1bb5f5a0f1c677062815e9d893e55516f0bb0aab1cdb5c482766c8a38b0a1ce595daaec42e59a061dddaf36da261e98a0b6dec1218bdf755544003922b6bc251c20a48afb0d46ee0f4140a3a1be38f3dcaaf6a8d7bdcd844 |
| SignatureAlgorithmOID             | 1.2.840.113549.1.1.5 |
| IsCertificateAuthority            | False |
| SerialNumber                      | 03019a023aff58b16bd6d5eae617f066 |
| Version                           | 3 |
###### Certificate 0dd0e3374ac95bdbfa6b434b2a48ec06
| Field                             | Value                      |
|-----------------------------------|----------------------------|
| ToBeSigned (TBS) MD5              | f92649915476229b093c211c2b18e6c4  |
| ToBeSigned (TBS) SHA1             | 2d54c16a8f8b69ccdea48d0603c132f547a5cf75 |
| ToBeSigned (TBS) SHA256           | 2cd702a7dec30aa441345672e8992ef9770ce4946f276d767b45b0ed627658fb |
| Subject                           | C=US, O=DigiCert Inc, OU=www.digicert.com, CN=DigiCert EV Code Signing CA |
| ValidFrom                         | 2012-04-18 12:00:00 |
| ValidTo                           | 2027-04-18 12:00:00 |
| Signature                         | 9e5b963a2e1288acab016da49f75e40187a3a532d7bcbaa97ea3d61417f7c2136b7c738f2b6ae50f265968b08e259b6ceffa6c939208c14dcf459e9c46d61e74a19b14a3fa012f4ab101e1724048111368b9369d914bd7c2391210c1c4dcbb6214142a615d4f387c661fc61bffadbe4f7f945b7343000f4d73b751cf0ef677c05bcd348cd96313aa0e6111d6f28e27fcb47bb8b91120918678ea0ed428ff2ad52438e837b2ec96bb9fbc4a1650e15ebf517d23a032c7c1949e7ac9c026a2cc2587a0127e749f2d8db1c8e784beb9d1e9debb6a4e887371e12238cb2487e9737e51b2ff98eb4e7e2fe0ca0efab35ed1ba0542a8489f83f63fc4caa8df68a05061 |
| SignatureAlgorithmOID             | 1.2.840.113549.1.1.5 |
| IsCertificateAuthority            | True |
| SerialNumber                      | 0dd0e3374ac95bdbfa6b434b2a48ec06 |
| Version                           | 3 |
###### Certificate 06fdf9039603adea000aeb3f27bbba1b
| Field                             | Value                      |
|-----------------------------------|----------------------------|
| ToBeSigned (TBS) MD5              | 4e5ad189638cf52ba9cd881d4d44668c  |
| ToBeSigned (TBS) SHA1             | cdc115e98d798b33904c820d63cc1e1afc19251d |
| ToBeSigned (TBS) SHA256           | 37560fb9d548ab62cc3ed4669a4ab74828b5a108e67e829937ffb2d10a5f78dd |
| Subject                           | C=US, O=DigiCert Inc, OU=www.digicert.com, CN=DigiCert Assured ID CA,1 |
| ValidFrom                         | 2006-11-10 00:00:00 |
| ValidTo                           | 2021-11-10 00:00:00 |
| Signature                         | 46503ec9b72824a7381db65b29af52cf52e93147ab565c7bd50d0b41b3efec751f7438f2b25c61a29c95c350e482b923d1ba3a8672ad3878ac755d1717347247859456d1ebbb368477cc24a5f3041955a9e7e3e7ab62cdfb8b2d90c2c0d2b594bd5e4fb105d20e3d1aa9145ba6863162a8a833e49b39a7c4f5ce1d7876942573e42aabcf9c764bed5fc24b16e44b704c00891efcc579bc4c1257fe5fe11ebc025da8fefb07384f0dc65d91b90f6745cdd683ede7920d8db1698c4ffb59e0230fd2aaae007cee9c420ecf91d727b716ee0fc3bd7c0aa0ee2c08558522b8eb181a4dfc2a21ad49318347957771dcb11b4b4b1c109c7714c19d4f2f5a9508291026 |
| SignatureAlgorithmOID             | 1.2.840.113549.1.1.5 |
| IsCertificateAuthority            | True |
| SerialNumber                      | 06fdf9039603adea000aeb3f27bbba1b |
| Version                           | 3 |

{{< /details >}}
#### Imports
{{< details "Expand" >}}
* ntoskrnl.exe

{{< /details >}}
#### Imported Functions
{{< details "Expand" >}}
* IoDeleteSymbolicLink
* IoGetRelatedDeviceObject
* RtlInitUnicodeString
* IoDeleteDevice
* KeSetEvent
* IoCreateFile
* KeInitializeEvent
* IoFileObjectType
* ZwClose
* IofCompleteRequest
* ObReferenceObjectByHandle
* KeWaitForSingleObject
* IoFreeIrp
* IoAllocateIrp
* IoCreateSymbolicLink
* ObfDereferenceObject
* IoCreateDevice
* DbgPrint
* IofCallDriver

{{< /details >}}
#### Exported Functions
{{< details "Expand" >}}

{{< /details >}}

#### Sections
{{< details "Expand" >}}
* .text
* .rdata
* .pdata
* INIT
* .rsrc

{{< /details >}}
#### Signature
{{< details "Expand" >}}
```
{
  "Certificates": [
    {
      "IsCertificateAuthority": false,
      "SerialNumber": "57c76f616cbd9aeb18b22862a09d94dc",
      "Signature": "a13032767aa0a7cf1bc7a580da80f4d20642b0b4b8160fc23d16d38d05fb4f65e792f2e47e29b3c720e247248144275fb0b63e8cfde47b3e15019edb71e9c59f88f2455bbf111dae971157ac862767d607307491183199c65837c588ca898d4019d0b5cc09c34c73ed5500f4158a5522b7f53d4e334d6af3d69915f55b688f5d8956d7048b19a7cf20c571e79df0e13af35b33796d0bff926814d3e8d984b9228db9b3ef9be929d62a1cca4c1e0c50e5bc8525d5431f0e380a7b46166def3b594ea0f73e2e8bb3f9af2a044ccf888e6b23185047d87fd349ed4a93a9d1a639c4122714c4046b4c6f2eb8cc667ae78ecbee2e477affffcb16f5e4a34a72dc1946",
      "SignatureAlgorithmOID": "1.2.840.113549.1.1.5",
      "Subject": "C=CN, ST=BeiJing, L=BeiJing, O=Lespeed Technology Ltd., CN=Lespeed Technology Ltd.",
      "TBS": {
        "MD5": "d3b63256734014c7a7f5e01a335af2ac",
        "SHA1": "b7c7ae11be35f9788e341a5b868b4b599b1d6763",
        "SHA256": "0114225eea0b2816e2fe11ce39f522a5f7a4a0bdd6887016b9671308b6260937",
        "SHA384": "38204a5ba53242499ba3fdd8579117d1a666070a872ecba8a05bc00a977b8c3ebfd0edb1148e2546f3f7dcfaf15d04d2"
      },
      "ValidFrom": "2015-05-07 00:00:00",
      "ValidTo": "2017-05-14 23:59:59",
      "Version": 3
    },
    {
      "IsCertificateAuthority": true,
      "SerialNumber": "611993e400000000001c",
      "Signature": "812a82168c34672be503eb347b8ca2a3508af45586f11e8c8eae7dee0319ce72951848ad6211fd20fd3f4706015ae2e06f8c152c4e3c6a506c0b36a3cf7a0d9c42bc5cf819d560e369e6e22341678c6883762b8f93a32ab57fbe59fba9c9b2268fcaa2f3821b983e919527978661ee5b5d076bcd86a8e26580a8e215e2b2be23056aba0cf347934daca48c077939c061123a050d89a3ec9f578984fbecca7c47661491d8b60f195de6b84aacbc47c8714396e63220a5dc7786fd3ce38b71db7b9b03fcb71d3264eb1652a043a3fa2ead59924e7cc7f233424838513a7c38c71b242228401e1a461f17db18f7f027356cb863d9cdb9645d2ba55eefc629b4f2c7f821cc04ba57fd01b6abc667f9e7d3997ff4f522fa72f5fdff3a1c423aa1f98018a5ee8d1cd4669e4501feaaeefffb178f30f7f1cd29c59decb5d549003d85b8cbbb933a276a49c030ae66c9f723283276f9a48356c848ce5a96aaa0cc0cc47fb48e97af6de35427c39f86c0d6e473089705dbd054625e0348c2d59f7fa7668cd09db04fd4d3985f4b7ac97fb22952d01280c70f54b61e67cdc6a06c110384d34875e72afeb03b6e0a3aa66b769905a3f177686133144706fc537f52bd92145c4a246a678caf8d90aad0f679211b93267cc3ce1ebd883892ae45c6196a4950b305f8ae59378a6a250394b1598150e8ba8380b72335f476b9671d5918ad208d94",
      "SignatureAlgorithmOID": "1.2.840.113549.1.1.5",
      "Subject": "C=US, O=VeriSign, Inc., OU=VeriSign Trust Network, OU=(c) 2006 VeriSign, Inc. , For authorized use only, CN=VeriSign Class 3 Public Primary Certification Authority , G5",
      "TBS": {
        "MD5": "78a717e082dcc1cda3458d917e677d14",
        "SHA1": "4a872e0e51f9b304469cd1dedb496ee9b8b983a4",
        "SHA256": "317fa1d234ebc49040ebc5e8746f8997471496051b185a91bdd9dfbb23fab5f8",
        "SHA384": "b71052da4eb9157c8c1a5d7f55df19d69b9128598b72fcca608e5b7cc7d64c43c5504b9c86355a6dc22ee40c88cc385c"
      },
      "ValidFrom": "2011-02-22 19:25:17",
      "ValidTo": "2021-02-22 19:35:17",
      "Version": 3
    },
    {
      "IsCertificateAuthority": true,
      "SerialNumber": "5200e5aa2556fc1a86ed96c9d44b33c7",
      "Signature": "5622e634a4c461cb48b901ad56a8640fd98c91c4bbcc0ce5ad7aa0227fdf47384a2d6cd17f711a7cec70a9b1f04fe40f0c53fa155efe749849248581261c911447b04c638cbba134d4c645e80d85267303d0a98c646ddc7192e645056015595139fc58146bfed4a4ed796b080c4172e737220609be23e93f449a1ee9619dccb1905cfc3dd28dac423d6536d4b43d40288f9b10cf2326cc4b20cb901f5d8c4c34ca3cd8e537d66fa520bd34eb26d9ae0de7c59af7a1b42191336f86e858bb257c740e58fe751b633fce317c9b8f1b969ec55376845b9cad91faaced93ba5dc82153c2825363af120d5087111b3d5452968a2c9c3d921a089a052ec793a54891d3",
      "SignatureAlgorithmOID": "1.2.840.113549.1.1.5",
      "Subject": "C=US, O=VeriSign, Inc., OU=VeriSign Trust Network, OU=Terms of use at https://www.verisign.com/rpa (c)10, CN=VeriSign Class 3 Code Signing 2010 CA",
      "TBS": {
        "MD5": "b30c31a572b0409383ed3fbe17e56e81",
        "SHA1": "4843a82ed3b1f2bfbee9671960e1940c942f688d",
        "SHA256": "03cda47a6e654ed85d932714fc09ce4874600eda29ec6628cfbaeb155cab78c9",
        "SHA384": "bbda8407c4f9fc4e54d772f1c7fb9d30bc97e1f97ecd51c443063d1fa0644e266328781776cd5c44896c457c75f4d7da"
      },
      "ValidFrom": "2010-02-08 00:00:00",
      "ValidTo": "2020-02-07 23:59:59",
      "Version": 3
    }
  ],
  "CertificatesInfo": "",
  "Signer": [
    {
      "Issuer": "C=US, O=VeriSign, Inc., OU=VeriSign Trust Network, OU=Terms of use at https://www.verisign.com/rpa (c)10, CN=VeriSign Class 3 Code Signing 2010 CA",
      "SerialNumber": "57c76f616cbd9aeb18b22862a09d94dc",
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
| Creation Timestamp           | 2017-06-29 01:22:02 |
| MD5                | [da8437200af5f3f790e301b9958993d2](https://www.virustotal.com/gui/file/da8437200af5f3f790e301b9958993d2) |
| SHA1               | [ce31292b05c0ae1dc639a6ee95bb3bc7350f2aaf](https://www.virustotal.com/gui/file/ce31292b05c0ae1dc639a6ee95bb3bc7350f2aaf) |
| SHA256             | [87aae726bf7104aac8c8f566ea98f2b51a2bfb6097b6fc8aa1f70adeb4681e1b](https://www.virustotal.com/gui/file/87aae726bf7104aac8c8f566ea98f2b51a2bfb6097b6fc8aa1f70adeb4681e1b) |
| Authentihash MD5   | [4e4d97955557f085f4e1fe4cbba82321](https://www.virustotal.com/gui/search/authentihash%253A4e4d97955557f085f4e1fe4cbba82321) |
| Authentihash SHA1  | [131a7703dbaf36bcf7034e8690a7046e9eb52d2b](https://www.virustotal.com/gui/search/authentihash%253A131a7703dbaf36bcf7034e8690a7046e9eb52d2b) |
| Authentihash SHA256| [8a844a8d993db0ee1159b096aee959e32bb9155edd9167b1e6aad2e4019202dd](https://www.virustotal.com/gui/search/authentihash%253A8a844a8d993db0ee1159b096aee959e32bb9155edd9167b1e6aad2e4019202dd) |
| RichPEHeaderHash MD5   | [90cb984cab66f2e7b36cce65ed28b399](https://www.virustotal.com/gui/search/rich_pe_header_hash%253A90cb984cab66f2e7b36cce65ed28b399) |
| RichPEHeaderHash SHA1  | [72b29313b8c3e72489d006710e4f341b9dd15f24](https://www.virustotal.com/gui/search/rich_pe_header_hash%253A72b29313b8c3e72489d006710e4f341b9dd15f24) |
| RichPEHeaderHash SHA256| [c882845cce4f8b835749bf56874a8a88d627bd1b225cb03363005b84f8e6c00b](https://www.virustotal.com/gui/search/rich_pe_header_hash%253Ac882845cce4f8b835749bf56874a8a88d627bd1b225cb03363005b84f8e6c00b) |
| Company           | WiseCleaner.com |
| Description       | WiseUnlo |
| Product           | WiseUnlo |
| OriginalFilename  | WiseUnlo.sys |

{{< button "https://github.com/magicsword-io/LOLDrivers/raw/main/drivers/da8437200af5f3f790e301b9958993d2.bin" "Download" >}} 

#### Certificates

{{< details "Expand" >}}
###### Certificate 61204db4000000000027
| Field                             | Value                      |
|-----------------------------------|----------------------------|
| ToBeSigned (TBS) MD5              | 8e3ffc222fbcebdbb8b23115ab259be7  |
| ToBeSigned (TBS) SHA1             | ee20bff28ffe13be731c294c90d6ded5aae0ec0e |
| ToBeSigned (TBS) SHA256           | 59826b69bc8c28118c96323b627da59aaca0b142cc5d8bad25a8fcfd399aa821 |
| Subject                           | C=US, O=DigiCert Inc, OU=www.digicert.com, CN=DigiCert High Assurance EV Root CA |
| ValidFrom                         | 2011-04-15 19:45:33 |
| ValidTo                           | 2021-04-15 19:55:33 |
| Signature                         | 208cc159ed6f9c6b2dc14a3e751d454c41501cbd80ead9b0928b062a133f53169e56396a8a63b6782479f57db8b947a10a96c2f6cbbda2669f06e1acd279090efd3cdcac020c70af3f1bec787ed4eb4b056026d973619121edb06863e09712ab6fa012edd99fd2da273cb3e456f9d1d4810f71bd427ca689dccdd5bd95a2abf193117de8ac3129a85d6670419dfc75c9d5b31a392ad08505508bac91cac493cb71a59da4946f580cfa6e20c40831b5859d7e81f9d23dca5b18856c0a86ec22091ba574344f7f28bc954aab1db698b05d09a477767eefa78e5d84f61824cbd16da6c3a19cc2107580ff9d32fde6cf433a82f7ce8fe1722a9b62b75fed951a395c2f946d48b7015f332fbbdc2d73348904420a1c8b79f9a3fa17effaa11a10dfe0b2c195eb5c0c05973b353e18884ddb6cbf24898dc8bdd89f7b393a24a0d5dfd1f34a1a97f6a66f7a1fb090a9b3ac013991d361b764f13e573803afce7ad2b590f5aedc3999d5b63c97eda6cb16c77d6b2a4c9094e64c54fd1ecd20ecce689c8758e96160beeb0ec9d5197d9fe978bd0eac2175078fa96ee08c6a2a6b9ce3e765bcbc2d3c6ddc04dc67453632af0481bca8006e614c95c55cd48e8e9f2fc13274bdbd11650307cdefb75e0257da86d41a2834af8849b2cfa5dd82566f68aa14e25954feffeaeeefea9270226081e32523c09fcc0f49b235aa58c33ac3d9169410 |
| SignatureAlgorithmOID             | 1.2.840.113549.1.1.5 |
| IsCertificateAuthority            | True |
| SerialNumber                      | 61204db4000000000027 |
| Version                           | 3 |
###### Certificate 0b847f536116fd6d5a31dbf8f6ad8aa1
| Field                             | Value                      |
|-----------------------------------|----------------------------|
| ToBeSigned (TBS) MD5              | c4a1cd15e009d0791fdb4d9e3612c0b7  |
| ToBeSigned (TBS) SHA1             | 64d8e05d4deddf634440d1e326aacfb4e06c9a0b |
| ToBeSigned (TBS) SHA256           | d34c5ac9e993a225771de09bbcf963e629669168ca2f57c2a0d0b91f0bb511c2 |
| Subject                           | ??=Private Organization, ??=CN, ??=Beijing, serialNumber=91110101593898951F, ??=Chaoyang District, ??=103, Unit C, Building 8, Yard 6, Zuojiazhuang Street, postalCode=100028, C=CN, ST=Beijing, L=Beijing, O=Beijing Lang Xingda Network Technology Co., Ltd, CN=Beijing Lang Xingda Network Technology Co., Ltd |
| ValidFrom                         | 2017-06-16 00:00:00 |
| ValidTo                           | 2019-12-31 12:00:00 |
| Signature                         | 036aa0d600d0e810dc9b7b5b6cb97acc0b21792e351c21236bd4f67a88c232ecde9e6fcd99c2933c5d4f24cb8ad45e6e39547a8a9df084ac43a89cb017cccda9430d89b932c5a8c8c3d1e7ebf997408739bd63d23d52b24bbd72bf3a4ad05363bb5515795ffc9d6328309273587abe0d5c4b60edb85e8ce73ba5caa6b0a1bf597e9691910cc996344537234eee6c64af497f1b29c4432e38d978d7f45822ef88ecd5462752beb2619ba4cbf88eb4be5b8ac2ba19eed2265ee342980ad7fb4f9767487867ce1d6f7f6d6ad0ce642879781ee23ef8e932fae775e511c2e4f07c5e60cf9d8362362cba51c61ff59f352cf8368c000ee3aa8c7a57dc7f3c7dd5a10a |
| SignatureAlgorithmOID             | 1.2.840.113549.1.1.5 |
| IsCertificateAuthority            | False |
| SerialNumber                      | 0b847f536116fd6d5a31dbf8f6ad8aa1 |
| Version                           | 3 |
###### Certificate 03019a023aff58b16bd6d5eae617f066
| Field                             | Value                      |
|-----------------------------------|----------------------------|
| ToBeSigned (TBS) MD5              | a752afee44f017e8d74e3f3eb7914ae3  |
| ToBeSigned (TBS) SHA1             | 8eca80a6b80e9c69dcef7745748524afb8019e2d |
| ToBeSigned (TBS) SHA256           | 82560fa7efec30b5ff82af643e6f3bf3d46868bbd5e7d76f93db185e9e3553a1 |
| Subject                           | C=US, O=DigiCert, CN=DigiCert Timestamp Responder |
| ValidFrom                         | 2014-10-22 00:00:00 |
| ValidTo                           | 2024-10-22 00:00:00 |
| Signature                         | 9d257e1b334db226815c9b86ce23200f8087e588ffffb1d46a2c31ed3a17197117cda91bbc5a1639009de36c84e45a40fbde06018c37fa9bb19d247efe20a457ad5bb79ab06026ea6957215d342f1f71b0839419056b359010a07b97c7f63fe7e21141a6bd62d9f0273d381d286f3a5209f0ec7062d3624bb0e073a692c0d38e31d82fe36d171306eee403b614abf38f43a7719d21dd14ca155d9241daf90f81d199740d26c40e7f1bb5f5a0f1c677062815e9d893e55516f0bb0aab1cdb5c482766c8a38b0a1ce595daaec42e59a061dddaf36da261e98a0b6dec1218bdf755544003922b6bc251c20a48afb0d46ee0f4140a3a1be38f3dcaaf6a8d7bdcd844 |
| SignatureAlgorithmOID             | 1.2.840.113549.1.1.5 |
| IsCertificateAuthority            | False |
| SerialNumber                      | 03019a023aff58b16bd6d5eae617f066 |
| Version                           | 3 |
###### Certificate 0dd0e3374ac95bdbfa6b434b2a48ec06
| Field                             | Value                      |
|-----------------------------------|----------------------------|
| ToBeSigned (TBS) MD5              | f92649915476229b093c211c2b18e6c4  |
| ToBeSigned (TBS) SHA1             | 2d54c16a8f8b69ccdea48d0603c132f547a5cf75 |
| ToBeSigned (TBS) SHA256           | 2cd702a7dec30aa441345672e8992ef9770ce4946f276d767b45b0ed627658fb |
| Subject                           | C=US, O=DigiCert Inc, OU=www.digicert.com, CN=DigiCert EV Code Signing CA |
| ValidFrom                         | 2012-04-18 12:00:00 |
| ValidTo                           | 2027-04-18 12:00:00 |
| Signature                         | 9e5b963a2e1288acab016da49f75e40187a3a532d7bcbaa97ea3d61417f7c2136b7c738f2b6ae50f265968b08e259b6ceffa6c939208c14dcf459e9c46d61e74a19b14a3fa012f4ab101e1724048111368b9369d914bd7c2391210c1c4dcbb6214142a615d4f387c661fc61bffadbe4f7f945b7343000f4d73b751cf0ef677c05bcd348cd96313aa0e6111d6f28e27fcb47bb8b91120918678ea0ed428ff2ad52438e837b2ec96bb9fbc4a1650e15ebf517d23a032c7c1949e7ac9c026a2cc2587a0127e749f2d8db1c8e784beb9d1e9debb6a4e887371e12238cb2487e9737e51b2ff98eb4e7e2fe0ca0efab35ed1ba0542a8489f83f63fc4caa8df68a05061 |
| SignatureAlgorithmOID             | 1.2.840.113549.1.1.5 |
| IsCertificateAuthority            | True |
| SerialNumber                      | 0dd0e3374ac95bdbfa6b434b2a48ec06 |
| Version                           | 3 |
###### Certificate 06fdf9039603adea000aeb3f27bbba1b
| Field                             | Value                      |
|-----------------------------------|----------------------------|
| ToBeSigned (TBS) MD5              | 4e5ad189638cf52ba9cd881d4d44668c  |
| ToBeSigned (TBS) SHA1             | cdc115e98d798b33904c820d63cc1e1afc19251d |
| ToBeSigned (TBS) SHA256           | 37560fb9d548ab62cc3ed4669a4ab74828b5a108e67e829937ffb2d10a5f78dd |
| Subject                           | C=US, O=DigiCert Inc, OU=www.digicert.com, CN=DigiCert Assured ID CA,1 |
| ValidFrom                         | 2006-11-10 00:00:00 |
| ValidTo                           | 2021-11-10 00:00:00 |
| Signature                         | 46503ec9b72824a7381db65b29af52cf52e93147ab565c7bd50d0b41b3efec751f7438f2b25c61a29c95c350e482b923d1ba3a8672ad3878ac755d1717347247859456d1ebbb368477cc24a5f3041955a9e7e3e7ab62cdfb8b2d90c2c0d2b594bd5e4fb105d20e3d1aa9145ba6863162a8a833e49b39a7c4f5ce1d7876942573e42aabcf9c764bed5fc24b16e44b704c00891efcc579bc4c1257fe5fe11ebc025da8fefb07384f0dc65d91b90f6745cdd683ede7920d8db1698c4ffb59e0230fd2aaae007cee9c420ecf91d727b716ee0fc3bd7c0aa0ee2c08558522b8eb181a4dfc2a21ad49318347957771dcb11b4b4b1c109c7714c19d4f2f5a9508291026 |
| SignatureAlgorithmOID             | 1.2.840.113549.1.1.5 |
| IsCertificateAuthority            | True |
| SerialNumber                      | 06fdf9039603adea000aeb3f27bbba1b |
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
* IoDeleteDevice
* KeSetEvent
* IoCreateFile
* KeInitializeEvent
* IoFileObjectType
* KeGetCurrentThread
* ZwClose
* IofCompleteRequest
* IoGetRelatedDeviceObject
* KeWaitForSingleObject
* IoFreeIrp
* IoAllocateIrp
* IoCreateSymbolicLink
* ObfDereferenceObject
* IoCreateDevice
* DbgPrint
* IofCallDriver
* ObReferenceObjectByHandle
* IoDeleteSymbolicLink
* KeGetCurrentIrql

{{< /details >}}
#### Exported Functions
{{< details "Expand" >}}

{{< /details >}}

#### Sections
{{< details "Expand" >}}
* .text
* .rdata
* INIT
* .rsrc
* .reloc

{{< /details >}}
#### Signature
{{< details "Expand" >}}
```
{
  "Certificates": [
    {
      "IsCertificateAuthority": false,
      "SerialNumber": "57c76f616cbd9aeb18b22862a09d94dc",
      "Signature": "a13032767aa0a7cf1bc7a580da80f4d20642b0b4b8160fc23d16d38d05fb4f65e792f2e47e29b3c720e247248144275fb0b63e8cfde47b3e15019edb71e9c59f88f2455bbf111dae971157ac862767d607307491183199c65837c588ca898d4019d0b5cc09c34c73ed5500f4158a5522b7f53d4e334d6af3d69915f55b688f5d8956d7048b19a7cf20c571e79df0e13af35b33796d0bff926814d3e8d984b9228db9b3ef9be929d62a1cca4c1e0c50e5bc8525d5431f0e380a7b46166def3b594ea0f73e2e8bb3f9af2a044ccf888e6b23185047d87fd349ed4a93a9d1a639c4122714c4046b4c6f2eb8cc667ae78ecbee2e477affffcb16f5e4a34a72dc1946",
      "SignatureAlgorithmOID": "1.2.840.113549.1.1.5",
      "Subject": "C=CN, ST=BeiJing, L=BeiJing, O=Lespeed Technology Ltd., CN=Lespeed Technology Ltd.",
      "TBS": {
        "MD5": "d3b63256734014c7a7f5e01a335af2ac",
        "SHA1": "b7c7ae11be35f9788e341a5b868b4b599b1d6763",
        "SHA256": "0114225eea0b2816e2fe11ce39f522a5f7a4a0bdd6887016b9671308b6260937",
        "SHA384": "38204a5ba53242499ba3fdd8579117d1a666070a872ecba8a05bc00a977b8c3ebfd0edb1148e2546f3f7dcfaf15d04d2"
      },
      "ValidFrom": "2015-05-07 00:00:00",
      "ValidTo": "2017-05-14 23:59:59",
      "Version": 3
    },
    {
      "IsCertificateAuthority": true,
      "SerialNumber": "611993e400000000001c",
      "Signature": "812a82168c34672be503eb347b8ca2a3508af45586f11e8c8eae7dee0319ce72951848ad6211fd20fd3f4706015ae2e06f8c152c4e3c6a506c0b36a3cf7a0d9c42bc5cf819d560e369e6e22341678c6883762b8f93a32ab57fbe59fba9c9b2268fcaa2f3821b983e919527978661ee5b5d076bcd86a8e26580a8e215e2b2be23056aba0cf347934daca48c077939c061123a050d89a3ec9f578984fbecca7c47661491d8b60f195de6b84aacbc47c8714396e63220a5dc7786fd3ce38b71db7b9b03fcb71d3264eb1652a043a3fa2ead59924e7cc7f233424838513a7c38c71b242228401e1a461f17db18f7f027356cb863d9cdb9645d2ba55eefc629b4f2c7f821cc04ba57fd01b6abc667f9e7d3997ff4f522fa72f5fdff3a1c423aa1f98018a5ee8d1cd4669e4501feaaeefffb178f30f7f1cd29c59decb5d549003d85b8cbbb933a276a49c030ae66c9f723283276f9a48356c848ce5a96aaa0cc0cc47fb48e97af6de35427c39f86c0d6e473089705dbd054625e0348c2d59f7fa7668cd09db04fd4d3985f4b7ac97fb22952d01280c70f54b61e67cdc6a06c110384d34875e72afeb03b6e0a3aa66b769905a3f177686133144706fc537f52bd92145c4a246a678caf8d90aad0f679211b93267cc3ce1ebd883892ae45c6196a4950b305f8ae59378a6a250394b1598150e8ba8380b72335f476b9671d5918ad208d94",
      "SignatureAlgorithmOID": "1.2.840.113549.1.1.5",
      "Subject": "C=US, O=VeriSign, Inc., OU=VeriSign Trust Network, OU=(c) 2006 VeriSign, Inc. , For authorized use only, CN=VeriSign Class 3 Public Primary Certification Authority , G5",
      "TBS": {
        "MD5": "78a717e082dcc1cda3458d917e677d14",
        "SHA1": "4a872e0e51f9b304469cd1dedb496ee9b8b983a4",
        "SHA256": "317fa1d234ebc49040ebc5e8746f8997471496051b185a91bdd9dfbb23fab5f8",
        "SHA384": "b71052da4eb9157c8c1a5d7f55df19d69b9128598b72fcca608e5b7cc7d64c43c5504b9c86355a6dc22ee40c88cc385c"
      },
      "ValidFrom": "2011-02-22 19:25:17",
      "ValidTo": "2021-02-22 19:35:17",
      "Version": 3
    },
    {
      "IsCertificateAuthority": true,
      "SerialNumber": "5200e5aa2556fc1a86ed96c9d44b33c7",
      "Signature": "5622e634a4c461cb48b901ad56a8640fd98c91c4bbcc0ce5ad7aa0227fdf47384a2d6cd17f711a7cec70a9b1f04fe40f0c53fa155efe749849248581261c911447b04c638cbba134d4c645e80d85267303d0a98c646ddc7192e645056015595139fc58146bfed4a4ed796b080c4172e737220609be23e93f449a1ee9619dccb1905cfc3dd28dac423d6536d4b43d40288f9b10cf2326cc4b20cb901f5d8c4c34ca3cd8e537d66fa520bd34eb26d9ae0de7c59af7a1b42191336f86e858bb257c740e58fe751b633fce317c9b8f1b969ec55376845b9cad91faaced93ba5dc82153c2825363af120d5087111b3d5452968a2c9c3d921a089a052ec793a54891d3",
      "SignatureAlgorithmOID": "1.2.840.113549.1.1.5",
      "Subject": "C=US, O=VeriSign, Inc., OU=VeriSign Trust Network, OU=Terms of use at https://www.verisign.com/rpa (c)10, CN=VeriSign Class 3 Code Signing 2010 CA",
      "TBS": {
        "MD5": "b30c31a572b0409383ed3fbe17e56e81",
        "SHA1": "4843a82ed3b1f2bfbee9671960e1940c942f688d",
        "SHA256": "03cda47a6e654ed85d932714fc09ce4874600eda29ec6628cfbaeb155cab78c9",
        "SHA384": "bbda8407c4f9fc4e54d772f1c7fb9d30bc97e1f97ecd51c443063d1fa0644e266328781776cd5c44896c457c75f4d7da"
      },
      "ValidFrom": "2010-02-08 00:00:00",
      "ValidTo": "2020-02-07 23:59:59",
      "Version": 3
    }
  ],
  "CertificatesInfo": "",
  "Signer": [
    {
      "Issuer": "C=US, O=VeriSign, Inc., OU=VeriSign Trust Network, OU=Terms of use at https://www.verisign.com/rpa (c)10, CN=VeriSign Class 3 Code Signing 2010 CA",
      "SerialNumber": "57c76f616cbd9aeb18b22862a09d94dc",
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
| Creation Timestamp           | 2015-05-11 01:36:54 |
| MD5                | [4cee9945f9a3e8f2433f5aa8c58671fb](https://www.virustotal.com/gui/file/4cee9945f9a3e8f2433f5aa8c58671fb) |
| SHA1               | [b314742af197a786218c6dd704b438469445eefa](https://www.virustotal.com/gui/file/b314742af197a786218c6dd704b438469445eefa) |
| SHA256             | [5e27fe26110d2b9f6c2bad407d3d0611356576b531564f75ff96f9f72d5fcae4](https://www.virustotal.com/gui/file/5e27fe26110d2b9f6c2bad407d3d0611356576b531564f75ff96f9f72d5fcae4) |
| Authentihash MD5   | [42d1a185325fed53f39a49a1cbf5ef51](https://www.virustotal.com/gui/search/authentihash%253A42d1a185325fed53f39a49a1cbf5ef51) |
| Authentihash SHA1  | [0d258e0459c2a6754b7dfb69e12a2c44805ca8d8](https://www.virustotal.com/gui/search/authentihash%253A0d258e0459c2a6754b7dfb69e12a2c44805ca8d8) |
| Authentihash SHA256| [36861bb32abd5ba7955aa69269d27772f75d0306485d10ed045125816422c423](https://www.virustotal.com/gui/search/authentihash%253A36861bb32abd5ba7955aa69269d27772f75d0306485d10ed045125816422c423) |
| RichPEHeaderHash MD5   | [2c93997fbfc6e8e1338e69bb9a988272](https://www.virustotal.com/gui/search/rich_pe_header_hash%253A2c93997fbfc6e8e1338e69bb9a988272) |
| RichPEHeaderHash SHA1  | [a82c319dbe3b4991d04277b3bc2cc9d5b20b309c](https://www.virustotal.com/gui/search/rich_pe_header_hash%253Aa82c319dbe3b4991d04277b3bc2cc9d5b20b309c) |
| RichPEHeaderHash SHA256| [0db9aad853aaf211e35030b5677df8f10a23c541537125b49ac8efd782819665](https://www.virustotal.com/gui/search/rich_pe_header_hash%253A0db9aad853aaf211e35030b5677df8f10a23c541537125b49ac8efd782819665) |
| Company           | WiseCleaner.com |
| Description       | WiseUnlo |
| Product           | WiseUnlo |
| OriginalFilename  | WiseUnlo.sys |

{{< button "https://github.com/magicsword-io/LOLDrivers/raw/main/drivers/4cee9945f9a3e8f2433f5aa8c58671fb.bin" "Download" >}} 

#### Certificates

{{< details "Expand" >}}
###### Certificate 57c76f616cbd9aeb18b22862a09d94dc
| Field                             | Value                      |
|-----------------------------------|----------------------------|
| ToBeSigned (TBS) MD5              | d3b63256734014c7a7f5e01a335af2ac  |
| ToBeSigned (TBS) SHA1             | b7c7ae11be35f9788e341a5b868b4b599b1d6763 |
| ToBeSigned (TBS) SHA256           | 0114225eea0b2816e2fe11ce39f522a5f7a4a0bdd6887016b9671308b6260937 |
| Subject                           | C=CN, ST=BeiJing, L=BeiJing, O=Lespeed Technology Ltd., CN=Lespeed Technology Ltd. |
| ValidFrom                         | 2015-05-07 00:00:00 |
| ValidTo                           | 2017-05-14 23:59:59 |
| Signature                         | a13032767aa0a7cf1bc7a580da80f4d20642b0b4b8160fc23d16d38d05fb4f65e792f2e47e29b3c720e247248144275fb0b63e8cfde47b3e15019edb71e9c59f88f2455bbf111dae971157ac862767d607307491183199c65837c588ca898d4019d0b5cc09c34c73ed5500f4158a5522b7f53d4e334d6af3d69915f55b688f5d8956d7048b19a7cf20c571e79df0e13af35b33796d0bff926814d3e8d984b9228db9b3ef9be929d62a1cca4c1e0c50e5bc8525d5431f0e380a7b46166def3b594ea0f73e2e8bb3f9af2a044ccf888e6b23185047d87fd349ed4a93a9d1a639c4122714c4046b4c6f2eb8cc667ae78ecbee2e477affffcb16f5e4a34a72dc1946 |
| SignatureAlgorithmOID             | 1.2.840.113549.1.1.5 |
| IsCertificateAuthority            | False |
| SerialNumber                      | 57c76f616cbd9aeb18b22862a09d94dc |
| Version                           | 3 |
###### Certificate 611993e400000000001c
| Field                             | Value                      |
|-----------------------------------|----------------------------|
| ToBeSigned (TBS) MD5              | 78a717e082dcc1cda3458d917e677d14  |
| ToBeSigned (TBS) SHA1             | 4a872e0e51f9b304469cd1dedb496ee9b8b983a4 |
| ToBeSigned (TBS) SHA256           | 317fa1d234ebc49040ebc5e8746f8997471496051b185a91bdd9dfbb23fab5f8 |
| Subject                           | C=US, O=VeriSign, Inc., OU=VeriSign Trust Network, OU=(c) 2006 VeriSign, Inc. , For authorized use only, CN=VeriSign Class 3 Public Primary Certification Authority , G5 |
| ValidFrom                         | 2011-02-22 19:25:17 |
| ValidTo                           | 2021-02-22 19:35:17 |
| Signature                         | 812a82168c34672be503eb347b8ca2a3508af45586f11e8c8eae7dee0319ce72951848ad6211fd20fd3f4706015ae2e06f8c152c4e3c6a506c0b36a3cf7a0d9c42bc5cf819d560e369e6e22341678c6883762b8f93a32ab57fbe59fba9c9b2268fcaa2f3821b983e919527978661ee5b5d076bcd86a8e26580a8e215e2b2be23056aba0cf347934daca48c077939c061123a050d89a3ec9f578984fbecca7c47661491d8b60f195de6b84aacbc47c8714396e63220a5dc7786fd3ce38b71db7b9b03fcb71d3264eb1652a043a3fa2ead59924e7cc7f233424838513a7c38c71b242228401e1a461f17db18f7f027356cb863d9cdb9645d2ba55eefc629b4f2c7f821cc04ba57fd01b6abc667f9e7d3997ff4f522fa72f5fdff3a1c423aa1f98018a5ee8d1cd4669e4501feaaeefffb178f30f7f1cd29c59decb5d549003d85b8cbbb933a276a49c030ae66c9f723283276f9a48356c848ce5a96aaa0cc0cc47fb48e97af6de35427c39f86c0d6e473089705dbd054625e0348c2d59f7fa7668cd09db04fd4d3985f4b7ac97fb22952d01280c70f54b61e67cdc6a06c110384d34875e72afeb03b6e0a3aa66b769905a3f177686133144706fc537f52bd92145c4a246a678caf8d90aad0f679211b93267cc3ce1ebd883892ae45c6196a4950b305f8ae59378a6a250394b1598150e8ba8380b72335f476b9671d5918ad208d94 |
| SignatureAlgorithmOID             | 1.2.840.113549.1.1.5 |
| IsCertificateAuthority            | True |
| SerialNumber                      | 611993e400000000001c |
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
* DbgPrint
* IoCreateFile
* IoFreeIrp
* KeSetEvent
* KeWaitForSingleObject
* IofCallDriver
* KeGetCurrentThread
* KeInitializeEvent
* IoDeleteSymbolicLink
* IoAllocateIrp
* IoGetRelatedDeviceObject
* ObReferenceObjectByHandle
* IoFileObjectType
* RtlAssert
* ZwClose
* IofCompleteRequest
* IoCreateSymbolicLink
* IoCreateDevice
* ObfDereferenceObject
* IoDeleteDevice
* KeGetCurrentIrql

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
* .rsrc
* .reloc

{{< /details >}}
#### Signature
{{< details "Expand" >}}
```
{
  "Certificates": [
    {
      "IsCertificateAuthority": false,
      "SerialNumber": "57c76f616cbd9aeb18b22862a09d94dc",
      "Signature": "a13032767aa0a7cf1bc7a580da80f4d20642b0b4b8160fc23d16d38d05fb4f65e792f2e47e29b3c720e247248144275fb0b63e8cfde47b3e15019edb71e9c59f88f2455bbf111dae971157ac862767d607307491183199c65837c588ca898d4019d0b5cc09c34c73ed5500f4158a5522b7f53d4e334d6af3d69915f55b688f5d8956d7048b19a7cf20c571e79df0e13af35b33796d0bff926814d3e8d984b9228db9b3ef9be929d62a1cca4c1e0c50e5bc8525d5431f0e380a7b46166def3b594ea0f73e2e8bb3f9af2a044ccf888e6b23185047d87fd349ed4a93a9d1a639c4122714c4046b4c6f2eb8cc667ae78ecbee2e477affffcb16f5e4a34a72dc1946",
      "SignatureAlgorithmOID": "1.2.840.113549.1.1.5",
      "Subject": "C=CN, ST=BeiJing, L=BeiJing, O=Lespeed Technology Ltd., CN=Lespeed Technology Ltd.",
      "TBS": {
        "MD5": "d3b63256734014c7a7f5e01a335af2ac",
        "SHA1": "b7c7ae11be35f9788e341a5b868b4b599b1d6763",
        "SHA256": "0114225eea0b2816e2fe11ce39f522a5f7a4a0bdd6887016b9671308b6260937",
        "SHA384": "38204a5ba53242499ba3fdd8579117d1a666070a872ecba8a05bc00a977b8c3ebfd0edb1148e2546f3f7dcfaf15d04d2"
      },
      "ValidFrom": "2015-05-07 00:00:00",
      "ValidTo": "2017-05-14 23:59:59",
      "Version": 3
    },
    {
      "IsCertificateAuthority": true,
      "SerialNumber": "611993e400000000001c",
      "Signature": "812a82168c34672be503eb347b8ca2a3508af45586f11e8c8eae7dee0319ce72951848ad6211fd20fd3f4706015ae2e06f8c152c4e3c6a506c0b36a3cf7a0d9c42bc5cf819d560e369e6e22341678c6883762b8f93a32ab57fbe59fba9c9b2268fcaa2f3821b983e919527978661ee5b5d076bcd86a8e26580a8e215e2b2be23056aba0cf347934daca48c077939c061123a050d89a3ec9f578984fbecca7c47661491d8b60f195de6b84aacbc47c8714396e63220a5dc7786fd3ce38b71db7b9b03fcb71d3264eb1652a043a3fa2ead59924e7cc7f233424838513a7c38c71b242228401e1a461f17db18f7f027356cb863d9cdb9645d2ba55eefc629b4f2c7f821cc04ba57fd01b6abc667f9e7d3997ff4f522fa72f5fdff3a1c423aa1f98018a5ee8d1cd4669e4501feaaeefffb178f30f7f1cd29c59decb5d549003d85b8cbbb933a276a49c030ae66c9f723283276f9a48356c848ce5a96aaa0cc0cc47fb48e97af6de35427c39f86c0d6e473089705dbd054625e0348c2d59f7fa7668cd09db04fd4d3985f4b7ac97fb22952d01280c70f54b61e67cdc6a06c110384d34875e72afeb03b6e0a3aa66b769905a3f177686133144706fc537f52bd92145c4a246a678caf8d90aad0f679211b93267cc3ce1ebd883892ae45c6196a4950b305f8ae59378a6a250394b1598150e8ba8380b72335f476b9671d5918ad208d94",
      "SignatureAlgorithmOID": "1.2.840.113549.1.1.5",
      "Subject": "C=US, O=VeriSign, Inc., OU=VeriSign Trust Network, OU=(c) 2006 VeriSign, Inc. , For authorized use only, CN=VeriSign Class 3 Public Primary Certification Authority , G5",
      "TBS": {
        "MD5": "78a717e082dcc1cda3458d917e677d14",
        "SHA1": "4a872e0e51f9b304469cd1dedb496ee9b8b983a4",
        "SHA256": "317fa1d234ebc49040ebc5e8746f8997471496051b185a91bdd9dfbb23fab5f8",
        "SHA384": "b71052da4eb9157c8c1a5d7f55df19d69b9128598b72fcca608e5b7cc7d64c43c5504b9c86355a6dc22ee40c88cc385c"
      },
      "ValidFrom": "2011-02-22 19:25:17",
      "ValidTo": "2021-02-22 19:35:17",
      "Version": 3
    },
    {
      "IsCertificateAuthority": true,
      "SerialNumber": "5200e5aa2556fc1a86ed96c9d44b33c7",
      "Signature": "5622e634a4c461cb48b901ad56a8640fd98c91c4bbcc0ce5ad7aa0227fdf47384a2d6cd17f711a7cec70a9b1f04fe40f0c53fa155efe749849248581261c911447b04c638cbba134d4c645e80d85267303d0a98c646ddc7192e645056015595139fc58146bfed4a4ed796b080c4172e737220609be23e93f449a1ee9619dccb1905cfc3dd28dac423d6536d4b43d40288f9b10cf2326cc4b20cb901f5d8c4c34ca3cd8e537d66fa520bd34eb26d9ae0de7c59af7a1b42191336f86e858bb257c740e58fe751b633fce317c9b8f1b969ec55376845b9cad91faaced93ba5dc82153c2825363af120d5087111b3d5452968a2c9c3d921a089a052ec793a54891d3",
      "SignatureAlgorithmOID": "1.2.840.113549.1.1.5",
      "Subject": "C=US, O=VeriSign, Inc., OU=VeriSign Trust Network, OU=Terms of use at https://www.verisign.com/rpa (c)10, CN=VeriSign Class 3 Code Signing 2010 CA",
      "TBS": {
        "MD5": "b30c31a572b0409383ed3fbe17e56e81",
        "SHA1": "4843a82ed3b1f2bfbee9671960e1940c942f688d",
        "SHA256": "03cda47a6e654ed85d932714fc09ce4874600eda29ec6628cfbaeb155cab78c9",
        "SHA384": "bbda8407c4f9fc4e54d772f1c7fb9d30bc97e1f97ecd51c443063d1fa0644e266328781776cd5c44896c457c75f4d7da"
      },
      "ValidFrom": "2010-02-08 00:00:00",
      "ValidTo": "2020-02-07 23:59:59",
      "Version": 3
    }
  ],
  "CertificatesInfo": "",
  "Signer": [
    {
      "Issuer": "C=US, O=VeriSign, Inc., OU=VeriSign Trust Network, OU=Terms of use at https://www.verisign.com/rpa (c)10, CN=VeriSign Class 3 Code Signing 2010 CA",
      "SerialNumber": "57c76f616cbd9aeb18b22862a09d94dc",
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
| Creation Timestamp           | 2017-06-29 01:21:54 |
| MD5                | [1762105b28eb90d19e9ab3acde16ead6](https://www.virustotal.com/gui/file/1762105b28eb90d19e9ab3acde16ead6) |
| SHA1               | [20cf02c95e329cf2fd4563cddcbd434aad81ccb4](https://www.virustotal.com/gui/file/20cf02c95e329cf2fd4563cddcbd434aad81ccb4) |
| SHA256             | [daf549a7080d384ba99d1b5bd2383dbb1aa640f7ea3a216df1f08981508155f5](https://www.virustotal.com/gui/file/daf549a7080d384ba99d1b5bd2383dbb1aa640f7ea3a216df1f08981508155f5) |
| Authentihash MD5   | [6d1e6e5682f9a5e8a64dc8d2ec6ddfac](https://www.virustotal.com/gui/search/authentihash%253A6d1e6e5682f9a5e8a64dc8d2ec6ddfac) |
| Authentihash SHA1  | [49fb554b77c8d533e4a1ff30bbc60ef7f80b7055](https://www.virustotal.com/gui/search/authentihash%253A49fb554b77c8d533e4a1ff30bbc60ef7f80b7055) |
| Authentihash SHA256| [c36ace67f4e25f391e8709776348397e4fd3930e641b32c1b0da398e59199ca7](https://www.virustotal.com/gui/search/authentihash%253Ac36ace67f4e25f391e8709776348397e4fd3930e641b32c1b0da398e59199ca7) |
| RichPEHeaderHash MD5   | [8d3c5247eb754073fa6215b4e6b75923](https://www.virustotal.com/gui/search/rich_pe_header_hash%253A8d3c5247eb754073fa6215b4e6b75923) |
| RichPEHeaderHash SHA1  | [2810d5abd81048f341ced0b06c0d974c39795cce](https://www.virustotal.com/gui/search/rich_pe_header_hash%253A2810d5abd81048f341ced0b06c0d974c39795cce) |
| RichPEHeaderHash SHA256| [379e3e6bf0f81d613c578c7131d36935edbf8d462638cdd4a1dc6787444af023](https://www.virustotal.com/gui/search/rich_pe_header_hash%253A379e3e6bf0f81d613c578c7131d36935edbf8d462638cdd4a1dc6787444af023) |
| Company           | WiseCleaner.com |
| Description       | WiseUnlo |
| Product           | WiseUnlo |
| OriginalFilename  | WiseUnlo.sys |

{{< button "https://github.com/magicsword-io/LOLDrivers/raw/main/drivers/1762105b28eb90d19e9ab3acde16ead6.bin" "Download" >}} 

#### Certificates

{{< details "Expand" >}}
###### Certificate 6dd472eb02ae0406e3dd843f5fe145e1
| Field                             | Value                      |
|-----------------------------------|----------------------------|
| ToBeSigned (TBS) MD5              | e3898a5cae592360ce7bfdf5ff3fb13f  |
| ToBeSigned (TBS) SHA1             | 217c51b90dbb7f0528e8ba170d227f647fbc995b |
| ToBeSigned (TBS) SHA256           | 3a9b4006a9e125b4458344389c86dfb4f6728848b9871654c615a138514d02ec |
| Subject                           | C=GB, ST=Greater Manchester, L=Salford, O=COMODO CA Limited, CN=COMODO RSA Extended Validation Code Signing CA |
| ValidFrom                         | 2014-12-03 00:00:00 |
| ValidTo                           | 2029-12-02 23:59:59 |
| Signature                         | 664eecb716776f11e81b5d6a4ed9f28b6cb15628408bc031c49948233df80ee88097ef6d200b1f13c486fb173415e18e54f7c2b8007315e028d9dabafa8254c2f7ebbfc336d0309fe5a11c94dfef7ce8f62c78a2accf266a15a11531d6313498bd534fc48483a3c4965c3dd8fed6f954ff67936df83e2b6b2ca2087c5648813218b26eac90c1dbe4de398b86e5c7184059a4df9647bab27fb1f8570f858074380e3a58621efe52e3e6ae530986fe8f9bdb5656cc07b089c104f1530b6c6f77ecb21fecf65b4043600f1bab1854b410048ef80ee9cb83b17af2344e6a544ce9832ae9b030251cce628e0eeb85e629feb14ae3f2ae3c91f54ca1bec8170e5cbb424de31a8a92cd3e207edde975b1ea1f745c9e54c29437b261dd0716597f968016e099b5d26eb0c9230615acd123f4338bce75f0c186d3ffe12efa904ffe46f9bbdb4fbbb7fed10d2b04f1d2d195852c8a2eb88556f2c38452a1e933b1eb50c8a1b09fe3c38b3a879ee755d3d36d3417300d68220bd5b9ed733572c3eda737cde343ae45cd34bf28ca8762ed43a4affacb31cb215861465eb6c67aa61e532aa8f85c511f3a5a100f28c0e4748b74c604aaf84b26280a3289db9d2a60716ac3964e16b963bf6195678c4b2ebbb04e83e94d31e58e2722f53c267b4491d3d45af0d37cf438be149a990e8bb15beae48b0f119d7742821c5c3ad4daab882f8d573054 |
| SignatureAlgorithmOID             | 1.2.840.113549.1.1.12 |
| IsCertificateAuthority            | True |
| SerialNumber                      | 6dd472eb02ae0406e3dd843f5fe145e1 |
| Version                           | 3 |
###### Certificate 61185486000000000024
| Field                             | Value                      |
|-----------------------------------|----------------------------|
| ToBeSigned (TBS) MD5              | ad73330abdd8883ba17ac2572100221e  |
| ToBeSigned (TBS) SHA1             | 3770402ce3d71f9823386167aa35a7c862f409d3 |
| ToBeSigned (TBS) SHA256           | 04bc415adcb4ef7df32b9dfe199d92a4078cbd132fd5173961211e7f75385491 |
| Subject                           | C=GB, ST=Greater Manchester, L=Salford, O=COMODO CA Limited, CN=COMODO RSA Certification Authority |
| ValidFrom                         | 2011-04-11 22:06:20 |
| ValidTo                           | 2021-04-11 22:16:20 |
| Signature                         | 81980792fe6f325fd9d24bf57dd971e0fdfc169205b4ce67f5cc4bd4c7109854fa521b48582f73bf19d937a0ad33f351052379d9b277648aebbdc3b39db7b1e637d1d2597e41d98fb314ab15774d6cda40245bb207b8582c4b0c2b5351b3df2eb976ac69c9c2ed64377b8d217accdc9fbc172804cc2547242a85cc56e639398775181f46f6910faa46fa4de64754e2322c76eefbcdbd62e1962429064b0cfe344ae9101d74e57a2f954bcc6ebafdd7355f91e45942defb008e08f151512d62258415081911864061d52553232c297738cc58d38c5fbc19b866064c6310dbb2ac306c16bc8bbcd21bc603131546a550f49a9684bb721038db519ad4c55327cbbf28159e086b3d3f4cc00c911cbf19848b3751a0199d8555c55da56479ef10a5ebf4231cda6fe32e7d17b037761f4d8dc102411f363e067bc5b7602d416251dedde4512da7de81f4c3e0e0e9c31680dd9c497d17cfcb556307d66952f4a49d248dbe1bc98099874548cb49c5ed703500267ca70f7532f7ed088ff0bca560a022d5331efbe5022c95a607f4be14de704c8ea97e41dea9d95064866f9424f7abf683955d0d45d18c238c030a13e40eb943030a4367b3107446e46dbd65de4541867072040bbaddba591f571393b00bedb1144169d3090459c7368e7db64b9df120fcd0f18bbd68ca3eb131cf43d066f5a3ddafb1dcc3178cfa3128c73e4927ab6a1b |
| SignatureAlgorithmOID             | 1.2.840.113549.1.1.5 |
| IsCertificateAuthority            | True |
| SerialNumber                      | 61185486000000000024 |
| Version                           | 3 |
###### Certificate 2e4a279bde2eb688e8ab30f5904fa875
| Field                             | Value                      |
|-----------------------------------|----------------------------|
| ToBeSigned (TBS) MD5              | 99de6e0504f17e876cb9d36fc42080c4  |
| ToBeSigned (TBS) SHA1             | dd527101c981e893497468a612193e679a2a53d6 |
| ToBeSigned (TBS) SHA256           | d17e9d0bab1868e8d3e98517951899c58c639fd37ce9be228caf626ee91a1e5f |
| Subject                           | serialNumber=91110101593898951F, ??=CN, ??=Private Organization, C=CN, postalCode=100028, ST=Beijing Shi, L=Beijing, ??=Chaoyang District, ??=Room 1610, Haocheng Building, No.9 Building, No.6 Courtyard, Zuojiazhuang Middle Street, O=Lespeed Technology Co., Ltd, CN=Lespeed Technology Co., Ltd |
| ValidFrom                         | 2020-07-09 00:00:00 |
| ValidTo                           | 2023-07-09 23:59:59 |
| Signature                         | 0813de16aad5aae2206ec189ee90af05a8a8b9d096e6812c419f8a6320ea5936e3089eb2abf2022a5e946464d9a3cb09d0b041ce8dd90c37d791f5e3fdafa755ad2fd7fbd7da760fa4bbaeba655509ad015c5f37df20229360fb596ebb7a91b644f7a86ef28c4f8d16debe8666f4d6ebefd7d4a4d5d8c3b96d36c54ebc0386ae680dd469dc252893eca2fba6929f4e589974cf6cb1d33fa8270b67d606dc4118ee320a1cb2894a7ea655dbf42f9ef9c2e204a736a62e326ef85afad054c8f38506b050580120383f3136b33f8f6160bddabbe9cdc3c9d130d2915a5987951d7237bb2480172bb326256efa866a88f4e4432b844a69892ea38c560dde939f18d7 |
| SignatureAlgorithmOID             | 1.2.840.113549.1.1.11 |
| IsCertificateAuthority            | False |
| SerialNumber                      | 2e4a279bde2eb688e8ab30f5904fa875 |
| Version                           | 3 |

{{< /details >}}
#### Imports
{{< details "Expand" >}}
* ntoskrnl.exe

{{< /details >}}
#### Imported Functions
{{< details "Expand" >}}
* IoDeleteSymbolicLink
* IoGetRelatedDeviceObject
* RtlInitUnicodeString
* IoDeleteDevice
* KeSetEvent
* IoCreateFile
* KeInitializeEvent
* IoFileObjectType
* ZwClose
* IofCompleteRequest
* ObReferenceObjectByHandle
* KeWaitForSingleObject
* IoFreeIrp
* IoAllocateIrp
* IoCreateSymbolicLink
* ObfDereferenceObject
* IoCreateDevice
* DbgPrint
* IofCallDriver

{{< /details >}}
#### Exported Functions
{{< details "Expand" >}}

{{< /details >}}

#### Sections
{{< details "Expand" >}}
* .text
* .rdata
* .pdata
* INIT
* .rsrc

{{< /details >}}
#### Signature
{{< details "Expand" >}}
```
{
  "Certificates": [
    {
      "IsCertificateAuthority": false,
      "SerialNumber": "57c76f616cbd9aeb18b22862a09d94dc",
      "Signature": "a13032767aa0a7cf1bc7a580da80f4d20642b0b4b8160fc23d16d38d05fb4f65e792f2e47e29b3c720e247248144275fb0b63e8cfde47b3e15019edb71e9c59f88f2455bbf111dae971157ac862767d607307491183199c65837c588ca898d4019d0b5cc09c34c73ed5500f4158a5522b7f53d4e334d6af3d69915f55b688f5d8956d7048b19a7cf20c571e79df0e13af35b33796d0bff926814d3e8d984b9228db9b3ef9be929d62a1cca4c1e0c50e5bc8525d5431f0e380a7b46166def3b594ea0f73e2e8bb3f9af2a044ccf888e6b23185047d87fd349ed4a93a9d1a639c4122714c4046b4c6f2eb8cc667ae78ecbee2e477affffcb16f5e4a34a72dc1946",
      "SignatureAlgorithmOID": "1.2.840.113549.1.1.5",
      "Subject": "C=CN, ST=BeiJing, L=BeiJing, O=Lespeed Technology Ltd., CN=Lespeed Technology Ltd.",
      "TBS": {
        "MD5": "d3b63256734014c7a7f5e01a335af2ac",
        "SHA1": "b7c7ae11be35f9788e341a5b868b4b599b1d6763",
        "SHA256": "0114225eea0b2816e2fe11ce39f522a5f7a4a0bdd6887016b9671308b6260937",
        "SHA384": "38204a5ba53242499ba3fdd8579117d1a666070a872ecba8a05bc00a977b8c3ebfd0edb1148e2546f3f7dcfaf15d04d2"
      },
      "ValidFrom": "2015-05-07 00:00:00",
      "ValidTo": "2017-05-14 23:59:59",
      "Version": 3
    },
    {
      "IsCertificateAuthority": true,
      "SerialNumber": "611993e400000000001c",
      "Signature": "812a82168c34672be503eb347b8ca2a3508af45586f11e8c8eae7dee0319ce72951848ad6211fd20fd3f4706015ae2e06f8c152c4e3c6a506c0b36a3cf7a0d9c42bc5cf819d560e369e6e22341678c6883762b8f93a32ab57fbe59fba9c9b2268fcaa2f3821b983e919527978661ee5b5d076bcd86a8e26580a8e215e2b2be23056aba0cf347934daca48c077939c061123a050d89a3ec9f578984fbecca7c47661491d8b60f195de6b84aacbc47c8714396e63220a5dc7786fd3ce38b71db7b9b03fcb71d3264eb1652a043a3fa2ead59924e7cc7f233424838513a7c38c71b242228401e1a461f17db18f7f027356cb863d9cdb9645d2ba55eefc629b4f2c7f821cc04ba57fd01b6abc667f9e7d3997ff4f522fa72f5fdff3a1c423aa1f98018a5ee8d1cd4669e4501feaaeefffb178f30f7f1cd29c59decb5d549003d85b8cbbb933a276a49c030ae66c9f723283276f9a48356c848ce5a96aaa0cc0cc47fb48e97af6de35427c39f86c0d6e473089705dbd054625e0348c2d59f7fa7668cd09db04fd4d3985f4b7ac97fb22952d01280c70f54b61e67cdc6a06c110384d34875e72afeb03b6e0a3aa66b769905a3f177686133144706fc537f52bd92145c4a246a678caf8d90aad0f679211b93267cc3ce1ebd883892ae45c6196a4950b305f8ae59378a6a250394b1598150e8ba8380b72335f476b9671d5918ad208d94",
      "SignatureAlgorithmOID": "1.2.840.113549.1.1.5",
      "Subject": "C=US, O=VeriSign, Inc., OU=VeriSign Trust Network, OU=(c) 2006 VeriSign, Inc. , For authorized use only, CN=VeriSign Class 3 Public Primary Certification Authority , G5",
      "TBS": {
        "MD5": "78a717e082dcc1cda3458d917e677d14",
        "SHA1": "4a872e0e51f9b304469cd1dedb496ee9b8b983a4",
        "SHA256": "317fa1d234ebc49040ebc5e8746f8997471496051b185a91bdd9dfbb23fab5f8",
        "SHA384": "b71052da4eb9157c8c1a5d7f55df19d69b9128598b72fcca608e5b7cc7d64c43c5504b9c86355a6dc22ee40c88cc385c"
      },
      "ValidFrom": "2011-02-22 19:25:17",
      "ValidTo": "2021-02-22 19:35:17",
      "Version": 3
    },
    {
      "IsCertificateAuthority": true,
      "SerialNumber": "5200e5aa2556fc1a86ed96c9d44b33c7",
      "Signature": "5622e634a4c461cb48b901ad56a8640fd98c91c4bbcc0ce5ad7aa0227fdf47384a2d6cd17f711a7cec70a9b1f04fe40f0c53fa155efe749849248581261c911447b04c638cbba134d4c645e80d85267303d0a98c646ddc7192e645056015595139fc58146bfed4a4ed796b080c4172e737220609be23e93f449a1ee9619dccb1905cfc3dd28dac423d6536d4b43d40288f9b10cf2326cc4b20cb901f5d8c4c34ca3cd8e537d66fa520bd34eb26d9ae0de7c59af7a1b42191336f86e858bb257c740e58fe751b633fce317c9b8f1b969ec55376845b9cad91faaced93ba5dc82153c2825363af120d5087111b3d5452968a2c9c3d921a089a052ec793a54891d3",
      "SignatureAlgorithmOID": "1.2.840.113549.1.1.5",
      "Subject": "C=US, O=VeriSign, Inc., OU=VeriSign Trust Network, OU=Terms of use at https://www.verisign.com/rpa (c)10, CN=VeriSign Class 3 Code Signing 2010 CA",
      "TBS": {
        "MD5": "b30c31a572b0409383ed3fbe17e56e81",
        "SHA1": "4843a82ed3b1f2bfbee9671960e1940c942f688d",
        "SHA256": "03cda47a6e654ed85d932714fc09ce4874600eda29ec6628cfbaeb155cab78c9",
        "SHA384": "bbda8407c4f9fc4e54d772f1c7fb9d30bc97e1f97ecd51c443063d1fa0644e266328781776cd5c44896c457c75f4d7da"
      },
      "ValidFrom": "2010-02-08 00:00:00",
      "ValidTo": "2020-02-07 23:59:59",
      "Version": 3
    }
  ],
  "CertificatesInfo": "",
  "Signer": [
    {
      "Issuer": "C=US, O=VeriSign, Inc., OU=VeriSign Trust Network, OU=Terms of use at https://www.verisign.com/rpa (c)10, CN=VeriSign Class 3 Code Signing 2010 CA",
      "SerialNumber": "57c76f616cbd9aeb18b22862a09d94dc",
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
| Filename           | WiseUnlo.sys |
| Creation Timestamp           | 2017-06-29 01:21:54 |
| MD5                | [356bda2bf0f6899a2c08b2da3ec69f13](https://www.virustotal.com/gui/file/356bda2bf0f6899a2c08b2da3ec69f13) |
| SHA1               | [b9807b8840327c6d7fbdde45fc27de921f1f1a82](https://www.virustotal.com/gui/file/b9807b8840327c6d7fbdde45fc27de921f1f1a82) |
| SHA256             | [358ac54be252673841a1d65bfc2fb6d549c1a4c877fa7f5e1bfa188f30375d69](https://www.virustotal.com/gui/file/358ac54be252673841a1d65bfc2fb6d549c1a4c877fa7f5e1bfa188f30375d69) |
| Authentihash MD5   | [6d1e6e5682f9a5e8a64dc8d2ec6ddfac](https://www.virustotal.com/gui/search/authentihash%253A6d1e6e5682f9a5e8a64dc8d2ec6ddfac) |
| Authentihash SHA1  | [49fb554b77c8d533e4a1ff30bbc60ef7f80b7055](https://www.virustotal.com/gui/search/authentihash%253A49fb554b77c8d533e4a1ff30bbc60ef7f80b7055) |
| Authentihash SHA256| [c36ace67f4e25f391e8709776348397e4fd3930e641b32c1b0da398e59199ca7](https://www.virustotal.com/gui/search/authentihash%253Ac36ace67f4e25f391e8709776348397e4fd3930e641b32c1b0da398e59199ca7) |
| RichPEHeaderHash MD5   | [8d3c5247eb754073fa6215b4e6b75923](https://www.virustotal.com/gui/search/rich_pe_header_hash%253A8d3c5247eb754073fa6215b4e6b75923) |
| RichPEHeaderHash SHA1  | [2810d5abd81048f341ced0b06c0d974c39795cce](https://www.virustotal.com/gui/search/rich_pe_header_hash%253A2810d5abd81048f341ced0b06c0d974c39795cce) |
| RichPEHeaderHash SHA256| [379e3e6bf0f81d613c578c7131d36935edbf8d462638cdd4a1dc6787444af023](https://www.virustotal.com/gui/search/rich_pe_header_hash%253A379e3e6bf0f81d613c578c7131d36935edbf8d462638cdd4a1dc6787444af023) |
| Company           | WiseCleaner.com |
| Description       | WiseUnlo |
| Product           | WiseUnlo |
| OriginalFilename  | WiseUnlo.sys |

{{< button "https://github.com/magicsword-io/LOLDrivers/raw/main/drivers/356bda2bf0f6899a2c08b2da3ec69f13.bin" "Download" >}} 

#### Certificates

{{< details "Expand" >}}
###### Certificate 6dd472eb02ae0406e3dd843f5fe145e1
| Field                             | Value                      |
|-----------------------------------|----------------------------|
| ToBeSigned (TBS) MD5              | e3898a5cae592360ce7bfdf5ff3fb13f  |
| ToBeSigned (TBS) SHA1             | 217c51b90dbb7f0528e8ba170d227f647fbc995b |
| ToBeSigned (TBS) SHA256           | 3a9b4006a9e125b4458344389c86dfb4f6728848b9871654c615a138514d02ec |
| Subject                           | C=GB, ST=Greater Manchester, L=Salford, O=COMODO CA Limited, CN=COMODO RSA Extended Validation Code Signing CA |
| ValidFrom                         | 2014-12-03 00:00:00 |
| ValidTo                           | 2029-12-02 23:59:59 |
| Signature                         | 664eecb716776f11e81b5d6a4ed9f28b6cb15628408bc031c49948233df80ee88097ef6d200b1f13c486fb173415e18e54f7c2b8007315e028d9dabafa8254c2f7ebbfc336d0309fe5a11c94dfef7ce8f62c78a2accf266a15a11531d6313498bd534fc48483a3c4965c3dd8fed6f954ff67936df83e2b6b2ca2087c5648813218b26eac90c1dbe4de398b86e5c7184059a4df9647bab27fb1f8570f858074380e3a58621efe52e3e6ae530986fe8f9bdb5656cc07b089c104f1530b6c6f77ecb21fecf65b4043600f1bab1854b410048ef80ee9cb83b17af2344e6a544ce9832ae9b030251cce628e0eeb85e629feb14ae3f2ae3c91f54ca1bec8170e5cbb424de31a8a92cd3e207edde975b1ea1f745c9e54c29437b261dd0716597f968016e099b5d26eb0c9230615acd123f4338bce75f0c186d3ffe12efa904ffe46f9bbdb4fbbb7fed10d2b04f1d2d195852c8a2eb88556f2c38452a1e933b1eb50c8a1b09fe3c38b3a879ee755d3d36d3417300d68220bd5b9ed733572c3eda737cde343ae45cd34bf28ca8762ed43a4affacb31cb215861465eb6c67aa61e532aa8f85c511f3a5a100f28c0e4748b74c604aaf84b26280a3289db9d2a60716ac3964e16b963bf6195678c4b2ebbb04e83e94d31e58e2722f53c267b4491d3d45af0d37cf438be149a990e8bb15beae48b0f119d7742821c5c3ad4daab882f8d573054 |
| SignatureAlgorithmOID             | 1.2.840.113549.1.1.12 |
| IsCertificateAuthority            | True |
| SerialNumber                      | 6dd472eb02ae0406e3dd843f5fe145e1 |
| Version                           | 3 |
###### Certificate 61185486000000000024
| Field                             | Value                      |
|-----------------------------------|----------------------------|
| ToBeSigned (TBS) MD5              | ad73330abdd8883ba17ac2572100221e  |
| ToBeSigned (TBS) SHA1             | 3770402ce3d71f9823386167aa35a7c862f409d3 |
| ToBeSigned (TBS) SHA256           | 04bc415adcb4ef7df32b9dfe199d92a4078cbd132fd5173961211e7f75385491 |
| Subject                           | C=GB, ST=Greater Manchester, L=Salford, O=COMODO CA Limited, CN=COMODO RSA Certification Authority |
| ValidFrom                         | 2011-04-11 22:06:20 |
| ValidTo                           | 2021-04-11 22:16:20 |
| Signature                         | 81980792fe6f325fd9d24bf57dd971e0fdfc169205b4ce67f5cc4bd4c7109854fa521b48582f73bf19d937a0ad33f351052379d9b277648aebbdc3b39db7b1e637d1d2597e41d98fb314ab15774d6cda40245bb207b8582c4b0c2b5351b3df2eb976ac69c9c2ed64377b8d217accdc9fbc172804cc2547242a85cc56e639398775181f46f6910faa46fa4de64754e2322c76eefbcdbd62e1962429064b0cfe344ae9101d74e57a2f954bcc6ebafdd7355f91e45942defb008e08f151512d62258415081911864061d52553232c297738cc58d38c5fbc19b866064c6310dbb2ac306c16bc8bbcd21bc603131546a550f49a9684bb721038db519ad4c55327cbbf28159e086b3d3f4cc00c911cbf19848b3751a0199d8555c55da56479ef10a5ebf4231cda6fe32e7d17b037761f4d8dc102411f363e067bc5b7602d416251dedde4512da7de81f4c3e0e0e9c31680dd9c497d17cfcb556307d66952f4a49d248dbe1bc98099874548cb49c5ed703500267ca70f7532f7ed088ff0bca560a022d5331efbe5022c95a607f4be14de704c8ea97e41dea9d95064866f9424f7abf683955d0d45d18c238c030a13e40eb943030a4367b3107446e46dbd65de4541867072040bbaddba591f571393b00bedb1144169d3090459c7368e7db64b9df120fcd0f18bbd68ca3eb131cf43d066f5a3ddafb1dcc3178cfa3128c73e4927ab6a1b |
| SignatureAlgorithmOID             | 1.2.840.113549.1.1.5 |
| IsCertificateAuthority            | True |
| SerialNumber                      | 61185486000000000024 |
| Version                           | 3 |
###### Certificate 2e4a279bde2eb688e8ab30f5904fa875
| Field                             | Value                      |
|-----------------------------------|----------------------------|
| ToBeSigned (TBS) MD5              | 99de6e0504f17e876cb9d36fc42080c4  |
| ToBeSigned (TBS) SHA1             | dd527101c981e893497468a612193e679a2a53d6 |
| ToBeSigned (TBS) SHA256           | d17e9d0bab1868e8d3e98517951899c58c639fd37ce9be228caf626ee91a1e5f |
| Subject                           | serialNumber=91110101593898951F, ??=CN, ??=Private Organization, C=CN, postalCode=100028, ST=Beijing Shi, L=Beijing, ??=Chaoyang District, ??=Room 1610, Haocheng Building, No.9 Building, No.6 Courtyard, Zuojiazhuang Middle Street, O=Lespeed Technology Co., Ltd, CN=Lespeed Technology Co., Ltd |
| ValidFrom                         | 2020-07-09 00:00:00 |
| ValidTo                           | 2023-07-09 23:59:59 |
| Signature                         | 0813de16aad5aae2206ec189ee90af05a8a8b9d096e6812c419f8a6320ea5936e3089eb2abf2022a5e946464d9a3cb09d0b041ce8dd90c37d791f5e3fdafa755ad2fd7fbd7da760fa4bbaeba655509ad015c5f37df20229360fb596ebb7a91b644f7a86ef28c4f8d16debe8666f4d6ebefd7d4a4d5d8c3b96d36c54ebc0386ae680dd469dc252893eca2fba6929f4e589974cf6cb1d33fa8270b67d606dc4118ee320a1cb2894a7ea655dbf42f9ef9c2e204a736a62e326ef85afad054c8f38506b050580120383f3136b33f8f6160bddabbe9cdc3c9d130d2915a5987951d7237bb2480172bb326256efa866a88f4e4432b844a69892ea38c560dde939f18d7 |
| SignatureAlgorithmOID             | 1.2.840.113549.1.1.11 |
| IsCertificateAuthority            | False |
| SerialNumber                      | 2e4a279bde2eb688e8ab30f5904fa875 |
| Version                           | 3 |

{{< /details >}}
#### Imports
{{< details "Expand" >}}
* ntoskrnl.exe

{{< /details >}}
#### Imported Functions
{{< details "Expand" >}}
* IoDeleteSymbolicLink
* IoGetRelatedDeviceObject
* RtlInitUnicodeString
* IoDeleteDevice
* KeSetEvent
* IoCreateFile
* KeInitializeEvent
* IoFileObjectType
* ZwClose
* IofCompleteRequest
* ObReferenceObjectByHandle
* KeWaitForSingleObject
* IoFreeIrp
* IoAllocateIrp
* IoCreateSymbolicLink
* ObfDereferenceObject
* IoCreateDevice
* DbgPrint
* IofCallDriver

{{< /details >}}
#### Exported Functions
{{< details "Expand" >}}

{{< /details >}}

#### Sections
{{< details "Expand" >}}
* .text
* .rdata
* .pdata
* INIT
* .rsrc

{{< /details >}}
#### Signature
{{< details "Expand" >}}
```
{
  "Certificates": [
    {
      "IsCertificateAuthority": false,
      "SerialNumber": "57c76f616cbd9aeb18b22862a09d94dc",
      "Signature": "a13032767aa0a7cf1bc7a580da80f4d20642b0b4b8160fc23d16d38d05fb4f65e792f2e47e29b3c720e247248144275fb0b63e8cfde47b3e15019edb71e9c59f88f2455bbf111dae971157ac862767d607307491183199c65837c588ca898d4019d0b5cc09c34c73ed5500f4158a5522b7f53d4e334d6af3d69915f55b688f5d8956d7048b19a7cf20c571e79df0e13af35b33796d0bff926814d3e8d984b9228db9b3ef9be929d62a1cca4c1e0c50e5bc8525d5431f0e380a7b46166def3b594ea0f73e2e8bb3f9af2a044ccf888e6b23185047d87fd349ed4a93a9d1a639c4122714c4046b4c6f2eb8cc667ae78ecbee2e477affffcb16f5e4a34a72dc1946",
      "SignatureAlgorithmOID": "1.2.840.113549.1.1.5",
      "Subject": "C=CN, ST=BeiJing, L=BeiJing, O=Lespeed Technology Ltd., CN=Lespeed Technology Ltd.",
      "TBS": {
        "MD5": "d3b63256734014c7a7f5e01a335af2ac",
        "SHA1": "b7c7ae11be35f9788e341a5b868b4b599b1d6763",
        "SHA256": "0114225eea0b2816e2fe11ce39f522a5f7a4a0bdd6887016b9671308b6260937",
        "SHA384": "38204a5ba53242499ba3fdd8579117d1a666070a872ecba8a05bc00a977b8c3ebfd0edb1148e2546f3f7dcfaf15d04d2"
      },
      "ValidFrom": "2015-05-07 00:00:00",
      "ValidTo": "2017-05-14 23:59:59",
      "Version": 3
    },
    {
      "IsCertificateAuthority": true,
      "SerialNumber": "611993e400000000001c",
      "Signature": "812a82168c34672be503eb347b8ca2a3508af45586f11e8c8eae7dee0319ce72951848ad6211fd20fd3f4706015ae2e06f8c152c4e3c6a506c0b36a3cf7a0d9c42bc5cf819d560e369e6e22341678c6883762b8f93a32ab57fbe59fba9c9b2268fcaa2f3821b983e919527978661ee5b5d076bcd86a8e26580a8e215e2b2be23056aba0cf347934daca48c077939c061123a050d89a3ec9f578984fbecca7c47661491d8b60f195de6b84aacbc47c8714396e63220a5dc7786fd3ce38b71db7b9b03fcb71d3264eb1652a043a3fa2ead59924e7cc7f233424838513a7c38c71b242228401e1a461f17db18f7f027356cb863d9cdb9645d2ba55eefc629b4f2c7f821cc04ba57fd01b6abc667f9e7d3997ff4f522fa72f5fdff3a1c423aa1f98018a5ee8d1cd4669e4501feaaeefffb178f30f7f1cd29c59decb5d549003d85b8cbbb933a276a49c030ae66c9f723283276f9a48356c848ce5a96aaa0cc0cc47fb48e97af6de35427c39f86c0d6e473089705dbd054625e0348c2d59f7fa7668cd09db04fd4d3985f4b7ac97fb22952d01280c70f54b61e67cdc6a06c110384d34875e72afeb03b6e0a3aa66b769905a3f177686133144706fc537f52bd92145c4a246a678caf8d90aad0f679211b93267cc3ce1ebd883892ae45c6196a4950b305f8ae59378a6a250394b1598150e8ba8380b72335f476b9671d5918ad208d94",
      "SignatureAlgorithmOID": "1.2.840.113549.1.1.5",
      "Subject": "C=US, O=VeriSign, Inc., OU=VeriSign Trust Network, OU=(c) 2006 VeriSign, Inc. , For authorized use only, CN=VeriSign Class 3 Public Primary Certification Authority , G5",
      "TBS": {
        "MD5": "78a717e082dcc1cda3458d917e677d14",
        "SHA1": "4a872e0e51f9b304469cd1dedb496ee9b8b983a4",
        "SHA256": "317fa1d234ebc49040ebc5e8746f8997471496051b185a91bdd9dfbb23fab5f8",
        "SHA384": "b71052da4eb9157c8c1a5d7f55df19d69b9128598b72fcca608e5b7cc7d64c43c5504b9c86355a6dc22ee40c88cc385c"
      },
      "ValidFrom": "2011-02-22 19:25:17",
      "ValidTo": "2021-02-22 19:35:17",
      "Version": 3
    },
    {
      "IsCertificateAuthority": true,
      "SerialNumber": "5200e5aa2556fc1a86ed96c9d44b33c7",
      "Signature": "5622e634a4c461cb48b901ad56a8640fd98c91c4bbcc0ce5ad7aa0227fdf47384a2d6cd17f711a7cec70a9b1f04fe40f0c53fa155efe749849248581261c911447b04c638cbba134d4c645e80d85267303d0a98c646ddc7192e645056015595139fc58146bfed4a4ed796b080c4172e737220609be23e93f449a1ee9619dccb1905cfc3dd28dac423d6536d4b43d40288f9b10cf2326cc4b20cb901f5d8c4c34ca3cd8e537d66fa520bd34eb26d9ae0de7c59af7a1b42191336f86e858bb257c740e58fe751b633fce317c9b8f1b969ec55376845b9cad91faaced93ba5dc82153c2825363af120d5087111b3d5452968a2c9c3d921a089a052ec793a54891d3",
      "SignatureAlgorithmOID": "1.2.840.113549.1.1.5",
      "Subject": "C=US, O=VeriSign, Inc., OU=VeriSign Trust Network, OU=Terms of use at https://www.verisign.com/rpa (c)10, CN=VeriSign Class 3 Code Signing 2010 CA",
      "TBS": {
        "MD5": "b30c31a572b0409383ed3fbe17e56e81",
        "SHA1": "4843a82ed3b1f2bfbee9671960e1940c942f688d",
        "SHA256": "03cda47a6e654ed85d932714fc09ce4874600eda29ec6628cfbaeb155cab78c9",
        "SHA384": "bbda8407c4f9fc4e54d772f1c7fb9d30bc97e1f97ecd51c443063d1fa0644e266328781776cd5c44896c457c75f4d7da"
      },
      "ValidFrom": "2010-02-08 00:00:00",
      "ValidTo": "2020-02-07 23:59:59",
      "Version": 3
    }
  ],
  "CertificatesInfo": "",
  "Signer": [
    {
      "Issuer": "C=US, O=VeriSign, Inc., OU=VeriSign Trust Network, OU=Terms of use at https://www.verisign.com/rpa (c)10, CN=VeriSign Class 3 Code Signing 2010 CA",
      "SerialNumber": "57c76f616cbd9aeb18b22862a09d94dc",
      "Version": 1
    }
  ],
  "SignerInfo": ""
}
```

{{< /details >}}
-----



[*source*](https://github.com/magicsword-io/LOLDrivers/tree/main/yaml/b28cc2ee-d4a2-4fe4-9acb-a7a61cad20c6.yaml)

*last_updated:* 2025-03-03

{{< /column >}}
{{< /block >}}
