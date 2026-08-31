+++

description = ""
title = "8fcec30c-f5ca-4aae-b2d8-77af60b78d42"
weight = 10
displayTitle = "zntport.sys"
+++


{{< block "grid-1" >}}
{{< column "mt-2 pt-1">}}


# zntport.sys ![:inline](/images/twitter_verified.png) 

### Description

The legacy NTPort driver creates the &#34;\\.\zntport&#34; device and exposes IOCTL 0xF10024CC with FILE_ANY_ACCESS. The handler accepts a caller-controlled 32-bit physical address, maps 0x32 bytes below 4 GiB with MmMapIoSpace, and copies data through an unchecked strcpy operation. After an administrator installs the driver, an unprivileged process may be able to abuse the device for physical-memory disclosure or memory corruption, depending on the device ACL.
- **UUID**: 8fcec30c-f5ca-4aae-b2d8-77af60b78d42
- **Created**: 2026-08-11
- **Author**: Element2023H
- **Acknowledgement**:  | [Element2023H](https://twitter.com/Element2023H)

{{< button "https://github.com/magicsword-io/LOLDrivers/raw/main/drivers/1e712a45f50b2c7cc235e81fb7e06e8f.bin" "Download" >}}
{{< tip "warning" >}}
This download link contains the vulnerable driver!

{{< /tip >}}

{{< blockbanner "zntport.sys" >}}
### Commands

```
sc.exe create zntport binPath= C:\windows\temp\zntport.sys type= kernel &amp;&amp; sc.exe start zntport
```


| Use Case | Privileges | Operating System | 
|:---- | ---- | ---- |
| Read physical memory below 4 GiB or trigger memory corruption through the unchecked copy operation. | Administrator required to install; device access may be available to unprivileged users after installation | Windows NT, Windows 2000, Windows XP, Windows Server 2003, Windows Vista |



### Detections


{{< block "grid-3" >}}
{{< column >}}
#### YARA 🏹
{{< details "Expand" >}}

{{< button "https://github.com/magicsword-io/LOLDrivers/blob/main/detections/yara/yara-rules_vuln_drivers_strict.yar" "Exact Match" >}}{{< tip >}}with header and size limitation{{< /tip >}} 

{{< button "https://github.com/magicsword-io/LOLDrivers/blob/main/detections/yara/other/yara-rules_vuln_drivers.yar" "Threat Hunting" >}}{{< tip >}}without header and size limitation{{< /tip >}} 

{{< button "https://github.com/magicsword-io/LOLDrivers/blob/main/detections/yara/other/yara-rules_vuln_drivers_strict_renamed.yar" "Renamed" >}}{{< tip >}}for renamed driver files{{< /tip >}} 


{{< /details >}}
{{< /column >}}



{{< column >}}

#### Sigma 🛡️
{{< details "Expand" >}}
{{< button "https://github.com/magicsword-io/LOLDrivers/blob/main/detections/sigma/driver_load_win_vuln_drivers_names.yml" "Names" >}}{{< tip >}}detects loading using name only{{< /tip >}} 


{{< button "https://github.com/magicsword-io/LOLDrivers/blob/main/detections/sigma/driver_load_win_vuln_drivers.yml" "Hashes" >}}{{< tip >}}detects loading using hashes only{{< /tip >}} 

{{< /details >}}

{{< /column >}}


{{< column "mb-2" >}}

#### Sysmon 🔎
{{< details "Expand" >}}
{{< button "https://github.com/magicsword-io/LOLDrivers/blob/main/detections/sysmon/sysmon_config_vulnerable_hashes_block.xml" "Block" >}}{{< tip >}}on hashes{{< /tip >}} 

{{< button "https://github.com/magicsword-io/LOLDrivers/blob/main/detections/sysmon/sysmon_config_vulnerable_hashes.xml" "Alert" >}}{{< tip >}}on hashes{{< /tip >}} 

{{< /details >}}

{{< /column >}}
{{< /block >}}


### Resources
<br>
<li><a href="https://github.com/The-Sword-of-Constantine/UsingBYOVD/blob/master/RawDriverFiles/zntport.sys">https://github.com/The-Sword-of-Constantine/UsingBYOVD/blob/master/RawDriverFiles/zntport.sys</a></li>
<li><a href="https://www.zealsoftstudio.com/ntport/portfaq.html">https://www.zealsoftstudio.com/ntport/portfaq.html</a></li>
<br>


### Known Vulnerable Samples

| Property           | Value |
|:-------------------|:------|
| Filename           | zntport.sys |
| Creation Timestamp           | 2007-12-22 01:35:56 |
| MD5                | [1e712a45f50b2c7cc235e81fb7e06e8f](https://www.virustotal.com/gui/file/1e712a45f50b2c7cc235e81fb7e06e8f) |
| SHA1               | [86025bc313156397b0b5e3864106208898e27218](https://www.virustotal.com/gui/file/86025bc313156397b0b5e3864106208898e27218) |
| SHA256             | [c653fe66aeb6170899ad8b405b7550e247490a2366bda828bfa3b2a2dc18fa91](https://www.virustotal.com/gui/file/c653fe66aeb6170899ad8b405b7550e247490a2366bda828bfa3b2a2dc18fa91) |
| Authentihash MD5   | [a8dfc8192b5a589bbcf4c6618135cedd](https://www.virustotal.com/gui/search/authentihash%253Aa8dfc8192b5a589bbcf4c6618135cedd) |
| Authentihash SHA1  | [4301542b6e2d0bb05daefc31d0a9559c2b325ef0](https://www.virustotal.com/gui/search/authentihash%253A4301542b6e2d0bb05daefc31d0a9559c2b325ef0) |
| Authentihash SHA256| [d9a6d18a51bfd4cb1f375590b051ea95f9e2d9090dcda4be51fca6fddaafb598](https://www.virustotal.com/gui/search/authentihash%253Ad9a6d18a51bfd4cb1f375590b051ea95f9e2d9090dcda4be51fca6fddaafb598) |
| RichPEHeaderHash MD5   | [bab7ca9d03f0546edd81ae1a9b85cd52](https://www.virustotal.com/gui/search/rich_pe_header_hash%253Abab7ca9d03f0546edd81ae1a9b85cd52) |
| RichPEHeaderHash SHA1  | [3ae35f55cd52006c8d5cf02622947e49d888386c](https://www.virustotal.com/gui/search/rich_pe_header_hash%253A3ae35f55cd52006c8d5cf02622947e49d888386c) |
| RichPEHeaderHash SHA256| [25b450c68d20191e07f756e2b35dddc1d486a5c8ebef34ea41f1345830d2ae9f](https://www.virustotal.com/gui/search/rich_pe_header_hash%253A25b450c68d20191e07f756e2b35dddc1d486a5c8ebef34ea41f1345830d2ae9f) |
| Company           | Zeal SoftStudio |
| Description       | NTPort Library kernel driver |
| Product           | NTPort Library |
| OriginalFilename  | zntport.sys |

{{< button "https://github.com/magicsword-io/LOLDrivers/raw/main/drivers/1e712a45f50b2c7cc235e81fb7e06e8f.bin" "Download" >}} 

#### Certificates

{{< details "Expand" >}}
###### Certificate 0d91d62ed03dda74e5efe8d70ae793c9
| Field                             | Value                      |
|-----------------------------------|----------------------------|
| ToBeSigned (TBS) MD5              | c5edda178503ccfbc896cd596dba71ab  |
| ToBeSigned (TBS) SHA1             | 7df69e18fcb66c69f1b17258919f2976988265bb |
| ToBeSigned (TBS) SHA256           | 59091d162fa68b89e157ddf3eb49d6be09a7ae6e16158980a00c7aaf1677ad2c |
| Subject                           | JURISDICTION_OF_INCORPORATION_C=TW, BUSINESS_CATEGORY=Private Organization, serialNumber=09424319, C=TW, ST=T&#39;ai,pei, L=New Taipei, O=CLEVO CO., CN=CLEVO CO. |
| ValidFrom                         | 2018-08-21 00:00:00 |
| ValidTo                           | 2021-11-17 12:00:00 |
| Signature                         | 0d6ff3c3775d78638245067a52811b8d4de62370b8cefcb1323b8304f2445f4c3861bbe76b933ce316478d04af1bc45b578bbdc4fdc7f07148cb716cd7292c4f94133165a9fa7137f9679d45566381783bdd2f38db7a395d9653958a4ce211bd459724571339504e554f31066142a050d71d1134a4e8e07f15f77d44001821a8fbcc195395235845bc0dd0dc6c66f0449292736a44395be9ca15b063863cfbc8d9eb0f9da047fc9156ce272a8924529cd47a8697c681f2742855d726a3871e33fc5c1c698a37c9f389ba91049902a953b1f1fca4179011d49bcd04c26fccefb02b5dfae916ea909dc78430f9a26fb93bd09bb0098dac413e9af4f4f9f478c913 |
| SignatureAlgorithmOID             | 1.2.840.113549.1.1.11 |
| IsCertificateAuthority            | False |
| SerialNumber                      | 0d91d62ed03dda74e5efe8d70ae793c9 |
| Version                           | 3 |
###### Certificate 03f1b4e15f3a82f1149678b3d7d8475c
| Field                             | Value                      |
|-----------------------------------|----------------------------|
| ToBeSigned (TBS) MD5              | 83f5de89f641d0fbf60248e10a7b9534  |
| ToBeSigned (TBS) SHA1             | 382a73a059a08698d6eb98c87e1b36fc750933a4 |
| ToBeSigned (TBS) SHA256           | eec58131dc11cd7f512501b15fdbc6074c603b68ca91f7162d5a042054edb0cf |
| Subject                           | C=US, O=DigiCert Inc, OU=www.digicert.com, CN=DigiCert EV Code Signing CA (SHA2) |
| ValidFrom                         | 2012-04-18 12:00:00 |
| ValidTo                           | 2027-04-18 12:00:00 |
| Signature                         | 19334a0c813337dbad36c9e4c93abbb51b2e7aa2e2f44342179ebf4ea14de1b1dbe981dd9f01f2e488d5e9fe09fd21c1ec5d80d2f0d6c143c2fe772bdbf9d79133ce6cd5b2193be62ed6c9934f88408ecde1f57ef10fc6595672e8eb6a41bd1cd546d57c49ca663815c1bfe091707787dcc98d31c90c29a233ed8de287cd898d3f1bffd5e01a978b7cda6dfba8c6b23a666b7b01b3cdd8a634ec1201ab9558a5c45357a860e6e70212a0b92364a24dbb7c81256421becfee42184397bba53706af4dff26a54d614bec4641b865ceb8799e08960b818c8a3b8fc7998ca32a6e986d5e61c696b78ab9612d93b8eb0e0443d7f5fea6f062d4996aa5c1c1f0649480 |
| SignatureAlgorithmOID             | 1.2.840.113549.1.1.11 |
| IsCertificateAuthority            | True |
| SerialNumber                      | 03f1b4e15f3a82f1149678b3d7d8475c |
| Version                           | 3 |

{{< /details >}}
#### Imports
{{< details "Expand" >}}
* ntoskrnl.exe

{{< /details >}}
#### Imported Functions
{{< details "Expand" >}}
* IofCompleteRequest
* MmUnmapIoSpace
* strcpy
* MmMapIoSpace
* IoRaiseInformationalHardError
* RtlInitUnicodeString
* IoDeleteDevice
* IoDeleteSymbolicLink
* MmFreeNonCachedMemory
* IoCreateSymbolicLink
* IoCreateDevice
* MmAllocateNonCachedMemory
* IoQueryDeviceDescription
* KeBugCheckEx

{{< /details >}}
#### Exported Functions
{{< details "Expand" >}}

{{< /details >}}

#### Sections
{{< details "Expand" >}}
* .text
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
      "CertificateType": "Leaf (Code Signing)",
      "IsCA": false,
      "IsCertificateAuthority": false,
      "IsCodeSigning": true,
      "SerialNumber": "0d91d62ed03dda74e5efe8d70ae793c9",
      "Signature": "0d6ff3c3775d78638245067a52811b8d4de62370b8cefcb1323b8304f2445f4c3861bbe76b933ce316478d04af1bc45b578bbdc4fdc7f07148cb716cd7292c4f94133165a9fa7137f9679d45566381783bdd2f38db7a395d9653958a4ce211bd459724571339504e554f31066142a050d71d1134a4e8e07f15f77d44001821a8fbcc195395235845bc0dd0dc6c66f0449292736a44395be9ca15b063863cfbc8d9eb0f9da047fc9156ce272a8924529cd47a8697c681f2742855d726a3871e33fc5c1c698a37c9f389ba91049902a953b1f1fca4179011d49bcd04c26fccefb02b5dfae916ea909dc78430f9a26fb93bd09bb0098dac413e9af4f4f9f478c913",
      "SignatureAlgorithmOID": "1.2.840.113549.1.1.11",
      "Subject": "JURISDICTION_OF_INCORPORATION_C=TW, BUSINESS_CATEGORY=Private Organization, serialNumber=09424319, C=TW, ST=T\u0027ai,pei, L=New Taipei, O=CLEVO CO., CN=CLEVO CO.",
      "TBS": {
        "MD5": "c5edda178503ccfbc896cd596dba71ab",
        "SHA1": "7df69e18fcb66c69f1b17258919f2976988265bb",
        "SHA256": "59091d162fa68b89e157ddf3eb49d6be09a7ae6e16158980a00c7aaf1677ad2c",
        "SHA384": "e76a77ddcf5addcad9f86979645e26d6c4f191daa6fb58a2c7016082b9ad648081b6b4f73af456843a78f9ed60b74bcb"
      },
      "ValidFrom": "2018-08-21 00:00:00",
      "ValidTo": "2021-11-17 12:00:00",
      "Version": 3
    },
    {
      "CertificateType": "CA",
      "IsCA": true,
      "IsCertificateAuthority": true,
      "IsCodeSigning": true,
      "SerialNumber": "03f1b4e15f3a82f1149678b3d7d8475c",
      "Signature": "19334a0c813337dbad36c9e4c93abbb51b2e7aa2e2f44342179ebf4ea14de1b1dbe981dd9f01f2e488d5e9fe09fd21c1ec5d80d2f0d6c143c2fe772bdbf9d79133ce6cd5b2193be62ed6c9934f88408ecde1f57ef10fc6595672e8eb6a41bd1cd546d57c49ca663815c1bfe091707787dcc98d31c90c29a233ed8de287cd898d3f1bffd5e01a978b7cda6dfba8c6b23a666b7b01b3cdd8a634ec1201ab9558a5c45357a860e6e70212a0b92364a24dbb7c81256421becfee42184397bba53706af4dff26a54d614bec4641b865ceb8799e08960b818c8a3b8fc7998ca32a6e986d5e61c696b78ab9612d93b8eb0e0443d7f5fea6f062d4996aa5c1c1f0649480",
      "SignatureAlgorithmOID": "1.2.840.113549.1.1.11",
      "Subject": "C=US, O=DigiCert Inc, OU=www.digicert.com, CN=DigiCert EV Code Signing CA (SHA2)",
      "TBS": {
        "MD5": "83f5de89f641d0fbf60248e10a7b9534",
        "SHA1": "382a73a059a08698d6eb98c87e1b36fc750933a4",
        "SHA256": "eec58131dc11cd7f512501b15fdbc6074c603b68ca91f7162d5a042054edb0cf",
        "SHA384": "4a25018683cabfb8ec2cad136334f37f33c89aa8540326322991d997c8adfb7faf06ab602ebd46630fe75fe3d2edc6b1"
      },
      "ValidFrom": "2012-04-18 12:00:00",
      "ValidTo": "2027-04-18 12:00:00",
      "Version": 3
    }
  ],
  "CertificatesInfo": "",
  "Signer": [
    {
      "Issuer": "C=US, O=DigiCert Inc, OU=www.digicert.com, CN=DigiCert EV Code Signing CA (SHA2)",
      "SerialNumber": "0d91d62ed03dda74e5efe8d70ae793c9",
      "Version": 1
    }
  ],
  "SignerInfo": ""
}
```

{{< /details >}}
-----



[*source*](https://github.com/magicsword-io/LOLDrivers/blob/main/yaml/8fcec30c-f5ca-4aae-b2d8-77af60b78d42.yaml)

*last_updated:* 2026-08-31

{{< /column >}}
{{< /block >}}
