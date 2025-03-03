+++

description = ""
title = "dc3fdbd3-601a-4d2a-bf34-d2e84c6ff1d3"
weight = 10
displayTitle = "stdcdrvws64.sys"
+++


{{< block "grid-1" >}}
{{< column "mt-2 pt-1">}}


# stdcdrvws64.sys ![:inline](/images/twitter_verified.png) 

### Description

The Carbon Black Threat Analysis Unit (TAU) discovered 34 unique vulnerable drivers (237 file hashes) accepting firmware access. Six allow kernel memory access. All give full control of the devices to non-admin users. By exploiting the vulnerable drivers, an attacker without the system privilege may erase/alter firmware, and/or elevate privileges. As of the time of writing in October 2023, the filenames of the vulnerable drivers have not been made public until now.
- **UUID**: dc3fdbd3-601a-4d2a-bf34-d2e84c6ff1d3
- **Created**: 2023-11-02
- **Author**: Takahiro Haruyama
- **Acknowledgement**:  | [](https://twitter.com/)

{{< button "https://github.com/magicsword-io/LOLDrivers/raw/main/drivers/003dc41d148ec3286dc7df404ba3f2aa.bin" "Download" >}}{{< button "https://www.magicsword.io/premium" "Block" "red" >}}
{{< tip "warning" >}}
This download link contains the vulnerable driver!

{{< /tip >}}

### Commands

```
sc.exe create stdcdrvws64sys binPath= C:\windows\temp\stdcdrvws64sys.sys type=kernel &amp;&amp; sc.exe start stdcdrvws64sys
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
<li><a href="https://blogs.vmware.com/security/2023/10/hunting-vulnerable-kernel-drivers.html">https://blogs.vmware.com/security/2023/10/hunting-vulnerable-kernel-drivers.html</a></li>
<br>


### Known Vulnerable Samples

| Property           | Value |
|:-------------------|:------|
| Filename           |  |
| Creation Timestamp           | 2010-11-10 17:06:03 |
| MD5                | [003dc41d148ec3286dc7df404ba3f2aa](https://www.virustotal.com/gui/file/003dc41d148ec3286dc7df404ba3f2aa) |
| SHA1               | [948fa3149742f73bf3089893407df1b20f78a563](https://www.virustotal.com/gui/file/948fa3149742f73bf3089893407df1b20f78a563) |
| SHA256             | [70afdc0e11db840d5367afe53c35d9642c1cf616c7832ab283781d085988e505](https://www.virustotal.com/gui/file/70afdc0e11db840d5367afe53c35d9642c1cf616c7832ab283781d085988e505) |
| Authentihash MD5   | [fc47e6d80dc89fc8ac7d7a85a677f801](https://www.virustotal.com/gui/search/authentihash%253Afc47e6d80dc89fc8ac7d7a85a677f801) |
| Authentihash SHA1  | [68ea69d26c24877d531b180ffb81b2f6dfdc2b0b](https://www.virustotal.com/gui/search/authentihash%253A68ea69d26c24877d531b180ffb81b2f6dfdc2b0b) |
| Authentihash SHA256| [53f2bfe03b5d74c9db8c6a849e5a4690cba9a9861dd98c204865000506d8ce67](https://www.virustotal.com/gui/search/authentihash%253A53f2bfe03b5d74c9db8c6a849e5a4690cba9a9861dd98c204865000506d8ce67) |
| RichPEHeaderHash MD5   | [0a17c1f8d7cbaf754857362b16f43892](https://www.virustotal.com/gui/search/rich_pe_header_hash%253A0a17c1f8d7cbaf754857362b16f43892) |
| RichPEHeaderHash SHA1  | [9dbf81fa9b273a0f4ab917febba296c2eda0f6db](https://www.virustotal.com/gui/search/rich_pe_header_hash%253A9dbf81fa9b273a0f4ab917febba296c2eda0f6db) |
| RichPEHeaderHash SHA256| [20fe35301295c726603b7ad49bb178ba7ac2b2ebe8636f7a28ce043bc5ceb6d0](https://www.virustotal.com/gui/search/rich_pe_header_hash%253A20fe35301295c726603b7ad49bb178ba7ac2b2ebe8636f7a28ce043bc5ceb6d0) |
| Company           | Intel Corp. |
| Description       | SelfTest Data Collector Driver |
| Product           | SelfTest Data Collector Driver for Windows 7 x64 |
| OriginalFilename  | stdcdrvws64.sys |

{{< button "https://github.com/magicsword-io/LOLDrivers/raw/main/drivers/003dc41d148ec3286dc7df404ba3f2aa.bin" "Download" >}} 

#### Certificates

{{< details "Expand" >}}
###### Certificate 05b0ff
| Field                             | Value                      |
|-----------------------------------|----------------------------|
| ToBeSigned (TBS) MD5              | f532f9999c3f7a078f0f973c726a2a04  |
| ToBeSigned (TBS) SHA1             | f56832bc9412c372f9a8744591258f8bb11af2d8 |
| ToBeSigned (TBS) SHA256           | 4c75ce4be51027c4e1f7422775c3ae79d5195ffc0ff7f379123a603ccb702c60 |
| Subject                           | C=US, O=Intel Corporation, CN=Intel External Basic Policy CA |
| ValidFrom                         | 2006-02-16 18:01:30 |
| ValidTo                           | 2016-02-19 18:01:30 |
| Signature                         | 131038ada454a5489545b02d3772c09f9ed8ef8f0bfb9096d2b6177951cab3df067ebdb4e9083f84a00c939fb31ca86c8acf2deef99012f0f83a26d773810e9fc4319259d4282541f555f1ca3d993dda64c8d21864223209092d1de331fafdd347d764a8f95dea8227e24fd2612124611d54263e145964b098d5f3a7c3aead50 |
| SignatureAlgorithmOID             | 1.2.840.113549.1.1.5 |
| IsCertificateAuthority            | True |
| SerialNumber                      | 05b0ff |
| Version                           | 3 |
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
###### Certificate 610bdc8f00000000001a
| Field                             | Value                      |
|-----------------------------------|----------------------------|
| ToBeSigned (TBS) MD5              | 6e11ed171e9a07e607b8ca65bf0e8858  |
| ToBeSigned (TBS) SHA1             | 6d329a72420f76868584957854cdc45172e9f902 |
| ToBeSigned (TBS) SHA256           | 75efb8656a18ba5dacc596757bfb0fa11f0d3d81fd5f8cf9bb8975ced87e7b1b |
| Subject                           | C=US, O=Equifax, OU=Equifax Secure Certificate Authority |
| ValidFrom                         | 2006-05-23 17:01:15 |
| ValidTo                           | 2016-05-23 17:11:15 |
| Signature                         | 87a40f6b55916248ff54811ccf5db6c5a514aa671df485f6860d38b31c8d22ce7c867946fb71e16114d0ed4e46a48bca64654094f92ad7870ca9b7bedcc40bbd09c106eb9530841b9d8de7bc70c6f86539c4e5c4e65c8fcda130baef065e555290edd8587f15142ecc21a593dab8508d805e6e22a70fde8093add71d24b02aa2f4f20b98750131cc69bc359b3d13662f21bde54ec3639cc8518d59f5b600937ef10c35b0f4180dbfa7bdb2aae16b9f3ce6bb41b5d904e7c8a63abf8a5bdcaa9a3cd2c8dfcb1774163d78470b4c108e406616a0f300ede034998af0f9460ff27fbf202c972616d59e81da94a6dc61c8f18e092d4e32d03df682267d91d7a6c67bc1311d210ed4a342c1b4dfc0446b4f2aeebb29d62787b0a450ae1a9ab5f996f4ccabe52b3df166e2d5e1c3f0c687b659536638026e6194df1563aa415052f9bb64dc95e05b6c2aacfed6e603c21ff65557fe7e813fcb5a0bc1029cac84e47cd3f4c25a17c312706009ec82e5eccdd0b2106d69868c8da60e0416c57164ebd95bb8b08cfc32427e60846f655b7244272b846181f461d50fd51dbc05a27a5f937f26d1c8b3afa0190723e43e225d32d14a0fcee7b72a5c7b6e1c57126864e8337e8c501340a487b0d3a69b1eacbd3d7812bc52af09e0bab0508e5c81f98383af1482f50a6d035721bb9ac32e66fb04215b0a120fc1c907d63cecabf9a52f90883a |
| SignatureAlgorithmOID             | 1.2.840.113549.1.1.5 |
| IsCertificateAuthority            | True |
| SerialNumber                      | 610bdc8f00000000001a |
| Version                           | 3 |
###### Certificate 292cfc6e000100005eb6
| Field                             | Value                      |
|-----------------------------------|----------------------------|
| ToBeSigned (TBS) MD5              | 4e672f6873333f698c07a5d678a1847f  |
| ToBeSigned (TBS) SHA1             | 4c27cd07ca350df4687962868004d61c1301562a |
| ToBeSigned (TBS) SHA256           | c9d77b4a367333cad2994a39acc20659fe5efa6dde51e3a0e761e68149317360 |
| Subject                           | O=Intel Corporation, CN=Intel(R) Tools and Technologies, emailAddress=tnt.software@intel.com |
| ValidFrom                         | 2010-11-05 23:29:10 |
| ValidTo                           | 2013-10-20 23:29:10 |
| Signature                         | 757255ea1e69c1cfe215f84e34a2c1081855b9bcea4dda8e7bde4ad32c4e8a2ff39a72d2a5526ab1d78a05a853fd1dafc421d1ae9458fa32ece72f28b95e00b1a12c95692122857adcb3a8b16de609c0f52bd70bc2f2bb999f57f9cecd82ce43d89c8fcea47d5c418d32d77c3df300ebf8823c6a6c6543f3b5b2159dca614c0d6fd3bcedd53e541479925ce71689397f7e69078d3ee1697bee9224507e7e21ee3f80cf44668538220f4c0dac90125ff3d7f4c02335bf0fde1d2a6c81a3480abbc4a57bc6ddfcd2821bc09c5198a5cc6c972427e740b82bceb91eef73b6e8f0dbe9c532eeaeb53efe09fbb47dd208e3ac3fb8414bbdd793f77bd1a783ee3edc3a |
| SignatureAlgorithmOID             | 1.2.840.113549.1.1.5 |
| IsCertificateAuthority            | True |
| SerialNumber                      | 292cfc6e000100005eb6 |
| Version                           | 3 |
###### Certificate 61208a62000000000008
| Field                             | Value                      |
|-----------------------------------|----------------------------|
| ToBeSigned (TBS) MD5              | ebaa5c3e94eb970f0d7abc67a299662f  |
| ToBeSigned (TBS) SHA1             | fe7ed643c9193cc253850b8a3f2b81b37acb5c6a |
| ToBeSigned (TBS) SHA256           | 1f43b3cf2d48d52755d3d5ad7f8da7cd164321c394348b7dba6ee20f8e16910d |
| Subject                           | C=US, O=Intel Corporation, CN=Intel External Basic Issuing CA 3B |
| ValidFrom                         | 2009-05-15 19:27:26 |
| ValidTo                           | 2015-05-15 19:37:26 |
| Signature                         | b1b50107721550857ca312ab4c55431eea09263ec21ccc7c527aa35ba3d76c0feeb16d3eb9253fa8620a4802d7c4b185de509bb570286aa5bdb65396cc033ede690716e5bcde7ee7d6bc0ea5836d38f01f28733063feafb93f936962b50ef233a63788d38df26adc4959ef2156a72eeb077566fda37a01362a59f31b4bfc5f87e242c661f776ba1498c248d3f699247b0bb636e316736c1c336b2595f5bf194cefc2dbd618ec91310d3e685b55b7d38f98bf6469e1bf8b6623c4193c236d71e81726b7e1465d83f5b5a975338fad688b0d4ab3cb567a28bed370e4bf3c297c4470895e43dabbfb614d00a92280dadbe73edd703efa04537c0438b2f4cedbad0d |
| SignatureAlgorithmOID             | 1.2.840.113549.1.1.5 |
| IsCertificateAuthority            | True |
| SerialNumber                      | 61208a62000000000008 |
| Version                           | 3 |

{{< /details >}}
#### Imports
{{< details "Expand" >}}
* ntoskrnl.exe

{{< /details >}}
#### Imported Functions
{{< details "Expand" >}}
* IoDeleteSymbolicLink
* RtlInitUnicodeString
* IoDeleteDevice
* IofCompleteRequest
* IoCreateSymbolicLink
* IoCreateDevice
* DbgPrint
* ExAllocatePoolWithTag
* ExFreePoolWithTag
* KeSetSystemGroupAffinityThread
* KeQueryMaximumGroupCount
* KeQueryGroupAffinity
* MmUnmapIoSpace
* KeQueryActiveGroupCount
* MmGetPhysicalAddress
* MmMapIoSpace
* KeBugCheckEx
* __C_specific_handler

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
      "IsCertificateAuthority": true,
      "SerialNumber": "05b0ff",
      "Signature": "131038ada454a5489545b02d3772c09f9ed8ef8f0bfb9096d2b6177951cab3df067ebdb4e9083f84a00c939fb31ca86c8acf2deef99012f0f83a26d773810e9fc4319259d4282541f555f1ca3d993dda64c8d21864223209092d1de331fafdd347d764a8f95dea8227e24fd2612124611d54263e145964b098d5f3a7c3aead50",
      "SignatureAlgorithmOID": "1.2.840.113549.1.1.5",
      "Subject": "C=US, O=Intel Corporation, CN=Intel External Basic Policy CA",
      "TBS": {
        "MD5": "f532f9999c3f7a078f0f973c726a2a04",
        "SHA1": "f56832bc9412c372f9a8744591258f8bb11af2d8",
        "SHA256": "4c75ce4be51027c4e1f7422775c3ae79d5195ffc0ff7f379123a603ccb702c60",
        "SHA384": "084772ceb63ae50ebd8125ba9eba0c9b38d0e94a806f58513f71f1d5489f52489b0dfbb8c67603a425a603451b3b1719"
      },
      "ValidFrom": "2006-02-16 18:01:30",
      "ValidTo": "2016-02-19 18:01:30",
      "Version": 3
    },
    {
      "IsCertificateAuthority": false,
      "SerialNumber": "3825d7faf861af9ef490e726b5d65ad5",
      "Signature": "50c54bc82480dfe40d24c2de1ab1a102a1a6822d0c831581370a820e2cb05a1761b5d805fe88dbf19191b3561a40a6eb92be3839b07536743a984fe437ba9989ca95421db0b9c7a08d57e0fad5640442354e01d133a217c84daa27c7f2e1864c02384d8378c6fc53e0ebe00687dda4969e5e0c98e2a5bebf8285c360e1dfad28d8c7a54b64dac71b5bbdac3908d53822a1338b2f8a9aebbc07213f44410907b5651c24bc48d34480eba1cfc902b414cf54c716a3805cf9793e5d727d88179e2c43a2ca53ce7d3df62a3ab84f9400a56d0a835df95e53f418b3570f70c3fbf5ad95a00e17dec4168060c90f2b6e8604f1ebf47827d105c5ee345b5eb94932f233",
      "SignatureAlgorithmOID": "1.2.840.113549.1.1.5",
      "Subject": "C=US, O=VeriSign, Inc., CN=VeriSign Time Stamping Services Signer , G2",
      "TBS": {
        "MD5": "d6c7684e9aaa508cf268335f83afe040",
        "SHA1": "18066d20ad92409c567cdfde745279ff71c75226",
        "SHA256": "a612fb22ce8be6dab75e47c98508f98496583e79c9c97b936a8caee9ea9f3fff",
        "SHA384": "35c249d6ad0261a6229b2a727067ac6ba32a5d24b30b9249051f748c7735fbe2ec2ef26a702c50df1790fbe32a65aee7"
      },
      "ValidFrom": "2007-06-15 00:00:00",
      "ValidTo": "2012-06-14 23:59:59",
      "Version": 3
    },
    {
      "IsCertificateAuthority": true,
      "SerialNumber": "47bf1995df8d524643f7db6d480d31a4",
      "Signature": "4a6bf9ea58c2441c318979992b96bf82ac01d61c4ccdb08a586edf0829a35ec8ca9313e704520def47272f0038b0e4c9934e9ad4226215f73f37214f703180f18b3887b3e8e89700fecf55964e24d2a9274e7aaeb76141f32acee7c9d95eddbb2b853eb59db5d9e157ffbeb4c57ef5cf0c9ef097fe2bd33b521b1b3827f73f4a",
      "SignatureAlgorithmOID": "1.2.840.113549.1.1.5",
      "Subject": "C=US, O=VeriSign, Inc., CN=VeriSign Time Stamping Services CA",
      "TBS": {
        "MD5": "518d2ea8a21e879c942d504824ac211c",
        "SHA1": "21ce87d827077e61abddf2beba69fde5432ea031",
        "SHA256": "1ec3b4f02e03930a470020e0e48d24b84678bb558f46182888d870541f5e25c7",
        "SHA384": "53e346bbde23779a5d116cc9d86fdd71c97b1f1b343439f8a11aa1d3c87af63864bb8488a5aeb2d0c26a6a1e0b15f03f"
      },
      "ValidFrom": "2003-12-04 00:00:00",
      "ValidTo": "2013-12-03 23:59:59",
      "Version": 3
    },
    {
      "IsCertificateAuthority": true,
      "SerialNumber": "610bdc8f00000000001a",
      "Signature": "87a40f6b55916248ff54811ccf5db6c5a514aa671df485f6860d38b31c8d22ce7c867946fb71e16114d0ed4e46a48bca64654094f92ad7870ca9b7bedcc40bbd09c106eb9530841b9d8de7bc70c6f86539c4e5c4e65c8fcda130baef065e555290edd8587f15142ecc21a593dab8508d805e6e22a70fde8093add71d24b02aa2f4f20b98750131cc69bc359b3d13662f21bde54ec3639cc8518d59f5b600937ef10c35b0f4180dbfa7bdb2aae16b9f3ce6bb41b5d904e7c8a63abf8a5bdcaa9a3cd2c8dfcb1774163d78470b4c108e406616a0f300ede034998af0f9460ff27fbf202c972616d59e81da94a6dc61c8f18e092d4e32d03df682267d91d7a6c67bc1311d210ed4a342c1b4dfc0446b4f2aeebb29d62787b0a450ae1a9ab5f996f4ccabe52b3df166e2d5e1c3f0c687b659536638026e6194df1563aa415052f9bb64dc95e05b6c2aacfed6e603c21ff65557fe7e813fcb5a0bc1029cac84e47cd3f4c25a17c312706009ec82e5eccdd0b2106d69868c8da60e0416c57164ebd95bb8b08cfc32427e60846f655b7244272b846181f461d50fd51dbc05a27a5f937f26d1c8b3afa0190723e43e225d32d14a0fcee7b72a5c7b6e1c57126864e8337e8c501340a487b0d3a69b1eacbd3d7812bc52af09e0bab0508e5c81f98383af1482f50a6d035721bb9ac32e66fb04215b0a120fc1c907d63cecabf9a52f90883a",
      "SignatureAlgorithmOID": "1.2.840.113549.1.1.5",
      "Subject": "C=US, O=Equifax, OU=Equifax Secure Certificate Authority",
      "TBS": {
        "MD5": "6e11ed171e9a07e607b8ca65bf0e8858",
        "SHA1": "6d329a72420f76868584957854cdc45172e9f902",
        "SHA256": "75efb8656a18ba5dacc596757bfb0fa11f0d3d81fd5f8cf9bb8975ced87e7b1b",
        "SHA384": "c41060ed797c77588692c0b3e36e19cca2d48c354863437f3df76009e25c916e8d2c7e17b297fbc59da085e98d070093"
      },
      "ValidFrom": "2006-05-23 17:01:15",
      "ValidTo": "2016-05-23 17:11:15",
      "Version": 3
    },
    {
      "IsCertificateAuthority": true,
      "SerialNumber": "292cfc6e000100005eb6",
      "Signature": "757255ea1e69c1cfe215f84e34a2c1081855b9bcea4dda8e7bde4ad32c4e8a2ff39a72d2a5526ab1d78a05a853fd1dafc421d1ae9458fa32ece72f28b95e00b1a12c95692122857adcb3a8b16de609c0f52bd70bc2f2bb999f57f9cecd82ce43d89c8fcea47d5c418d32d77c3df300ebf8823c6a6c6543f3b5b2159dca614c0d6fd3bcedd53e541479925ce71689397f7e69078d3ee1697bee9224507e7e21ee3f80cf44668538220f4c0dac90125ff3d7f4c02335bf0fde1d2a6c81a3480abbc4a57bc6ddfcd2821bc09c5198a5cc6c972427e740b82bceb91eef73b6e8f0dbe9c532eeaeb53efe09fbb47dd208e3ac3fb8414bbdd793f77bd1a783ee3edc3a",
      "SignatureAlgorithmOID": "1.2.840.113549.1.1.5",
      "Subject": "O=Intel Corporation, CN=Intel(R) Tools and Technologies, emailAddress=tnt.software@intel.com",
      "TBS": {
        "MD5": "4e672f6873333f698c07a5d678a1847f",
        "SHA1": "4c27cd07ca350df4687962868004d61c1301562a",
        "SHA256": "c9d77b4a367333cad2994a39acc20659fe5efa6dde51e3a0e761e68149317360",
        "SHA384": "a09b43987fb726b5776aecc06ff9a3899c43b0beb5aff304a257168af79888e2dd69947ba7be5a855537b5a97f245e1a"
      },
      "ValidFrom": "2010-11-05 23:29:10",
      "ValidTo": "2013-10-20 23:29:10",
      "Version": 3
    },
    {
      "IsCertificateAuthority": true,
      "SerialNumber": "61208a62000000000008",
      "Signature": "b1b50107721550857ca312ab4c55431eea09263ec21ccc7c527aa35ba3d76c0feeb16d3eb9253fa8620a4802d7c4b185de509bb570286aa5bdb65396cc033ede690716e5bcde7ee7d6bc0ea5836d38f01f28733063feafb93f936962b50ef233a63788d38df26adc4959ef2156a72eeb077566fda37a01362a59f31b4bfc5f87e242c661f776ba1498c248d3f699247b0bb636e316736c1c336b2595f5bf194cefc2dbd618ec91310d3e685b55b7d38f98bf6469e1bf8b6623c4193c236d71e81726b7e1465d83f5b5a975338fad688b0d4ab3cb567a28bed370e4bf3c297c4470895e43dabbfb614d00a92280dadbe73edd703efa04537c0438b2f4cedbad0d",
      "SignatureAlgorithmOID": "1.2.840.113549.1.1.5",
      "Subject": "C=US, O=Intel Corporation, CN=Intel External Basic Issuing CA 3B",
      "TBS": {
        "MD5": "ebaa5c3e94eb970f0d7abc67a299662f",
        "SHA1": "fe7ed643c9193cc253850b8a3f2b81b37acb5c6a",
        "SHA256": "1f43b3cf2d48d52755d3d5ad7f8da7cd164321c394348b7dba6ee20f8e16910d",
        "SHA384": "482afbaf5738886a2063498f776a1085e27be57fa913eacadf2d318c98e509ef2cf1cbe99150b99284a3ee230f37083e"
      },
      "ValidFrom": "2009-05-15 19:27:26",
      "ValidTo": "2015-05-15 19:37:26",
      "Version": 3
    }
  ],
  "CertificatesInfo": "",
  "Signer": [
    {
      "Issuer": "C=US, O=Intel Corporation, CN=Intel External Basic Issuing CA 3B",
      "SerialNumber": "292cfc6e000100005eb6",
      "Version": 1
    }
  ],
  "SignerInfo": ""
}
```

{{< /details >}}
-----



[*source*](https://github.com/magicsword-io/LOLDrivers/tree/main/yaml/dc3fdbd3-601a-4d2a-bf34-d2e84c6ff1d3.yaml)

*last_updated:* 2025-03-03

{{< /column >}}
{{< /block >}}
