+++

description = ""
title = "3bf3fd5d-dee3-42da-b8be-6a0b8b7bc88c"
weight = 10
displayTitle = "probmon.sys"
+++


{{< block "grid-1" >}}
{{< column "mt-2 pt-1">}}


# probmon.sys ![:inline](/images/twitter_verified.png) 

### Description

A vulnerable kernel driver that can be used to terminate arbitrary processes
- **UUID**: 3bf3fd5d-dee3-42da-b8be-6a0b8b7bc88c
- **Created**: 2025-01-29
- **Author**: Antonio Parata, Andrea Monzani
- **Acknowledgement**:  | [](https://twitter.com/)

{{< button "https://github.com/magicsword-io/LOLDrivers/raw/main/drivers/8c8c93a6b6c6d6e632a54877fc1a209e.bin" "Download" >}}{{< button "https://www.magicsword.io/premium" "Block" "red" >}}
{{< tip "warning" >}}
This download link contains the vulnerable driver!

{{< /tip >}}

### Commands

```
sc.exe create probmon.sys binPath=C:\windows\temp\probmon.sys type=kernel &amp;&amp; sc.exe start probmon.sys
```


| Use Case | Privileges | Operating System | 
|:---- | ---- | ---- |
| EDR Kill | Admin privileges | Windows 10 |



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
<li><a href="Internal Research">Internal Research</a></li>
<li><a href="https://www.welivesecurity.com/en/eset-research/embargo-ransomware-rocknrust/">https://www.welivesecurity.com/en/eset-research/embargo-ransomware-rocknrust/</a></li>
<br>

### CVE

<li><a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-26506">CVE-2024-26506</a></li>

### Known Vulnerable Samples

| Property           | Value |
|:-------------------|:------|
| Filename           | probmon.sys |
| Creation Timestamp           | 2011-11-19 08:35:45 |
| MD5                | [8c8c93a6b6c6d6e632a54877fc1a209e](https://www.virustotal.com/gui/file/8c8c93a6b6c6d6e632a54877fc1a209e) |
| SHA1               | [7310d6399683ba3eb2f695a2071e0e45891d743b](https://www.virustotal.com/gui/file/7310d6399683ba3eb2f695a2071e0e45891d743b) |
| SHA256             | [023d722cbbdd04e3db77de7e6e3cfeabcef21ba5b2f04c3f3a33691801dd45eb](https://www.virustotal.com/gui/file/023d722cbbdd04e3db77de7e6e3cfeabcef21ba5b2f04c3f3a33691801dd45eb) |
| Authentihash MD5   | [9740e9ac3b5e4cdbd1a35d5032b94e1c](https://www.virustotal.com/gui/search/authentihash%253A9740e9ac3b5e4cdbd1a35d5032b94e1c) |
| Authentihash SHA1  | [c250f8111b95a0cfd72a1b83c0dd08d8727a1038](https://www.virustotal.com/gui/search/authentihash%253Ac250f8111b95a0cfd72a1b83c0dd08d8727a1038) |
| Authentihash SHA256| [e8bdfab9d5b5c37f6f23ddf9dddba2feb74261b61a80dee0c6aebffbf39948fb](https://www.virustotal.com/gui/search/authentihash%253Ae8bdfab9d5b5c37f6f23ddf9dddba2feb74261b61a80dee0c6aebffbf39948fb) |
| RichPEHeaderHash MD5   | [3eac8823498d67797e199e1000b7fb3f](https://www.virustotal.com/gui/search/rich_pe_header_hash%253A3eac8823498d67797e199e1000b7fb3f) |
| RichPEHeaderHash SHA1  | [d96373e6faf669eba3eee38a1619da8ce5670863](https://www.virustotal.com/gui/search/rich_pe_header_hash%253Ad96373e6faf669eba3eee38a1619da8ce5670863) |
| RichPEHeaderHash SHA256| [18fdcb1929dc4bb7cb78addfbcc4db6f93081b91e831c3bb33443d6a3d36ca98](https://www.virustotal.com/gui/search/rich_pe_header_hash%253A18fdcb1929dc4bb7cb78addfbcc4db6f93081b91e831c3bb33443d6a3d36ca98) |
| Company           | ITM SYSTEM |
| Description       | ITM SYSTEM File Filter Driver |
| OriginalFilename  | probmon.sys |

{{< button "https://github.com/magicsword-io/LOLDrivers/raw/main/drivers/8c8c93a6b6c6d6e632a54877fc1a209e.bin" "Download" >}} 

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
###### Certificate 040000000001239e0facb3
| Field                             | Value                      |
|-----------------------------------|----------------------------|
| ToBeSigned (TBS) MD5              | 5ccf05e4dec10d9d6fe15d8778325272  |
| ToBeSigned (TBS) SHA1             | 79f0a648bd7f1184f86bff43ae47c9ecc3ed3cec |
| ToBeSigned (TBS) SHA256           | 33ea31b892ba274a4aefe545de45c42c218b6dff78146655cdea892545c2cccc |
| Subject                           | C=BE, O=GlobalSign nv,sa, OU=Primary Object Publishing CA, CN=GlobalSign Primary Object Publishing CA |
| ValidFrom                         | 1999-01-28 13:00:00 |
| ValidTo                           | 2017-01-27 12:00:00 |
| Signature                         | b578a6a27c04b77fc97f7d6abc71fa293060c2f4621efe7f431e9b6ee2b21f730b85765b7df54e49062fd4fab79140efed6f8d8e138354c52a023d0aa4dc990b7abd772fcc40c18ff3c48c4e72ba107ce6ff642bc7ce6ca7fcd79a7c8e468d01834d423bdb9c3f9f326157d717b0b33666f0b3fd446f8137b1944ea7562589f58ad66d116262795c42900218d39c23fc08e86445b92d7e805b4eafc38a299283781f914134af85c5fd07994e2c5cfec7fd17bb2525314d72b5b5294b489a376f13c7114e4a451e7e2f319cabe852afd6679734885f0e276a6652d15ac7ac302c2038dd2bff3aebce104582a27b1ba12073569b2a93e60451066c1bdc2f899493 |
| SignatureAlgorithmOID             | 1.2.840.113549.1.1.5 |
| IsCertificateAuthority            | True |
| SerialNumber                      | 040000000001239e0facb3 |
| Version                           | 3 |
###### Certificate 010000000001306de166be
| Field                             | Value                      |
|-----------------------------------|----------------------------|
| ToBeSigned (TBS) MD5              | c172176f170f45cab913afc7334dc549  |
| ToBeSigned (TBS) SHA1             | 6390cd1cc7572283dbce9f3e9d8a02650e3c3553 |
| ToBeSigned (TBS) SHA256           | 8f33d08c897c3e6f82ca2c673ba4a1781479521d22f45f73190899b41897b6ea |
| Subject                           | C=KR, ST=Seoul, L=Guro,gu, O=ITM System Co.,LTD, OU=DevTeam, CN=ITM System Co.,LTD |
| ValidFrom                         | 2011-06-08 06:01:39 |
| ValidTo                           | 2014-06-07 08:32:23 |
| Signature                         | 9da885a314dddadff944fb879c832ba9d12f7605af23e7be90725104587ad434c3fa67855cd1a57dfb288c77840b9a13c051a3af770890ee88142950276db8b29868e2f01784c153cb36f17cf2a3f37445671f57e182fce569e2048923dac0ad7172afc3d3410ae4d61245b673471387aaa408486289bd8dfda8d949e61a8ec1f6ee0c2acdf7fa6dda23f6b0d256e8876dd2a0db5fd39210ef81b65d1ee0b535352cd31195c8b14ee9811e07161ecac7030d8285da7ba243f2ecd14dfe911523c33065e1d2fb74970043c29620c5cfaf8bfaa8284960cec56e3354bd94a0767bdb389c24a37fe2eec444dc1f8752017fb58845061243cab98f8f757634bf1154 |
| SignatureAlgorithmOID             | 1.2.840.113549.1.1.5 |
| IsCertificateAuthority            | False |
| SerialNumber                      | 010000000001306de166be |
| Version                           | 3 |
###### Certificate 040000000001239e0faf24
| Field                             | Value                      |
|-----------------------------------|----------------------------|
| ToBeSigned (TBS) MD5              | 7dd2351a85d3665eeb6720a21f4f7dee  |
| ToBeSigned (TBS) SHA1             | 77838c4d7f36958a581841d28f481d61ce0696ed |
| ToBeSigned (TBS) SHA256           | 846725f4b0193468c1079d6127e9e6e420fc6ed66019ed02d732ba644decad57 |
| Subject                           | C=BE, O=GlobalSign nv,sa, OU=ObjectSign CA, CN=GlobalSign ObjectSign CA |
| ValidFrom                         | 2004-01-22 10:00:00 |
| ValidTo                           | 2017-01-27 10:00:00 |
| Signature                         | 1e6af36df48ea922fe7008652ea15dab3330dd6c78fa4beaadc58dec107a6ac55897396b92f391e20ca7281cd15d768e8b077c136fadc43643b3c1bc3159cf1838d8a33bceffca6758bfe0f1ac613ea23b1ebc025b41ac446bf526f3ed5ea865f6ca65a63fcaf577eba5862a582956f8be161040e9d2fc572c636137662539202e0703a036032594bd7ceb7ed3a3c2c57616753092b9ff7641352168d10e5e5c8ec30360e68040fcc05da2546e6e9267a7811287a2a32bdbb74dffe4d5c7e505e6d5f1aefccd661821f33e47c9e59542612c9d2680b20fa83d0ec9a778df6e748c2c46f672e93c646b2855c44b6433cb78541338f0d57106d43e0d0a350ee0b3 |
| SignatureAlgorithmOID             | 1.2.840.113549.1.1.5 |
| IsCertificateAuthority            | True |
| SerialNumber                      | 040000000001239e0faf24 |
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
* FLTMGR.SYS

{{< /details >}}
#### Imported Functions
{{< details "Expand" >}}
* RtlInitUnicodeString
* KeInitializeEvent
* ZwSetValueKey
* PsSetCreateProcessNotifyRoutine
* KeEnterCriticalRegion
* KeDelayExecutionThread
* ZwCreateFile
* PsCreateSystemThread
* ExSystemTimeToLocalTime
* ExAcquireResourceSharedLite
* IoGetCurrentProcess
* ExReleaseResourceLite
* ZwClose
* RtlSetDaclSecurityDescriptor
* KeWaitForSingleObject
* KeBugCheckEx
* ZwFlushKey
* RtlTimeToTimeFields
* ZwOpenProcess
* ExInitializeResourceLite
* ZwTerminateProcess
* ZwQueryInformationFile
* ZwWriteFile
* DbgPrint
* IofCallDriver
* ZwReadFile
* IoBuildSynchronousFsdRequest
* KeLeaveCriticalRegion
* ExFreePoolWithTag
* ZwCreateKey
* ExAllocatePoolWithTag
* ObReferenceObjectByHandle
* ExAcquireResourceExclusiveLite
* RtlAnsiCharToUnicodeChar
* __C_specific_handler
* FltBuildDefaultSecurityDescriptor
* FltCloseCommunicationPort
* FltUnregisterFilter
* FltFreeSecurityDescriptor
* FltCreateCommunicationPort
* FltCloseClientPort
* FltRegisterFilter

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
* .reloc

{{< /details >}}
#### Signature
{{< details "Expand" >}}
```
{
  "Certificates": [
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
      "SerialNumber": "040000000001239e0facb3",
      "Signature": "b578a6a27c04b77fc97f7d6abc71fa293060c2f4621efe7f431e9b6ee2b21f730b85765b7df54e49062fd4fab79140efed6f8d8e138354c52a023d0aa4dc990b7abd772fcc40c18ff3c48c4e72ba107ce6ff642bc7ce6ca7fcd79a7c8e468d01834d423bdb9c3f9f326157d717b0b33666f0b3fd446f8137b1944ea7562589f58ad66d116262795c42900218d39c23fc08e86445b92d7e805b4eafc38a299283781f914134af85c5fd07994e2c5cfec7fd17bb2525314d72b5b5294b489a376f13c7114e4a451e7e2f319cabe852afd6679734885f0e276a6652d15ac7ac302c2038dd2bff3aebce104582a27b1ba12073569b2a93e60451066c1bdc2f899493",
      "SignatureAlgorithmOID": "1.2.840.113549.1.1.5",
      "Subject": "C=BE, O=GlobalSign nv,sa, OU=Primary Object Publishing CA, CN=GlobalSign Primary Object Publishing CA",
      "TBS": {
        "MD5": "5ccf05e4dec10d9d6fe15d8778325272",
        "SHA1": "79f0a648bd7f1184f86bff43ae47c9ecc3ed3cec",
        "SHA256": "33ea31b892ba274a4aefe545de45c42c218b6dff78146655cdea892545c2cccc",
        "SHA384": "1350ebc11fd20f5f141bc545786506e6a154be054da7a6e603cb276a6d60a24f2a4016ecc2f5cabd1088e1905f60aabf"
      },
      "ValidFrom": "1999-01-28 13:00:00",
      "ValidTo": "2017-01-27 12:00:00",
      "Version": 3
    },
    {
      "IsCertificateAuthority": false,
      "SerialNumber": "010000000001306de166be",
      "Signature": "9da885a314dddadff944fb879c832ba9d12f7605af23e7be90725104587ad434c3fa67855cd1a57dfb288c77840b9a13c051a3af770890ee88142950276db8b29868e2f01784c153cb36f17cf2a3f37445671f57e182fce569e2048923dac0ad7172afc3d3410ae4d61245b673471387aaa408486289bd8dfda8d949e61a8ec1f6ee0c2acdf7fa6dda23f6b0d256e8876dd2a0db5fd39210ef81b65d1ee0b535352cd31195c8b14ee9811e07161ecac7030d8285da7ba243f2ecd14dfe911523c33065e1d2fb74970043c29620c5cfaf8bfaa8284960cec56e3354bd94a0767bdb389c24a37fe2eec444dc1f8752017fb58845061243cab98f8f757634bf1154",
      "SignatureAlgorithmOID": "1.2.840.113549.1.1.5",
      "Subject": "C=KR, ST=Seoul, L=Guro,gu, O=ITM System Co.,LTD, OU=DevTeam, CN=ITM System Co.,LTD",
      "TBS": {
        "MD5": "c172176f170f45cab913afc7334dc549",
        "SHA1": "6390cd1cc7572283dbce9f3e9d8a02650e3c3553",
        "SHA256": "8f33d08c897c3e6f82ca2c673ba4a1781479521d22f45f73190899b41897b6ea",
        "SHA384": "d856baef204f1eb7a945024acd9f1571fa4d37ac3879a467b6f1eb7c1a867bc80de74890691c86ee6e75d4a90b20180f"
      },
      "ValidFrom": "2011-06-08 06:01:39",
      "ValidTo": "2014-06-07 08:32:23",
      "Version": 3
    },
    {
      "IsCertificateAuthority": true,
      "SerialNumber": "040000000001239e0faf24",
      "Signature": "1e6af36df48ea922fe7008652ea15dab3330dd6c78fa4beaadc58dec107a6ac55897396b92f391e20ca7281cd15d768e8b077c136fadc43643b3c1bc3159cf1838d8a33bceffca6758bfe0f1ac613ea23b1ebc025b41ac446bf526f3ed5ea865f6ca65a63fcaf577eba5862a582956f8be161040e9d2fc572c636137662539202e0703a036032594bd7ceb7ed3a3c2c57616753092b9ff7641352168d10e5e5c8ec30360e68040fcc05da2546e6e9267a7811287a2a32bdbb74dffe4d5c7e505e6d5f1aefccd661821f33e47c9e59542612c9d2680b20fa83d0ec9a778df6e748c2c46f672e93c646b2855c44b6433cb78541338f0d57106d43e0d0a350ee0b3",
      "SignatureAlgorithmOID": "1.2.840.113549.1.1.5",
      "Subject": "C=BE, O=GlobalSign nv,sa, OU=ObjectSign CA, CN=GlobalSign ObjectSign CA",
      "TBS": {
        "MD5": "7dd2351a85d3665eeb6720a21f4f7dee",
        "SHA1": "77838c4d7f36958a581841d28f481d61ce0696ed",
        "SHA256": "846725f4b0193468c1079d6127e9e6e420fc6ed66019ed02d732ba644decad57",
        "SHA384": "aaa45fe704bc66bb1842a2123c6e45e016dfbc7ba2ce07d7d2ee0b5d488a39c68bc6db582cb45d51f5fa52e60be8efd6"
      },
      "ValidFrom": "2004-01-22 10:00:00",
      "ValidTo": "2017-01-27 10:00:00",
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
      "Issuer": "C=BE, O=GlobalSign nv,sa, OU=ObjectSign CA, CN=GlobalSign ObjectSign CA",
      "SerialNumber": "010000000001306de166be",
      "Version": 1
    }
  ],
  "SignerInfo": ""
}
```

{{< /details >}}
-----



[*source*](https://github.com/magicsword-io/LOLDrivers/tree/main/yaml/3bf3fd5d-dee3-42da-b8be-6a0b8b7bc88c.yaml)

*last_updated:* 2025-03-03

{{< /column >}}
{{< /block >}}
