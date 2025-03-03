+++

description = ""
title = "cfd36b2e-cf96-498e-aeb6-ee20e7b33bbb"
weight = 10
displayTitle = "magdrvamd64.sys"
+++


{{< block "grid-1" >}}
{{< column "mt-2 pt-1">}}


# magdrvamd64.sys ![:inline](/images/twitter_verified.png) 

### Description

magdrvamd64.sys is a vulnerable driver and more information will be added as found.
- **UUID**: cfd36b2e-cf96-498e-aeb6-ee20e7b33bbb
- **Created**: 2023-01-09
- **Author**: Michael Haag
- **Acknowledgement**:  | [](https://twitter.com/)

{{< button "https://github.com/magicsword-io/LOLDrivers/raw/main/drivers/49938383844ceec33dba794fb751c9a5.bin" "Download" >}}{{< button "https://www.magicsword.io/premium" "Block" "red" >}}
{{< tip "warning" >}}
This download link contains the vulnerable driver!

{{< /tip >}}

### Commands

```
sc.exe create magdrvamd64.sys binPath=C:\windows\temp\magdrvamd64.sys     type=kernel &amp;&amp; sc.exe start magdrvamd64.sys
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
<li><a href="https://www.unknowncheats.me/forum/anti-cheat-bypass/334557-vulnerable-driver-megathread.html">https://www.unknowncheats.me/forum/anti-cheat-bypass/334557-vulnerable-driver-megathread.html</a></li>
<li><a href=""></a></li>
<br>


### Known Vulnerable Samples

| Property           | Value |
|:-------------------|:------|
| Filename           | magdrvamd64.sys |
| Creation Timestamp           | 2013-11-28 06:29:00 |
| MD5                | [49938383844ceec33dba794fb751c9a5](https://www.virustotal.com/gui/file/49938383844ceec33dba794fb751c9a5) |
| SHA1               | [e22495d92ac3dcae5eeb1980549a9ead8155f98a](https://www.virustotal.com/gui/file/e22495d92ac3dcae5eeb1980549a9ead8155f98a) |
| SHA256             | [be54f7279e69fb7651f98e91d24069dbc7c4c67e65850e486622ccbdc44d9a57](https://www.virustotal.com/gui/file/be54f7279e69fb7651f98e91d24069dbc7c4c67e65850e486622ccbdc44d9a57) |
| Authentihash MD5   | [4bc9c678b740fdbb6da3da4af3444c09](https://www.virustotal.com/gui/search/authentihash%253A4bc9c678b740fdbb6da3da4af3444c09) |
| Authentihash SHA1  | [592989e3e6942baf38127b50e39dd732b323a92d](https://www.virustotal.com/gui/search/authentihash%253A592989e3e6942baf38127b50e39dd732b323a92d) |
| Authentihash SHA256| [911e01544557544de4ad59b374f1234513821c50a00c7afa62a8fcca07385b2f](https://www.virustotal.com/gui/search/authentihash%253A911e01544557544de4ad59b374f1234513821c50a00c7afa62a8fcca07385b2f) |
| RichPEHeaderHash MD5   | [b600bdf31f987123de173daba685c687](https://www.virustotal.com/gui/search/rich_pe_header_hash%253Ab600bdf31f987123de173daba685c687) |
| RichPEHeaderHash SHA1  | [a843b261089202e7260aaaeda0c341dd471e60de](https://www.virustotal.com/gui/search/rich_pe_header_hash%253Aa843b261089202e7260aaaeda0c341dd471e60de) |
| RichPEHeaderHash SHA256| [631fce68262329c32a525e128948baa17c8438f89b68df4c9c460865dac05699](https://www.virustotal.com/gui/search/rich_pe_header_hash%253A631fce68262329c32a525e128948baa17c8438f89b68df4c9c460865dac05699) |

{{< button "https://github.com/magicsword-io/LOLDrivers/raw/main/drivers/49938383844ceec33dba794fb751c9a5.bin" "Download" >}} 

#### Certificates

{{< details "Expand" >}}
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
###### Certificate 478a8efb59e1d83f0ce142d2a28707be
| Field                             | Value                      |
|-----------------------------------|----------------------------|
| ToBeSigned (TBS) MD5              | f13ede9179075999ef7f856ec31e364b  |
| ToBeSigned (TBS) SHA1             | 2f09867166e6107e17808317f5c8d4ee157f45bc |
| ToBeSigned (TBS) SHA256           | 089a2c4c6ac7432020acdb65c33bf39130da6f37c002ba79128bd4c94e4fa101 |
| Subject                           | C=GB, ST=Greater Manchester, L=Salford, O=COMODO CA Limited, CN=COMODO Time Stamping Signer |
| ValidFrom                         | 2010-05-10 00:00:00 |
| ValidTo                           | 2015-05-10 23:59:59 |
| Signature                         | c8fb63f80b75752c3af1f213a72db6a31a9cad0107d3348e77e0c26eae025d484fa4d221b636fd2a35437c6bdf80870b15f0763200b4ceb567a42f2f201b9c549e833f1f5f149562820f2241221f70b3f3f742de6c51cd4bf821ac9b3b8cb1e5e6288fce2a8af9aa524d8c5b77ba4d5a58dbbb6a04cc521e9de228370ebbe70e91c7f8dbf18198ebcd37b30eab65d362ec3aa576eb13a83593c92e0a01ecc0e8cc3d7eb6ebe2c1ecd3149282668750dcfd5097acb34a767306c486113ab35f4304526feab3d074364ccaf11b7984377063ad74b9aa0ef398b08608ebdbe01f8c10f239649bae4f0a2c928a4f18b591e58d1a935f1faef1a6f02e97d0d2f62b3c |
| SignatureAlgorithmOID             | 1.2.840.113549.1.1.5 |
| IsCertificateAuthority            | False |
| SerialNumber                      | 478a8efb59e1d83f0ce142d2a28707be |
| Version                           | 3 |
###### Certificate 1121d54c6060d0acf70c52ceac844116f169
| Field                             | Value                      |
|-----------------------------------|----------------------------|
| ToBeSigned (TBS) MD5              | 8b286e174f9f82d6c4f68ff7f24942bd  |
| ToBeSigned (TBS) SHA1             | daa7914258adea501744674b7c67b4b6b857202b |
| ToBeSigned (TBS) SHA256           | dea433e56a62967d675adc7c758cb5a97da80a8bc69826b22a6677fc5ec43971 |
| Subject                           | C=KR, ST=Gyeonggi,Do / Korea, L=Hwasung,City, O=Samsung Electronics Co., Ltd., CN=Samsung Electronics Co., Ltd. |
| ValidFrom                         | 2012-10-09 11:25:07 |
| ValidTo                           | 2015-10-10 11:25:07 |
| Signature                         | 5fe3fc15d97d52d4b48417db069212fa1633b7b9d3b12f086f330cdcd18fd0e14f2a1a4ef4671d0be6f2a8608f47615d05c2f84aeb9efb68fcef3494fd8fdb25103da6d421066123c28af746358c1c8ea787b109fba16d159f1f3c654d92ce1f973e808267c2af6ed5f0cef0b5e749576fcfb38b8899fc9bdc7ba713f489a654d3564d82dbe16f0f2938dbf7edeade05fa9869ab6c642d37d93a7823e886cc308fbad46e0a9e76f6850d6b3edcd28402371bb2f53d062fb675ae2480602309b360b6ed1069a8fed7491ef01bda5e99db1f44fd87bf20f1518393d6b8836e19e0593da3b88e6548bb65600df0f9edea73414ad49ec400ab03445a9645f8e1025c |
| SignatureAlgorithmOID             | 1.2.840.113549.1.1.5 |
| IsCertificateAuthority            | False |
| SerialNumber                      | 1121d54c6060d0acf70c52ceac844116f169 |
| Version                           | 3 |
###### Certificate 6129152700000000002a
| Field                             | Value                      |
|-----------------------------------|----------------------------|
| ToBeSigned (TBS) MD5              | 0bb058d116f02817737920f112d9fd3b  |
| ToBeSigned (TBS) SHA1             | fd116235171a4feafedee586b7a59185fb5fd7e6 |
| ToBeSigned (TBS) SHA256           | f970426cc46d2ae0fc5f899fa19dbe76e05f07e525654c60c3c9399492c291f4 |
| Subject                           | C=BE, O=GlobalSign nv,sa, OU=Root CA, CN=GlobalSign Root CA |
| ValidFrom                         | 2011-04-15 19:55:08 |
| ValidTo                           | 2021-04-15 20:05:08 |
| Signature                         | 5ff8d065746a81c6a6ca5b03b6914ae84bbdef2ba142f0efb4a5adcd3389ec0b9585ac62501108aa58d25aa08310e5a6337af25af2c5fe787cf09c83df190ad97396002dd62ccde914d41d9de83f3c1a76f7904efb01350a6c9313a0c356eb67a0e4d17a96dec267f190f80a7bf5321b94ec5f751f8d1b34da6c58a7cb2d279e2226b7c9aa30cc0777b836e38201b5393ccc8dd9a75f7f23b3877fdb5798918bd7ce2520e39d644fdd87f72b68490318e0a5df7c5f68644d36838d4781f2e9e0a869abfa7b163c05a449ea8830190a6c73055178dfd41ddd3ad47f2de44e54be83431e7a7433b4a4ebd77073bc2a02988966eef6bc8f749378e329025a5a43e258ce7ccf9acad236893be25fda26054ec8d4e72c910e1797c5beee8b13112323294ffa83d050f6bafad53db3173df4ff034aa325dce67561d1fa35086bd62744d068b78d45e0eb852cc8a15d614474160e5958aed2b5eea5bcd6d7076ab62978fd976767dd8d4f17944fd2ed0caf972437c3a29c81da6be143b6577b4cecbf791319e79fe844e94781b75e701e91f83dd17b27f50b7056434805dda92fab86101d0b12e31ad04c6e75ded645b30b748887935c564a41029af7aeb799d8b67f88fa11f2457cf4d71b91c01cf1a0fbd4080a411a142acef4eb34486e66879ed54b7a397fbb0e3d3861cf735706e412066bd96b5308cd7018c22d4f974691bca9f0 |
| SignatureAlgorithmOID             | 1.2.840.113549.1.1.5 |
| IsCertificateAuthority            | True |
| SerialNumber                      | 6129152700000000002a |
| Version                           | 3 |

{{< /details >}}
#### Imports
{{< details "Expand" >}}
* NTOSKRNL.exe

{{< /details >}}
#### Imported Functions
{{< details "Expand" >}}
* IoDeleteDevice
* IoCreateSymbolicLink
* IoCreateDevice
* RtlInitUnicodeString
* IofCompleteRequest
* IoDeleteSymbolicLink
* MmUnmapIoSpace
* MmMapIoSpace

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
      "SerialNumber": "478a8efb59e1d83f0ce142d2a28707be",
      "Signature": "c8fb63f80b75752c3af1f213a72db6a31a9cad0107d3348e77e0c26eae025d484fa4d221b636fd2a35437c6bdf80870b15f0763200b4ceb567a42f2f201b9c549e833f1f5f149562820f2241221f70b3f3f742de6c51cd4bf821ac9b3b8cb1e5e6288fce2a8af9aa524d8c5b77ba4d5a58dbbb6a04cc521e9de228370ebbe70e91c7f8dbf18198ebcd37b30eab65d362ec3aa576eb13a83593c92e0a01ecc0e8cc3d7eb6ebe2c1ecd3149282668750dcfd5097acb34a767306c486113ab35f4304526feab3d074364ccaf11b7984377063ad74b9aa0ef398b08608ebdbe01f8c10f239649bae4f0a2c928a4f18b591e58d1a935f1faef1a6f02e97d0d2f62b3c",
      "SignatureAlgorithmOID": "1.2.840.113549.1.1.5",
      "Subject": "C=GB, ST=Greater Manchester, L=Salford, O=COMODO CA Limited, CN=COMODO Time Stamping Signer",
      "TBS": {
        "MD5": "f13ede9179075999ef7f856ec31e364b",
        "SHA1": "2f09867166e6107e17808317f5c8d4ee157f45bc",
        "SHA256": "089a2c4c6ac7432020acdb65c33bf39130da6f37c002ba79128bd4c94e4fa101",
        "SHA384": "67be6d358f4ecd0726163603a404db9d78c340951d43fd608482cd89a2de7f9566f0ce45f8222f420003157cb266b939"
      },
      "ValidFrom": "2010-05-10 00:00:00",
      "ValidTo": "2015-05-10 23:59:59",
      "Version": 3
    },
    {
      "IsCertificateAuthority": false,
      "SerialNumber": "1121d54c6060d0acf70c52ceac844116f169",
      "Signature": "5fe3fc15d97d52d4b48417db069212fa1633b7b9d3b12f086f330cdcd18fd0e14f2a1a4ef4671d0be6f2a8608f47615d05c2f84aeb9efb68fcef3494fd8fdb25103da6d421066123c28af746358c1c8ea787b109fba16d159f1f3c654d92ce1f973e808267c2af6ed5f0cef0b5e749576fcfb38b8899fc9bdc7ba713f489a654d3564d82dbe16f0f2938dbf7edeade05fa9869ab6c642d37d93a7823e886cc308fbad46e0a9e76f6850d6b3edcd28402371bb2f53d062fb675ae2480602309b360b6ed1069a8fed7491ef01bda5e99db1f44fd87bf20f1518393d6b8836e19e0593da3b88e6548bb65600df0f9edea73414ad49ec400ab03445a9645f8e1025c",
      "SignatureAlgorithmOID": "1.2.840.113549.1.1.5",
      "Subject": "C=KR, ST=Gyeonggi,Do / Korea, L=Hwasung,City, O=Samsung Electronics Co., Ltd., CN=Samsung Electronics Co., Ltd.",
      "TBS": {
        "MD5": "8b286e174f9f82d6c4f68ff7f24942bd",
        "SHA1": "daa7914258adea501744674b7c67b4b6b857202b",
        "SHA256": "dea433e56a62967d675adc7c758cb5a97da80a8bc69826b22a6677fc5ec43971",
        "SHA384": "0db739e7be37dbf14353298c00b90d083749a927441b11c970e078e70dfef4795a21b70d24900af534d96ac08dc99b26"
      },
      "ValidFrom": "2012-10-09 11:25:07",
      "ValidTo": "2015-10-10 11:25:07",
      "Version": 3
    },
    {
      "IsCertificateAuthority": true,
      "SerialNumber": "6129152700000000002a",
      "Signature": "5ff8d065746a81c6a6ca5b03b6914ae84bbdef2ba142f0efb4a5adcd3389ec0b9585ac62501108aa58d25aa08310e5a6337af25af2c5fe787cf09c83df190ad97396002dd62ccde914d41d9de83f3c1a76f7904efb01350a6c9313a0c356eb67a0e4d17a96dec267f190f80a7bf5321b94ec5f751f8d1b34da6c58a7cb2d279e2226b7c9aa30cc0777b836e38201b5393ccc8dd9a75f7f23b3877fdb5798918bd7ce2520e39d644fdd87f72b68490318e0a5df7c5f68644d36838d4781f2e9e0a869abfa7b163c05a449ea8830190a6c73055178dfd41ddd3ad47f2de44e54be83431e7a7433b4a4ebd77073bc2a02988966eef6bc8f749378e329025a5a43e258ce7ccf9acad236893be25fda26054ec8d4e72c910e1797c5beee8b13112323294ffa83d050f6bafad53db3173df4ff034aa325dce67561d1fa35086bd62744d068b78d45e0eb852cc8a15d614474160e5958aed2b5eea5bcd6d7076ab62978fd976767dd8d4f17944fd2ed0caf972437c3a29c81da6be143b6577b4cecbf791319e79fe844e94781b75e701e91f83dd17b27f50b7056434805dda92fab86101d0b12e31ad04c6e75ded645b30b748887935c564a41029af7aeb799d8b67f88fa11f2457cf4d71b91c01cf1a0fbd4080a411a142acef4eb34486e66879ed54b7a397fbb0e3d3861cf735706e412066bd96b5308cd7018c22d4f974691bca9f0",
      "SignatureAlgorithmOID": "1.2.840.113549.1.1.5",
      "Subject": "C=BE, O=GlobalSign nv,sa, OU=Root CA, CN=GlobalSign Root CA",
      "TBS": {
        "MD5": "0bb058d116f02817737920f112d9fd3b",
        "SHA1": "fd116235171a4feafedee586b7a59185fb5fd7e6",
        "SHA256": "f970426cc46d2ae0fc5f899fa19dbe76e05f07e525654c60c3c9399492c291f4",
        "SHA384": "c0df876be008c26ca407fe904e6f5e7ccded17f9c16830ce9f8022309c9e64c97f494810f152811ae43e223b82ad7cc6"
      },
      "ValidFrom": "2011-04-15 19:55:08",
      "ValidTo": "2021-04-15 20:05:08",
      "Version": 3
    }
  ],
  "CertificatesInfo": "",
  "Signer": [
    {
      "Issuer": "C=BE, O=GlobalSign nv,sa, CN=GlobalSign CodeSigning CA , G2",
      "SerialNumber": "1121d54c6060d0acf70c52ceac844116f169",
      "Version": 1
    }
  ],
  "SignerInfo": ""
}
```

{{< /details >}}
-----



[*source*](https://github.com/magicsword-io/LOLDrivers/tree/main/yaml/cfd36b2e-cf96-498e-aeb6-ee20e7b33bbb.yaml)

*last_updated:* 2025-03-03

{{< /column >}}
{{< /block >}}
