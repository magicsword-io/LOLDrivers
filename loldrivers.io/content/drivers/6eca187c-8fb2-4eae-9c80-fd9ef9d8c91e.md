+++

description = ""
title = "6eca187c-8fb2-4eae-9c80-fd9ef9d8c91e"
weight = 10
displayTitle = "QIOMem.sys"
+++


{{< block "grid-1" >}}
{{< column "mt-2 pt-1">}}


# QIOMem.sys ![:inline](/images/twitter_verified.png) 

### Description

QIOMem.sys is the Generic IO &amp; Memory Access driver included with Toshiba and Dynabook password utilities. It binds to ACPI\QCI0701; on systems without that firmware device, the public proof of concept creates a matching software PnP device to trigger loading of an already-installed driver package. Six IOCTLs (0x08012000 through 0x08012014) pass an unvalidated 32-bit physical address to MmMapIoSpace, allowing a low-privileged process to read or write one, two, or four bytes of physical memory below 4 GiB.
- **UUID**: 6eca187c-8fb2-4eae-9c80-fd9ef9d8c91e
- **Created**: 2026-07-10
- **Author**: valium
- **Acknowledgement**: Akshit Yadav | [@valium007](https://twitter.com/@valium007)

{{< button "https://github.com/magicsword-io/LOLDrivers/raw/main/drivers/43252ab49c9a43d22aa583c15e96f7b7.bin" "Download" >}}
{{< tip "warning" >}}
This download link contains the vulnerable driver!

{{< /tip >}}

{{< blockbanner "QIOMem.sys" >}}
### Commands

```
acpi.exe
```


| Use Case | Privileges | Operating System | 
|:---- | ---- | ---- |
| Read or write physical memory from a low-privileged process. | User | Windows 7, Windows 8, Windows 8.1, Windows 10, Windows 11 |



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
<li><a href="https://github.com/valium007/qiomem">https://github.com/valium007/qiomem</a></li>
<li><a href="https://valium007.github.io/posts/toshiba-vuln/">https://valium007.github.io/posts/toshiba-vuln/</a></li>
<li><a href="https://jvn.jp/vu/JVNVU91051826/">https://jvn.jp/vu/JVNVU91051826/</a></li>
<li><a href="https://www.cve.org/CVERecord?id=CVE-2026-56129">https://www.cve.org/CVERecord?id=CVE-2026-56129</a></li>
<li><a href="https://dynabook.com/assistpc/info/2026/20260619_security.htm">https://dynabook.com/assistpc/info/2026/20260619_security.htm</a></li>
<br>

### CVE

<li><a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2026-56129">CVE-2026-56129</a></li>

### Known Vulnerable Samples

| Property           | Value |
|:-------------------|:------|
| Filename           | QIOMem.sys |
| Creation Timestamp           | 2015-05-05 05:40:35 |
| MD5                | [43252ab49c9a43d22aa583c15e96f7b7](https://www.virustotal.com/gui/file/43252ab49c9a43d22aa583c15e96f7b7) |
| SHA1               | [ee37a040b6ec7882b4e240e70da67bc0900fd799](https://www.virustotal.com/gui/file/ee37a040b6ec7882b4e240e70da67bc0900fd799) |
| SHA256             | [6abd8d0d541bcf9e257c65122216b1d2ae92cbf8a3a3cb7ce340846e66c449ca](https://www.virustotal.com/gui/file/6abd8d0d541bcf9e257c65122216b1d2ae92cbf8a3a3cb7ce340846e66c449ca) |
| Authentihash MD5   | [e7d3aa85b456b305803472f276dd29f0](https://www.virustotal.com/gui/search/authentihash%253Ae7d3aa85b456b305803472f276dd29f0) |
| Authentihash SHA1  | [927108063af531702e54c89d3beb395f715f9706](https://www.virustotal.com/gui/search/authentihash%253A927108063af531702e54c89d3beb395f715f9706) |
| Authentihash SHA256| [de7b59f676aadcc0173e5a8d6b22f74f6a7f9c0ed906e5cc5f3e0fd821adb813](https://www.virustotal.com/gui/search/authentihash%253Ade7b59f676aadcc0173e5a8d6b22f74f6a7f9c0ed906e5cc5f3e0fd821adb813) |
| RichPEHeaderHash MD5   | [b06ee72c38688c22e116ef8109e4c6c8](https://www.virustotal.com/gui/search/rich_pe_header_hash%253Ab06ee72c38688c22e116ef8109e4c6c8) |
| RichPEHeaderHash SHA1  | [6fb19cea0bf673048937137ae021785a3c50f51b](https://www.virustotal.com/gui/search/rich_pe_header_hash%253A6fb19cea0bf673048937137ae021785a3c50f51b) |
| RichPEHeaderHash SHA256| [acace1751c5a54f5b9a1906ac66d24a79e8c8fa9148b50b2b8ebd4861ca91f10](https://www.virustotal.com/gui/search/rich_pe_header_hash%253Aacace1751c5a54f5b9a1906ac66d24a79e8c8fa9148b50b2b8ebd4861ca91f10) |
| Publisher         | Microsoft Windows Hardware Compatibility Publisher |
| Company           | TOSHIBA |
| Description       | Generic IO &amp; Memory Access |
| OriginalFilename  | QIOMem.sys |

{{< button "https://github.com/magicsword-io/LOLDrivers/raw/main/drivers/43252ab49c9a43d22aa583c15e96f7b7.bin" "Download" >}} 

#### Certificates

{{< details "Expand" >}}
###### Certificate 1fa194ec05480faf4587210ed5dadd0e
| Field                             | Value                      |
|-----------------------------------|----------------------------|
| ToBeSigned (TBS) MD5              | 320eaa8b2d51fe81279df22ddf8ad432  |
| ToBeSigned (TBS) SHA1             | c4cd618c351fb3ebeb4a311be5309c63c3b9a4c1 |
| ToBeSigned (TBS) SHA256           | f6b8e27adc02bc59edb9eba387c5e063ff0c3260567c5ab714e397ad8d916551 |
| Subject                           | CN=WDKTestCert 1,130752733198717037 |
| ValidFrom                         | 2015-05-05 04:22:00 |
| ValidTo                           | 2025-05-05 00:00:00 |
| Signature                         | 37263cc0f54f52c4e64f0c6352d5ace94b517ef3603ec03fe1d1f319d6e21e92f09dec78062be4bb8bd8bbd186b0244ac737c36a71c1369711ed41d33d3df12ea4e101cf87513257cce90d77b5b2c11124481b2c7af558bfe326909638bcd33dd2b5740db59e314b43e22ccb7bc6b12e66ab8a72a50d818e5beb1e897ae3b43e5f4437a4dccb05ab96ec5a3ea2315325c0399ce0854f14f2e2dbd0a64dc0abcd8b25be28d18eb93b96ee2f661ed467c51b5ae696e55ca46b123ae8c900bdee2124f210ad640a040eac4a6222ba1f880a2e8c214a81c4251ed1b3c33ca7d5f6ce77400f5f20a84fb39e0d27d9e57626fa3acc17e6f387852c461eeac29cd7e738 |
| SignatureAlgorithmOID             | 1.2.840.113549.1.1.5 |
| IsCertificateAuthority            | True |
| SerialNumber                      | 1fa194ec05480faf4587210ed5dadd0e |
| Version                           | 3 |

{{< /details >}}
#### Imports
{{< details "Expand" >}}
* ntoskrnl.exe

{{< /details >}}
#### Imported Functions
{{< details "Expand" >}}
* RtlFreeUnicodeString
* KeInitializeSpinLock
* IoAttachDeviceToDeviceStack
* IofCallDriver
* IofCompleteRequest
* IoCreateDevice
* IoDeleteDevice
* IoRegisterDeviceInterface
* KeInitializeEvent
* KeSetEvent
* KeWaitForSingleObject
* IoDetachDevice
* IoSetDeviceInterfaceState
* ExAllocatePoolWithTag
* ExFreePoolWithTag
* MmMapIoSpace
* MmUnmapIoSpace
* IoWMIOpenBlock
* IoWMIQuerySingleInstance
* IoWMISetSingleInstance
* IoReportTargetDeviceChangeAsynchronous
* PoRequestPowerIrp
* PoSetPowerState
* PoCallDriver
* PoStartNextPowerIrp
* IoAllocateIrp
* IoBuildDeviceIoControlRequest
* IoFreeIrp
* IoGetAttachedDeviceReference
* ObfDereferenceObject

{{< /details >}}
#### Exported Functions
{{< details "Expand" >}}

{{< /details >}}

#### Sections
{{< details "Expand" >}}
* LOCKED
* .text
* .rdata
* .data
* .pdata
* PAGE
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
      "CertificateType": "Leaf (Code Signing)",
      "IsCA": false,
      "IsCertificateAuthority": true,
      "IsCodeSigning": true,
      "SerialNumber": "1fa194ec05480faf4587210ed5dadd0e",
      "Signature": "37263cc0f54f52c4e64f0c6352d5ace94b517ef3603ec03fe1d1f319d6e21e92f09dec78062be4bb8bd8bbd186b0244ac737c36a71c1369711ed41d33d3df12ea4e101cf87513257cce90d77b5b2c11124481b2c7af558bfe326909638bcd33dd2b5740db59e314b43e22ccb7bc6b12e66ab8a72a50d818e5beb1e897ae3b43e5f4437a4dccb05ab96ec5a3ea2315325c0399ce0854f14f2e2dbd0a64dc0abcd8b25be28d18eb93b96ee2f661ed467c51b5ae696e55ca46b123ae8c900bdee2124f210ad640a040eac4a6222ba1f880a2e8c214a81c4251ed1b3c33ca7d5f6ce77400f5f20a84fb39e0d27d9e57626fa3acc17e6f387852c461eeac29cd7e738",
      "SignatureAlgorithmOID": "1.2.840.113549.1.1.5",
      "Subject": "CN=WDKTestCert 1,130752733198717037",
      "TBS": {
        "MD5": "320eaa8b2d51fe81279df22ddf8ad432",
        "SHA1": "c4cd618c351fb3ebeb4a311be5309c63c3b9a4c1",
        "SHA256": "f6b8e27adc02bc59edb9eba387c5e063ff0c3260567c5ab714e397ad8d916551",
        "SHA384": "e30ec578d02909be1d8cd6a5b7b3d405ccd4422531d8dcd9e738ecdd8155cd4c1216e66ed5e4b96e09f61aed4021bf37"
      },
      "ValidFrom": "2015-05-05 04:22:00",
      "ValidTo": "2025-05-05 00:00:00",
      "Version": 3
    }
  ],
  "CertificatesInfo": "",
  "Signer": [
    {
      "Issuer": "CN=WDKTestCert 1,130752733198717037",
      "SerialNumber": "1fa194ec05480faf4587210ed5dadd0e",
      "Version": 1
    }
  ],
  "SignerInfo": ""
}
```

{{< /details >}}
-----



[*source*](https://github.com/magicsword-io/LOLDrivers/blob/main/yaml/6eca187c-8fb2-4eae-9c80-fd9ef9d8c91e.yaml)

*last_updated:* 2026-08-12

{{< /column >}}
{{< /block >}}
