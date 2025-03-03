+++

description = ""
title = "0baa833c-e4e1-449e-86ee-cafeb11f5fd5"
weight = 10
displayTitle = "vboxguest.sys"
+++


{{< block "grid-1" >}}
{{< column "mt-2 pt-1">}}


# vboxguest.sys ![:inline](/images/twitter_verified.png) 

### Description

Confirmed vulnerable driver from Microsoft Block List
- **UUID**: 0baa833c-e4e1-449e-86ee-cafeb11f5fd5
- **Created**: 2023-07-22
- **Author**: Michael Haag
- **Acknowledgement**:  | [](https://twitter.com/)

{{< button "https://github.com/magicsword-io/LOLDrivers/raw/main/drivers/d04f5388e962cd21462bcc54180e84e0.bin" "Download" >}}{{< button "https://www.magicsword.io/premium" "Block" "red" >}}
{{< tip "warning" >}}

{{< /tip >}}



| Use Case | Privileges | Operating System | 
|:---- | ---- | ---- |
| Elevate privileges | kernel | Windows |



### Detections


{{< block "grid-3" >}}
{{< column >}}
#### YARA 🏹
{{< details "Expand" >}}

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
<li><a href="https://gist.github.com/mgraeber-rc/1bde6a2a83237f17b463d051d32e802c">https://gist.github.com/mgraeber-rc/1bde6a2a83237f17b463d051d32e802c</a></li>
<br>

### CVE

<li><a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name="></a></li>

### Known Vulnerable Samples

| Property           | Value |
|:-------------------|:------|
| Filename           |  |
| Creation Timestamp           | 2007-10-18 01:49:33 |
| MD5                | [d04f5388e962cd21462bcc54180e84e0](https://www.virustotal.com/gui/file/d04f5388e962cd21462bcc54180e84e0) |
| SHA1               | [73c2148626ae56cf2ff7686c6fd196ab6f653ffb](https://www.virustotal.com/gui/file/73c2148626ae56cf2ff7686c6fd196ab6f653ffb) |
| SHA256             | [983310cdce8397c016bfcfcc9c3a8abbb5c928b235bc3c3ae3a3cc10ef24dfbd](https://www.virustotal.com/gui/file/983310cdce8397c016bfcfcc9c3a8abbb5c928b235bc3c3ae3a3cc10ef24dfbd) |
| Authentihash MD5   | [c9fff1bf9b2dd3c53150aa7fa931e7a9](https://www.virustotal.com/gui/search/authentihash%253Ac9fff1bf9b2dd3c53150aa7fa931e7a9) |
| Authentihash SHA1  | [1824949e8cbe70954e2e5676c7559e32867eb7b4](https://www.virustotal.com/gui/search/authentihash%253A1824949e8cbe70954e2e5676c7559e32867eb7b4) |
| Authentihash SHA256| [c3fa8f5c8094a6c6936faff1d1faa02fd489482f21c288e6c700446ade5c20be](https://www.virustotal.com/gui/search/authentihash%253Ac3fa8f5c8094a6c6936faff1d1faa02fd489482f21c288e6c700446ade5c20be) |
| RichPEHeaderHash MD5   | [6057ec1f7b3ca1fd52c465c5a75e98ed](https://www.virustotal.com/gui/search/rich_pe_header_hash%253A6057ec1f7b3ca1fd52c465c5a75e98ed) |
| RichPEHeaderHash SHA1  | [c399b3582e5ba4798e5ce1a449f610bc9885b220](https://www.virustotal.com/gui/search/rich_pe_header_hash%253Ac399b3582e5ba4798e5ce1a449f610bc9885b220) |
| RichPEHeaderHash SHA256| [f4fef270af86e98eeb55def2f308797953172c6137e55244fdaf1ee08f48046f](https://www.virustotal.com/gui/search/rich_pe_header_hash%253Af4fef270af86e98eeb55def2f308797953172c6137e55244fdaf1ee08f48046f) |
| Company           | innotek GmbH |
| Description       | VirtualBox Guest Driver |
| Product           | VirtualBox Guest Additions |
| OriginalFilename  | vboxguest.sys |

{{< button "https://github.com/magicsword-io/LOLDrivers/raw/main/drivers/d04f5388e962cd21462bcc54180e84e0.bin" "Download" >}} 

#### Certificates

{{< details "Expand" >}}
###### Certificate 0100000000011006daed6b
| Field                             | Value                      |
|-----------------------------------|----------------------------|
| ToBeSigned (TBS) MD5              | bfbe9f4dc7264d47b48dbc2ec48aa897  |
| ToBeSigned (TBS) SHA1             | 699c3e67f349f262426097a4c9320951f0d56e8f |
| ToBeSigned (TBS) SHA256           | 785b2e779c33465eaba8a6326a40af1ff990d22a5493b55ce3c1f3aa04f3b3e2 |
| Subject                           | C=DE, O=InnoTek Systemberatung GmbH, CN=InnoTek Systemberatung GmbH, emailAddress=info@innotek.de |
| ValidFrom                         | 2007-01-09 12:35:15 |
| ValidTo                           | 2008-01-09 12:35:15 |
| Signature                         | afdad3534508399d12ede2f611e2d0eeb79cddeb8193638a13865632fad7e8c879fa7dc83a9731e81f85ceb8bf6ef42b257af4b265a03fa7b445ea06869fda28efe2e0642c277fcb46d1e3d14394a70872581cff992979238c319514f6665e7906c738d7152ce8ae0e5660392ed454ef57309d41a139f32e4ef4ecd1fe9c8560da48ab88522492523bf103ca8a47d3ac853fd6d3502788ef56a107baa0a7335e25dca7dc2aa6456240144ba583c206ec308ba5b04c1be2229126c4d817e723ca2b8eb36d692329e7372e0dc4d78d82ace182d44856e88163ef041e16b415ab851b2dba181948f3c92fbaad952e41e7922e7e5354687f63204e6c76455b01ab5c |
| SignatureAlgorithmOID             | 1.2.840.113549.1.1.5 |
| IsCertificateAuthority            | True |
| SerialNumber                      | 0100000000011006daed6b |
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
###### Certificate 04000000000108d9612448
| Field                             | Value                      |
|-----------------------------------|----------------------------|
| ToBeSigned (TBS) MD5              | 2fc76031fc24eec1ef3db2d246d21d6a  |
| ToBeSigned (TBS) SHA1             | 75c3a1f76b9dfa31ef6bf56325e7bd0bf6e4779d |
| ToBeSigned (TBS) SHA256           | 9238292d441c56dc89684c253343c17de3ed9cecd7f83d1d8f793b5ebc91f7b9 |
| Subject                           | C=BE, O=GlobalSign nv,sa, OU=ObjectSign CA, CN=GlobalSign ObjectSign CA |
| ValidFrom                         | 2004-01-22 09:00:00 |
| ValidTo                           | 2014-01-27 10:00:00 |
| Signature                         | 11d45d8af43d0d9d7e4fa70071610b56b34caa70e1b2d1dec7886d1d897c2ba946e58b1f8e4cc26695911fe34d394ae31b70b7446edc068a4d6d25e89812dcbca0dd864eae8f81130540905a542529944acaf165b4ef0679dae7cb86f004c918dcee72b320015748dfe333e12ccd9c077f9447278d888d340ca67c5c20c17d07b3736b648c26d29bd7e87965a6a891a174862a050282c1847cf279cd3c2a2b0f99291eea8c8a1ab16aeaa266380e65e1add8c6c91f888d3976ee1782c4138d97ce6341e77af5b4b66c15c33813b3930b620688dde1447f10a950248b60dc05f75ba514b27b56720b96eabffc057090659e051ca4dd07af4b57dec639673bc574 |
| SignatureAlgorithmOID             | 1.2.840.113549.1.1.5 |
| IsCertificateAuthority            | True |
| SerialNumber                      | 04000000000108d9612448 |
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
* IoCreateSymbolicLink
* IoCreateDevice
* RtlInitUnicodeString
* IofCompleteRequest
* KeWaitForSingleObject
* IofCallDriver
* KePulseEvent
* KeInsertQueueDpc
* MmMapIoSpace
* MmUnmapIoSpace
* PsGetVersion
* ObfDereferenceObject
* KeResetEvent
* ZwSetSystemTime
* ZwClose
* ObReferenceObjectByHandle
* PsCreateSystemThread
* KeInitializeEvent
* IoDeleteDevice
* PoCallDriver
* PoStartNextPowerIrp
* IoDetachDevice
* IoConnectInterrupt
* KeInitializeDpc
* IoFreeMdl
* MmProbeAndLockPages
* IoAllocateMdl
* _except_handler3
* MmUnlockPages
* KeInitializeMutex
* KeReleaseMutex
* ExAllocatePoolWithTag
* ExFreePoolWithTag
* MmFreeContiguousMemory
* MmGetPhysicalAddress
* MmAllocateContiguousMemory
* IoAttachDeviceToDeviceStack
* KeSetEvent
* IoDeleteSymbolicLink
* ExAcquireFastMutex
* ExReleaseFastMutex

{{< /details >}}
#### Exported Functions
{{< details "Expand" >}}
* AssertMsg1
* AssertMsg2
* RTLogBackdoorPrintf
* RTLogBackdoorPrintfV
* RTLogFormatV
* RTLogWriteUser
* RTMemAlloc
* RTMemAllocZ
* RTMemContAlloc
* RTMemContFree
* RTMemExecAlloc
* RTMemExecFree
* RTMemFree
* RTMemRealloc
* RTMemTmpAlloc
* RTMemTmpAllocZ
* RTMemTmpFree
* RTSemEventCreate
* RTSemEventDestroy
* RTSemEventSignal
* RTSemEventWait
* RTSemFastMutexCreate
* RTSemFastMutexDestroy
* RTSemFastMutexRelease
* RTSemFastMutexRequest
* RTSemMutexCreate
* RTSemMutexDestroy
* RTSemMutexRelease
* RTSemMutexRequest
* RTStrFormat
* RTStrFormatNumber
* RTStrFormatV

{{< /details >}}

#### Sections
{{< details "Expand" >}}
* .text
* .rdata
* .data
* PAGE
* .edata
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
      "IsCertificateAuthority": true,
      "SerialNumber": "0100000000011006daed6b",
      "Signature": "afdad3534508399d12ede2f611e2d0eeb79cddeb8193638a13865632fad7e8c879fa7dc83a9731e81f85ceb8bf6ef42b257af4b265a03fa7b445ea06869fda28efe2e0642c277fcb46d1e3d14394a70872581cff992979238c319514f6665e7906c738d7152ce8ae0e5660392ed454ef57309d41a139f32e4ef4ecd1fe9c8560da48ab88522492523bf103ca8a47d3ac853fd6d3502788ef56a107baa0a7335e25dca7dc2aa6456240144ba583c206ec308ba5b04c1be2229126c4d817e723ca2b8eb36d692329e7372e0dc4d78d82ace182d44856e88163ef041e16b415ab851b2dba181948f3c92fbaad952e41e7922e7e5354687f63204e6c76455b01ab5c",
      "SignatureAlgorithmOID": "1.2.840.113549.1.1.5",
      "Subject": "C=DE, O=InnoTek Systemberatung GmbH, CN=InnoTek Systemberatung GmbH, emailAddress=info@innotek.de",
      "TBS": {
        "MD5": "bfbe9f4dc7264d47b48dbc2ec48aa897",
        "SHA1": "699c3e67f349f262426097a4c9320951f0d56e8f",
        "SHA256": "785b2e779c33465eaba8a6326a40af1ff990d22a5493b55ce3c1f3aa04f3b3e2",
        "SHA384": "3178625856310ac3802a36f337bf9af1e2b62fbc7881221390cbd8f2e1be0f8d82c165dba90745f99c09c0bad2eced79"
      },
      "ValidFrom": "2007-01-09 12:35:15",
      "ValidTo": "2008-01-09 12:35:15",
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
      "SerialNumber": "04000000000108d9611cd6",
      "Signature": "a0422eb876a7427186404d464d5b26b0b074f93f89a87b7cb7f1c697e08239999d43fe60823642b55b878df55df4bbffa91044a871d3c7f12241f29aa4a5ec63fae5eb654a19309d8bc7b6fddc3fe16cfdd5521407fc6d24ccb3cc81a2c052f327b96d9e063dd8a849023269c7054294d0bbe3bba908c393501bdb846dc0ba1e5298659c1376bdb3d567292f1f7baa2c51a0fd854f263c48a38127a6feee7f7899c245cf9d1f527ed7958bfde1d020c3af7e51a22f663bab2dcf2d8e8c4d7d18392128fbdcae6d6581d0e0d7184be7b5f774d784e6522aac3b68fd3b4ab80154849132bb95d28e6330a69ece2396feab2eb86a8b74dcde21a114c2fbbf53af10",
      "SignatureAlgorithmOID": "1.2.840.113549.1.1.5",
      "Subject": "C=BE, O=GlobalSign nv,sa, OU=Primary Object Publishing CA, CN=GlobalSign Primary Object Publishing CA",
      "TBS": {
        "MD5": "698f075151097d84c0b1f3e7bc3d6fca",
        "SHA1": "041750993d7c9e063f02dfe74699598640911aab",
        "SHA256": "a8622cca0913a20477be8313b8d16fcad5d83088b46b36ddac10b31e96abb5e8",
        "SHA384": "a50291d3b15caf28d96e972cefcb88455a58ce1c802920fdcc2f4feafb1553510fd9b464d25e81635f4ad37570225a67"
      },
      "ValidFrom": "1999-01-28 12:00:00",
      "ValidTo": "2014-01-27 11:00:00",
      "Version": 3
    },
    {
      "IsCertificateAuthority": true,
      "SerialNumber": "04000000000108d9612448",
      "Signature": "11d45d8af43d0d9d7e4fa70071610b56b34caa70e1b2d1dec7886d1d897c2ba946e58b1f8e4cc26695911fe34d394ae31b70b7446edc068a4d6d25e89812dcbca0dd864eae8f81130540905a542529944acaf165b4ef0679dae7cb86f004c918dcee72b320015748dfe333e12ccd9c077f9447278d888d340ca67c5c20c17d07b3736b648c26d29bd7e87965a6a891a174862a050282c1847cf279cd3c2a2b0f99291eea8c8a1ab16aeaa266380e65e1add8c6c91f888d3976ee1782c4138d97ce6341e77af5b4b66c15c33813b3930b620688dde1447f10a950248b60dc05f75ba514b27b56720b96eabffc057090659e051ca4dd07af4b57dec639673bc574",
      "SignatureAlgorithmOID": "1.2.840.113549.1.1.5",
      "Subject": "C=BE, O=GlobalSign nv,sa, OU=ObjectSign CA, CN=GlobalSign ObjectSign CA",
      "TBS": {
        "MD5": "2fc76031fc24eec1ef3db2d246d21d6a",
        "SHA1": "75c3a1f76b9dfa31ef6bf56325e7bd0bf6e4779d",
        "SHA256": "9238292d441c56dc89684c253343c17de3ed9cecd7f83d1d8f793b5ebc91f7b9",
        "SHA384": "9279c1377eb701fdd79ef85038ff151cd8902169ba55fca84b9850f003563f73a1daaf869544252a2e42f06f58d2275f"
      },
      "ValidFrom": "2004-01-22 09:00:00",
      "ValidTo": "2014-01-27 10:00:00",
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
      "SerialNumber": "0100000000011006daed6b",
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
| Creation Timestamp           | 2008-02-19 09:09:00 |
| MD5                | [ff7cc8b6553ab57c53d5bc8afcf50f67](https://www.virustotal.com/gui/file/ff7cc8b6553ab57c53d5bc8afcf50f67) |
| SHA1               | [d5ac49a7ab274bceb6671e19524bd850e06513a0](https://www.virustotal.com/gui/file/d5ac49a7ab274bceb6671e19524bd850e06513a0) |
| SHA256             | [d53f9111a5e6c94b37e3f39c5860897405cb250dd11aa91c3814a98b1759c055](https://www.virustotal.com/gui/file/d53f9111a5e6c94b37e3f39c5860897405cb250dd11aa91c3814a98b1759c055) |
| Authentihash MD5   | [741b0c8a0a56340b62854cb121cb4930](https://www.virustotal.com/gui/search/authentihash%253A741b0c8a0a56340b62854cb121cb4930) |
| Authentihash SHA1  | [7618118dbe72c953e62e1bcac6b3c874ec43b72f](https://www.virustotal.com/gui/search/authentihash%253A7618118dbe72c953e62e1bcac6b3c874ec43b72f) |
| Authentihash SHA256| [bfbc382decb986b6050268e53092eae5e981cb886ccfb116ca7a0b311cef3862](https://www.virustotal.com/gui/search/authentihash%253Abfbc382decb986b6050268e53092eae5e981cb886ccfb116ca7a0b311cef3862) |
| RichPEHeaderHash MD5   | [5b7fb26b2a4fe53c9cb6b5941eaa8d54](https://www.virustotal.com/gui/search/rich_pe_header_hash%253A5b7fb26b2a4fe53c9cb6b5941eaa8d54) |
| RichPEHeaderHash SHA1  | [156da0d85961b6517852b0361ba53ef4bb892496](https://www.virustotal.com/gui/search/rich_pe_header_hash%253A156da0d85961b6517852b0361ba53ef4bb892496) |
| RichPEHeaderHash SHA256| [0980a5fac489d65fbe4d22d6a614017751b3df951aa67678f67b27956fb44d7f](https://www.virustotal.com/gui/search/rich_pe_header_hash%253A0980a5fac489d65fbe4d22d6a614017751b3df951aa67678f67b27956fb44d7f) |
| Company           | innotek GmbH |
| Description       | VirtualBox Guest Driver |
| Product           | VirtualBox Guest Additions |
| OriginalFilename  | vboxguest.sys |

{{< button "https://github.com/magicsword-io/LOLDrivers/raw/main/drivers/ff7cc8b6553ab57c53d5bc8afcf50f67.bin" "Download" >}} 

#### Certificates

{{< details "Expand" >}}
###### Certificate 010000000001171c092665
| Field                             | Value                      |
|-----------------------------------|----------------------------|
| ToBeSigned (TBS) MD5              | 5cfd8530475b20ed5a2bed70b37ee977  |
| ToBeSigned (TBS) SHA1             | 4761dbd41ba2b01f21b9306ca21e8add93a30f09 |
| ToBeSigned (TBS) SHA256           | 219041cc8d9e3248c69d9b116d440a0bbaa6aa500aa0c5de2d5af15908d83c7f |
| Subject                           | C=DE, O=innotek GmbH, CN=innotek GmbH, emailAddress=info@innotek.de |
| ValidFrom                         | 2007-12-27 14:37:17 |
| ValidTo                           | 2010-12-27 14:37:17 |
| Signature                         | 2a6d31919705290526ee3286d2825883af75a52ec1257276e9ab0eeff47a83adeab4bc2068eb7f76f84a356d466012e17b91d4f5c2913d28c73ee15018243e2ba7487f70d21f954eeeefb9854fc980d1ee61bf9a779e6e9a661938d7d9d6d101ddb49a9917264622f0ce4d63ac106b50769c38e9361a34f6cf5c5cae3ef50eb2a49d0f02c001af28d1f1fe250f2c99e5436b485a107eab17295180e5750eb31faee1ea0937a827bc140906a014b85409d8c48afbfcee20bf53f4e74661c1f555823c4bee18fde06e1e3e44fb8930e3ea84385e5006fd994fe8e69205a84ed7ed0f25c7b9f8fcb6f7d5b30188c27bf99050175afb1fc60f89ed2462ce999ca5dc |
| SignatureAlgorithmOID             | 1.2.840.113549.1.1.5 |
| IsCertificateAuthority            | True |
| SerialNumber                      | 010000000001171c092665 |
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
###### Certificate 04000000000108d9612448
| Field                             | Value                      |
|-----------------------------------|----------------------------|
| ToBeSigned (TBS) MD5              | 2fc76031fc24eec1ef3db2d246d21d6a  |
| ToBeSigned (TBS) SHA1             | 75c3a1f76b9dfa31ef6bf56325e7bd0bf6e4779d |
| ToBeSigned (TBS) SHA256           | 9238292d441c56dc89684c253343c17de3ed9cecd7f83d1d8f793b5ebc91f7b9 |
| Subject                           | C=BE, O=GlobalSign nv,sa, OU=ObjectSign CA, CN=GlobalSign ObjectSign CA |
| ValidFrom                         | 2004-01-22 09:00:00 |
| ValidTo                           | 2014-01-27 10:00:00 |
| Signature                         | 11d45d8af43d0d9d7e4fa70071610b56b34caa70e1b2d1dec7886d1d897c2ba946e58b1f8e4cc26695911fe34d394ae31b70b7446edc068a4d6d25e89812dcbca0dd864eae8f81130540905a542529944acaf165b4ef0679dae7cb86f004c918dcee72b320015748dfe333e12ccd9c077f9447278d888d340ca67c5c20c17d07b3736b648c26d29bd7e87965a6a891a174862a050282c1847cf279cd3c2a2b0f99291eea8c8a1ab16aeaa266380e65e1add8c6c91f888d3976ee1782c4138d97ce6341e77af5b4b66c15c33813b3930b620688dde1447f10a950248b60dc05f75ba514b27b56720b96eabffc057090659e051ca4dd07af4b57dec639673bc574 |
| SignatureAlgorithmOID             | 1.2.840.113549.1.1.5 |
| IsCertificateAuthority            | True |
| SerialNumber                      | 04000000000108d9612448 |
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
* IoDeleteDevice
* IoDeleteSymbolicLink
* RtlInitUnicodeString
* KeSetEvent
* ObfDereferenceObject
* KeResetEvent
* ZwSetSystemTime
* ZwClose
* ObReferenceObjectByHandle
* PsCreateSystemThread
* KeInitializeEvent
* PsGetVersion
* IoDisconnectInterrupt
* IoConnectInterrupt
* KeInitializeDpc
* MmUnmapIoSpace
* IoCreateSymbolicLink
* IoCreateDevice
* MmMapIoSpace
* KeInsertQueueDpc
* KePulseEvent
* KeWaitForSingleObject
* IoFreeMdl
* MmProbeAndLockPages
* IoAllocateMdl
* MmUnlockPages
* KeInitializeMutex
* KeReleaseMutex
* ExAllocatePool
* ExFreePool
* MmFreeContiguousMemory
* MmGetPhysicalAddress
* MmAllocateContiguousMemory
* RtlUnwind
* IoAttachDeviceToDeviceStack
* IofCompleteRequest
* ExReleaseFastMutex
* HalAssignSlotResources
* HalGetInterruptVector
* HalGetBusData
* ExAcquireFastMutex

{{< /details >}}
#### Exported Functions
{{< details "Expand" >}}
* AssertMsg1
* AssertMsg2
* RTLogBackdoorPrintf
* RTLogBackdoorPrintfV
* RTLogFormatV
* RTLogWriteUser
* RTMemAlloc
* RTMemAllocZ
* RTMemContAlloc
* RTMemContFree
* RTMemExecAlloc
* RTMemExecFree
* RTMemFree
* RTMemRealloc
* RTMemTmpAlloc
* RTMemTmpAllocZ
* RTMemTmpFree
* RTSemEventCreate
* RTSemEventDestroy
* RTSemEventSignal
* RTSemEventWait
* RTSemFastMutexCreate
* RTSemFastMutexDestroy
* RTSemFastMutexRelease
* RTSemFastMutexRequest
* RTSemMutexCreate
* RTSemMutexDestroy
* RTSemMutexRelease
* RTSemMutexRequest
* RTStrFormat
* RTStrFormatNumber
* RTStrFormatV

{{< /details >}}

#### Sections
{{< details "Expand" >}}
* .text
* .rdata
* .data
* PAGE
* .edata
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
      "IsCertificateAuthority": true,
      "SerialNumber": "0100000000011006daed6b",
      "Signature": "afdad3534508399d12ede2f611e2d0eeb79cddeb8193638a13865632fad7e8c879fa7dc83a9731e81f85ceb8bf6ef42b257af4b265a03fa7b445ea06869fda28efe2e0642c277fcb46d1e3d14394a70872581cff992979238c319514f6665e7906c738d7152ce8ae0e5660392ed454ef57309d41a139f32e4ef4ecd1fe9c8560da48ab88522492523bf103ca8a47d3ac853fd6d3502788ef56a107baa0a7335e25dca7dc2aa6456240144ba583c206ec308ba5b04c1be2229126c4d817e723ca2b8eb36d692329e7372e0dc4d78d82ace182d44856e88163ef041e16b415ab851b2dba181948f3c92fbaad952e41e7922e7e5354687f63204e6c76455b01ab5c",
      "SignatureAlgorithmOID": "1.2.840.113549.1.1.5",
      "Subject": "C=DE, O=InnoTek Systemberatung GmbH, CN=InnoTek Systemberatung GmbH, emailAddress=info@innotek.de",
      "TBS": {
        "MD5": "bfbe9f4dc7264d47b48dbc2ec48aa897",
        "SHA1": "699c3e67f349f262426097a4c9320951f0d56e8f",
        "SHA256": "785b2e779c33465eaba8a6326a40af1ff990d22a5493b55ce3c1f3aa04f3b3e2",
        "SHA384": "3178625856310ac3802a36f337bf9af1e2b62fbc7881221390cbd8f2e1be0f8d82c165dba90745f99c09c0bad2eced79"
      },
      "ValidFrom": "2007-01-09 12:35:15",
      "ValidTo": "2008-01-09 12:35:15",
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
      "SerialNumber": "04000000000108d9611cd6",
      "Signature": "a0422eb876a7427186404d464d5b26b0b074f93f89a87b7cb7f1c697e08239999d43fe60823642b55b878df55df4bbffa91044a871d3c7f12241f29aa4a5ec63fae5eb654a19309d8bc7b6fddc3fe16cfdd5521407fc6d24ccb3cc81a2c052f327b96d9e063dd8a849023269c7054294d0bbe3bba908c393501bdb846dc0ba1e5298659c1376bdb3d567292f1f7baa2c51a0fd854f263c48a38127a6feee7f7899c245cf9d1f527ed7958bfde1d020c3af7e51a22f663bab2dcf2d8e8c4d7d18392128fbdcae6d6581d0e0d7184be7b5f774d784e6522aac3b68fd3b4ab80154849132bb95d28e6330a69ece2396feab2eb86a8b74dcde21a114c2fbbf53af10",
      "SignatureAlgorithmOID": "1.2.840.113549.1.1.5",
      "Subject": "C=BE, O=GlobalSign nv,sa, OU=Primary Object Publishing CA, CN=GlobalSign Primary Object Publishing CA",
      "TBS": {
        "MD5": "698f075151097d84c0b1f3e7bc3d6fca",
        "SHA1": "041750993d7c9e063f02dfe74699598640911aab",
        "SHA256": "a8622cca0913a20477be8313b8d16fcad5d83088b46b36ddac10b31e96abb5e8",
        "SHA384": "a50291d3b15caf28d96e972cefcb88455a58ce1c802920fdcc2f4feafb1553510fd9b464d25e81635f4ad37570225a67"
      },
      "ValidFrom": "1999-01-28 12:00:00",
      "ValidTo": "2014-01-27 11:00:00",
      "Version": 3
    },
    {
      "IsCertificateAuthority": true,
      "SerialNumber": "04000000000108d9612448",
      "Signature": "11d45d8af43d0d9d7e4fa70071610b56b34caa70e1b2d1dec7886d1d897c2ba946e58b1f8e4cc26695911fe34d394ae31b70b7446edc068a4d6d25e89812dcbca0dd864eae8f81130540905a542529944acaf165b4ef0679dae7cb86f004c918dcee72b320015748dfe333e12ccd9c077f9447278d888d340ca67c5c20c17d07b3736b648c26d29bd7e87965a6a891a174862a050282c1847cf279cd3c2a2b0f99291eea8c8a1ab16aeaa266380e65e1add8c6c91f888d3976ee1782c4138d97ce6341e77af5b4b66c15c33813b3930b620688dde1447f10a950248b60dc05f75ba514b27b56720b96eabffc057090659e051ca4dd07af4b57dec639673bc574",
      "SignatureAlgorithmOID": "1.2.840.113549.1.1.5",
      "Subject": "C=BE, O=GlobalSign nv,sa, OU=ObjectSign CA, CN=GlobalSign ObjectSign CA",
      "TBS": {
        "MD5": "2fc76031fc24eec1ef3db2d246d21d6a",
        "SHA1": "75c3a1f76b9dfa31ef6bf56325e7bd0bf6e4779d",
        "SHA256": "9238292d441c56dc89684c253343c17de3ed9cecd7f83d1d8f793b5ebc91f7b9",
        "SHA384": "9279c1377eb701fdd79ef85038ff151cd8902169ba55fca84b9850f003563f73a1daaf869544252a2e42f06f58d2275f"
      },
      "ValidFrom": "2004-01-22 09:00:00",
      "ValidTo": "2014-01-27 10:00:00",
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
      "SerialNumber": "0100000000011006daed6b",
      "Version": 1
    }
  ],
  "SignerInfo": ""
}
```

{{< /details >}}
-----



[*source*](https://github.com/magicsword-io/LOLDrivers/tree/main/yaml/0baa833c-e4e1-449e-86ee-cafeb11f5fd5.yaml)

*last_updated:* 2025-03-03

{{< /column >}}
{{< /block >}}
