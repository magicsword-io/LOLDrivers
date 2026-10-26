+++

description = ""
title = "8b8bbbfe-798b-47bf-991b-21a0a0becef3"
weight = 10
displayTitle = "vsapint.sys"
+++


{{< block "grid-1" >}}
{{< column "mt-2 pt-1">}}


# vsapint.sys ![:inline](/images/twitter_verified.png) 

### Description

A vulnerable kernel driver that can be used to disable Code Integrity
- **UUID**: 8b8bbbfe-798b-47bf-991b-21a0a0becef3
- **Created**: 2026-10-25
- **Author**: Andrea Monzani
- **Acknowledgement**: Andrea Monzani, Davide Netti, Antonio Parata | [](https://twitter.com/)

{{< button "https://github.com/magicsword-io/LOLDrivers/raw/main/drivers/3e62bffd59054488001977738bb917c6.bin" "Download" >}}
{{< tip "warning" >}}
This download link contains the vulnerable driver!

{{< /tip >}}

{{< blockbanner "vsapint.sys" >}}
### Commands

```
sc.exe create vsapint binPath=C:\windows\temp\vsapint.sys type=kernel &amp;&amp; sc.exe start vsapint
```


| Use Case | Privileges | Operating System | 
|:---- | ---- | ---- |
| Elevate privileges | kernel | Windows 10 |



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
<li><a href="https://web.archive.org/web/20160808182709/https://kat.lua.cz/posts/Some_fun_with_vintage_bugs_and_driver_signing_enforcement/">https://web.archive.org/web/20160808182709/https://kat.lua.cz/posts/Some_fun_with_vintage_bugs_and_driver_signing_enforcement/</a></li>
<li><a href="https://doi.org/10.1016/j.cose.2026.105194">https://doi.org/10.1016/j.cose.2026.105194</a></li>
<br>


### Known Vulnerable Samples

| Property           | Value |
|:-------------------|:------|
| Filename           | vsapint.sys |
| Creation Timestamp           | 2024-10-08 12:04:08 |
| MD5                | [3e62bffd59054488001977738bb917c6](https://www.virustotal.com/gui/file/3e62bffd59054488001977738bb917c6) |
| SHA1               | [109f48aad567df4dbb5a2b33b1baa5db0fa9e422](https://www.virustotal.com/gui/file/109f48aad567df4dbb5a2b33b1baa5db0fa9e422) |
| SHA256             | [0e674d7e96e2e2e33ca96a5537cd4dd9db247249131ac91c44ebe9764efbfffe](https://www.virustotal.com/gui/file/0e674d7e96e2e2e33ca96a5537cd4dd9db247249131ac91c44ebe9764efbfffe) |
| Authentihash MD5   | [46f3e2fe2824a0283fe717c0fe89b567](https://www.virustotal.com/gui/search/authentihash%253A46f3e2fe2824a0283fe717c0fe89b567) |
| Authentihash SHA1  | [5ecef80a764c8e52ca66ad0febbce6e09aa2c1ea](https://www.virustotal.com/gui/search/authentihash%253A5ecef80a764c8e52ca66ad0febbce6e09aa2c1ea) |
| Authentihash SHA256| [7e748ee7c0caaacbded97da7d2dd307de6520004a32bd96980e39523a19f744b](https://www.virustotal.com/gui/search/authentihash%253A7e748ee7c0caaacbded97da7d2dd307de6520004a32bd96980e39523a19f744b) |
| RichPEHeaderHash MD5   | [1d655196a84efc729e865813be7eff71](https://www.virustotal.com/gui/search/rich_pe_header_hash%253A1d655196a84efc729e865813be7eff71) |
| RichPEHeaderHash SHA1  | [3a8cc12028110dac08447af9825f68a449d5f33e](https://www.virustotal.com/gui/search/rich_pe_header_hash%253A3a8cc12028110dac08447af9825f68a449d5f33e) |
| RichPEHeaderHash SHA256| [ab50eed62287613b57467bbdd5b14bf1ae77d0395331384339c23361881f985f](https://www.virustotal.com/gui/search/rich_pe_header_hash%253Aab50eed62287613b57467bbdd5b14bf1ae77d0395331384339c23361881f985f) |

{{< button "https://github.com/magicsword-io/LOLDrivers/raw/main/drivers/3e62bffd59054488001977738bb917c6.bin" "Download" >}} 

#### Certificates

{{< details "Expand" >}}
###### Certificate 3300000110bbda1909b3f83897000000000110
| Field                             | Value                      |
|-----------------------------------|----------------------------|
| ToBeSigned (TBS) MD5              | dca6a67d48ad7ecdb2e445f502a8eb98  |
| ToBeSigned (TBS) SHA1             | 3a7630b4eeaf580dd8212039061c044504cd2741 |
| ToBeSigned (TBS) SHA256           | c7cd78241a66b6992cbe11a2773e8df626ecc6443c09204075b1818d6409caf7 |
| Subject                           | C=US, ST=Washington, L=Redmond, O=Microsoft Corporation, CN=Microsoft Windows Hardware Compatibility Publisher |
| ValidFrom                         | 2024-05-16 22:16:05 |
| ValidTo                           | 2025-05-14 22:16:05 |
| Signature                         | 59e526577072d951ca2b437f0eef40e4b19e73d0b8ec1c64d0e9a996978612e67bf32d77f143ae724db9ab2e2221da438aaab784799b2885c4a196315f7a6bfeda8be53518cd47cbb271d5e3dbdaa5917275d75b03097fe23504897a00797315aaa7e88d0b492956428b2086a866f4974bd1a282af175e3a27acd56c206d313cdecad2289c10867c8a3a7f24ea28831f9b574c47c86af5504c7d5647925cfa16e88c943f93aa6cc6bc3494d57661007189adf6498751ea2a8a607dfc79125d5e1398b8f98466b39427ac43b65c327c2e8347d4940c769054829ce7ca3ca32e0714532a075ed193bdc42fc8d102419acc65a565e0bd031efe41d7437148ca28af |
| SignatureAlgorithmOID             | 1.2.840.113549.1.1.11 |
| IsCertificateAuthority            | False |
| SerialNumber                      | 3300000110bbda1909b3f83897000000000110 |
| Version                           | 3 |
###### Certificate 610baac1000000000009
| Field                             | Value                      |
|-----------------------------------|----------------------------|
| ToBeSigned (TBS) MD5              | a569061297e8e824767dbc3184a69bea  |
| ToBeSigned (TBS) SHA1             | adbb26a587a8f44b4fccaecb306f980d1c55a150 |
| ToBeSigned (TBS) SHA256           | cec1afd0e310c55c1dcc601ab8e172917706aa32fb5eaf826813547fdf02dd46 |
| Subject                           | C=US, ST=Washington, L=Redmond, O=Microsoft Corporation, CN=Microsoft Windows Third Party Component CA 2012 |
| ValidFrom                         | 2012-04-18 23:48:38 |
| ValidTo                           | 2027-04-18 23:58:38 |
| Signature                         | 5a8a67daccd5fd0d264177bf0a4678b4b3de12692b7723c2652f015fd203f461ba509d2e8c3972f36c3e6ab11e766decb7f382dcccbbc56970287366173f54ebee011648c446d91b80ae813a8d0f796d68b09eea2d3f39d3ca387ebd5e7c086e19dcc6c2f438336861e2524783e1000156d2bacb878205310a418b4ee77f5f5fed5fd3392d45eba213bffd1ec298417161165fc80a70257c59693124e471e70abb0417f79f721ec9d2bb1abe3d02fe090cb243b4591a99539396215fe0d6b72601429536ac27fdbef48577683d18bdf4be98882211865216f345ec0397107087a37043713cdbc98603170cf5735bc67de15c64edd7c548d7ed32e2d1aad3cfa7f6574e61f977eb67f288b3de00da038fd08a34373e1dd862b8d2b1f3e12f8b723b81967c6ffcec667672601b24f2a0896d5b6d002eef28dd868705c2b4b9e5be64c22af24a155c98e2c42785ff52e3627e0fb2020bd766c70ab2d33d200414503259830a7d9bed5a38120152ba2f5e20728e4af1fde771028c3be107bec973f4dd47d8b4efb4a4b330b9893e76cab90098567eabea8ab8a5d038ab6977130b142fe9aa411ff7babd3a2b348aee0aab63e663f788248e200d2b3b9de3c24952ac9f1f0e393b5dd46e506ae67d523aaa7c3315290d265e0158a74ea93d7a846f743f609fe4324f3600af6d71d33ea646655f8174f1fec171da4ca0415a82ddf11f |
| SignatureAlgorithmOID             | 1.2.840.113549.1.1.11 |
| IsCertificateAuthority            | True |
| SerialNumber                      | 610baac1000000000009 |
| Version                           | 3 |

{{< /details >}}
#### Imports
{{< details "Expand" >}}
* ntoskrnl.exe

{{< /details >}}
#### Imported Functions
{{< details "Expand" >}}
* sprintf
* _stricmp
* IofCompleteRequest
* RtlInitUnicodeString
* ZwClose
* ZwCreateKey
* ZwSetValueKey
* mbstowcs
* RtlWriteRegistryValue
* RtlCopyUnicodeString
* RtlGetVersion
* KeInitializeEvent
* MmGetSystemRoutineAddress
* PsGetVersion
* IoCreateDevice
* IoCreateSymbolicLink
* IoDeleteDevice
* IoRegisterShutdownNotification
* wcsrchr
* _wcsicmp
* wcsncpy
* RtlQueryRegistryValues
* DbgPrint
* KeDelayExecutionThread
* ExAllocatePoolWithTag
* ExFreePoolWithTag
* ZwCreateFile
* ZwQueryInformationFile
* KeSetEvent
* KeWaitForSingleObject
* ObfDereferenceObject
* MmIsAddressValid
* MmMapViewInSystemSpace
* MmUnmapViewInSystemSpace
* MmCreateSection
* IoBuildDeviceIoControlRequest
* IofCallDriver
* IoGetDeviceObjectPointer
* ObReferenceObjectByHandle
* ZwSetInformationFile
* ZwReadFile
* ZwWriteFile
* ZwCreateSection
* ZwMapViewOfSection
* ZwUnmapViewOfSection
* ZwCreateEvent
* ZwQueryDirectoryFile
* ZwDuplicateObject
* ZwQuerySecurityObject
* IoDeleteSymbolicLink
* IoUnregisterShutdownNotification
* KeWaitForMultipleObjects
* PsCreateSystemThread
* PsTerminateSystemThread
* ZwOpenKey
* PsGetCurrentThreadId
* ZwNotifyChangeKey
* __C_specific_handler
* strchr
* strncpy
* strrchr
* strcmp
* strncmp
* wcschr
* swprintf
* atol
* strstr
* atoi
* _wcsnicmp
* tolower
* toupper
* _strnicmp
* RtlTimeToTimeFields
* KeEnterCriticalRegion
* KeLeaveCriticalRegion
* ExAcquireFastMutexUnsafe
* ExReleaseFastMutexUnsafe
* PsGetCurrentProcessId
* RtlUnicodeToMultiByteSize
* RtlUnicodeToMultiByteN
* NtSetSecurityObject
* ObOpenObjectByPointer
* KeBugCheckEx

{{< /details >}}
#### Exported Functions
{{< details "Expand" >}}
* AllocVsapiResourceForNtNativeResource
* FreeVsapiResourceForNtNativeResource
* IsVsapiWT
* KDGetFileAttributes
* KDGetFileAttributesW
* KDReadFile
* KDSetFileAttributes
* KDSetFileAttributesW
* KDWriteFile
* MapR0NameToR3Name
* MapR0NameToR3NameW
* MapR3NameToR0Name
* MapR3NameToR0NameW
* QueryKeyValue
* QueryStringValueUnderCurrentVersion
* QuerySystemRoot
* TMCopySecurityDescriptor
* TMQuerySecurityObject
* TMSetSecurityObject
* VSAccess
* VSAccessW
* VSActOnFile
* VSAddArchProcessExcludeExtName
* VSAddArchProcessExtName
* VSAddDataType
* VSAddPackPolicyExcludeName
* VSAddProcessExcludeExtName
* VSAddProcessExtName
* VSAddSpywareExcludeName
* VSAllocateMemoryArray
* VSArchFileNeedProcess
* VSBackupFile
* VSBackupFileW
* VSBackupResourceW
* VSBackupVSCData
* VSBaseName
* VSCalculateCRC
* VSCharType
* VSCheckPatternFileW
* VSCheckResourceIntegrity
* VSCleanVirus
* VSCleanVirusW
* VSClearArchProcessExcludeExtNameTable
* VSClearArchProcessExtNameTable
* VSClearPackPolicyExcludeNameTable
* VSClearProcessExcludeExtNameTable
* VSClearProcessExtNameTable
* VSClearSpywareExcludeNameTable
* VSCloseFile
* VSCloseIOFromHandle
* VSCloseResource
* VSConvertCharacter
* VSCopyFile
* VSCopyFileFD
* VSCopyFileW
* VSCrc32
* VSCreateDirectoryTree
* VSCreateDirectoryTreeA
* VSCreateDirectoryTreeU
* VSCreateDirectoryTreeW
* VSDCIsCompressed
* VSDataType
* VSDataTypeFD
* VSDecompress
* VSDecompressFile
* VSDelDataType
* VSDelUserDecodeFunc
* VSDeleteArchProcessExcludeExtName
* VSDeleteArchProcessExtName
* VSDeleteDirectoryFile
* VSDeleteDirectoryFileW
* VSDeleteFile
* VSDeleteFileW
* VSDeletePackPolicyExcludeName
* VSDeleteProcessExcludeExtName
* VSDeleteProcessExtName
* VSDeleteSpywareExcludeName
* VSDisablePattern
* VSEncBackupFile
* VSEncBackupFileW
* VSFileNeedProcess
* VSFindCloseFile
* VSFindFirstFile
* VSFindFirstFileW
* VSFindNextFile
* VSFindNextFileW
* VSFormatDate
* VSFreeMemUsageArray
* VSFreePatternList
* VSFreePatternNode
* VSFullPathTransform
* VSGetActiveScanFlag
* VSGetArchProcessExcludeExtName
* VSGetArchProcessExcludeExtNumber
* VSGetArchProcessExtName
* VSGetArchProcessExtNumber
* VSGetArchProcessExtTableSize
* VSGetBackupEncodeFlag
* VSGetBackupFileInfo
* VSGetBackupFileInfoW
* VSGetCharacterEnvType
* VSGetCleanBackupFlag
* VSGetCleanZipFlag
* VSGetConfChangeFlag
* VSGetConfig
* VSGetConfigEx
* VSGetCurrentPatternFileInternalVersion
* VSGetCurrentPatternFileVersion
* VSGetDataTypeInfo
* VSGetDebug
* VSGetDecodeFlag
* VSGetDecompressLayer
* VSGetDefaultExcludeExtList
* VSGetDefaultExcludeExtListSize
* VSGetDefaultExtList
* VSGetDefaultExtListSize
* VSGetDefaultHospitalPath
* VSGetDefaultPatternFile
* VSGetDefaultPatternPath
* VSGetDefaultTempPath
* VSGetDetectableVirusNumber
* VSGetDetectionExcludeNames
* VSGetEncodeAction
* VSGetEncryptTempFileFlag
* VSGetExpandLiteFlag
* VSGetExtractAmgFlag
* VSGetExtractArchiveFlag
* VSGetExtractFileCountLimit
* VSGetExtractFileRatioLimit
* VSGetExtractFileSizeLimit
* VSGetExtractFileSizeLimitByVSDT
* VSGetExtractPath
* VSGetFileAttributes
* VSGetFileAttributesByHandle
* VSGetFileAttributesW
* VSGetFileBasicInformation
* VSGetFileBasicInformationByHandle
* VSGetFileBasicInformationW
* VSGetFilePosition
* VSGetFileTimes
* VSGetFileTimesW
* VSGetHeuristicLevel
* VSGetKeepDecompressFileFlag
* VSGetMemUsage
* VSGetMemoryDecompressSize
* VSGetMsgScanLayer
* VSGetMultiPatternFilesInfo
* VSGetNormalizeMemScanFlag
* VSGetOleEmbedScanLayer
* VSGetPatternHandle
* VSGetPatternInternalVersion
* VSGetPatternPath
* VSGetPatternProperty
* VSGetProcessAllFileFlag
* VSGetProcessAllFileInArcFlag
* VSGetProcessAllSubDirFlag
* VSGetProcessExcludeExtName
* VSGetProcessExcludeExtNumber
* VSGetProcessExtName
* VSGetProcessExtNumber
* VSGetProcessExtTableSize
* VSGetProcessMemScanFlag
* VSGetRTFScanLayer
* VSGetRedAlertFlag
* VSGetScanBPFlag
* VSGetScanGenericMacroFlag
* VSGetScanJavaFlag
* VSGetScanMacroFlag
* VSGetScanMemoryFlag
* VSGetScanTask
* VSGetScanTaskStatus
* VSGetScriptTrapFlag
* VSGetServiceTable
* VSGetSmartDecompressFlag
* VSGetSoftMiceFlag
* VSGetSpywareExcludeName
* VSGetSpywareExcludeNameEx
* VSGetSpywareExcludeNumber
* VSGetStripMacroFlag
* VSGetTempPath
* VSGetVSCInfo
* VSGetVSDebug
* VSGetVSVerboseLevel
* VSGetVerboseLevel
* VSGetVersion
* VSGetVersionString
* VSGetVirusAction
* VSGetVirusDetectionInfo
* VSGetVirusHospitalPath
* VSGetVirusInfo
* VSGetVirusNameInfo
* VSGetVirusNameInfoEx
* VSGetVirusPatternInfo
* VSGetVirusPatternInfoEx
* VSGetVirusPatternInformation
* VSGetVirusPropertyByName
* VSInit
* VSIsDir
* VSIsEZDriveInstalled
* VSIsNewerEngine
* VSIsTwoByteWord
* VSKDCleanBootVirus
* VSKDGetLongPathName
* VSKDReadNewestPattern
* VSKDReadNewestPatternW
* VSKDScanBootSector
* VSKDScanPartitionTable
* VSKDSetCheckForInteropFlag
* VSKDSetPatternInsightCallbackFunc
* VSKDZwClose
* VSKDZwCreateFile
* VSKDZwQueryInformationFile
* VSKDZwSetInformationFile
* VSLoadCustomDefenseList
* VSLseekResource
* VSMakeDirectory
* VSMakeDirectoryW
* VSMatch
* VSOpenCreateFileW
* VSOpenFile
* VSOpenFileW
* VSOpenIOFromHandle
* VSOpenResource
* VSProcessFile
* VSQuit
* VSReadControlPattern
* VSReadFile
* VSReadPattern
* VSReadPatternInFile
* VSReadPatternInFileW
* VSReadPhysicalSector
* VSReadResource
* VSRemoveAllTempFile
* VSRemoveDirectory
* VSRemoveDirectoryW
* VSRemoveWhiteChar
* VSRenameFile
* VSRenameFileW
* VSResetConfChangeFlag
* VSResetCustomDefenseList
* VSResetScanCounter
* VSResourceDataType
* VSResourceSize
* VSRestoreFile
* VSRestoreFileW
* VSScanBP
* VSScanFile
* VSScanFileFD
* VSScanResource
* VSScanResourceNTKD
* VSScanShellCode
* VSSearchArchProcessExcludeExtName
* VSSearchArchProcessExtName
* VSSearchPackPolicyExcludeName
* VSSearchProcessExcludeExtName
* VSSearchSpywareExcludeName
* VSSeekFile
* VSSetActiveScanFlag
* VSSetAdvFileInfoCallBackFunc
* VSSetAskActionFunc
* VSSetBackupEncodeFlag
* VSSetCharacterEnvType
* VSSetCleanBackupFlag
* VSSetCleanZipFlag
* VSSetConfig
* VSSetConfigEx
* VSSetCountFileFlag
* VSSetDataTypeFD
* VSSetDataTypeInfo
* VSSetDecodeFlag
* VSSetDecompressLayer
* VSSetDefaultHospitalPath
* VSSetDefaultPatternFile
* VSSetDefaultPatternPath
* VSSetDefaultTempPath
* VSSetDetectionExcludeNames
* VSSetEncodeAction
* VSSetEncryptTempFileFlag
* VSSetEndOfFile
* VSSetExpandLiteFlag
* VSSetExtractAmgFlag
* VSSetExtractArchiveFlag
* VSSetExtractFileCountLimit
* VSSetExtractFileRatioLimit
* VSSetExtractFileSizeLimit
* VSSetExtractFileSizeLimitByVSDT
* VSSetExtractPath
* VSSetFeedbackCallBackFunc
* VSSetFileAttributes
* VSSetFileAttributesByHandle
* VSSetFileAttributesW
* VSSetFileBasicInformation
* VSSetFileBasicInformationByHandle
* VSSetFileBasicInformationW
* VSSetFilePosition
* VSSetFileTimes
* VSSetFileTimesW
* VSSetHeuristicLevel
* VSSetKeepDecompressFileFlag
* VSSetLogFilePath
* VSSetLogFilePathFunc
* VSSetLogFlag
* VSSetMemoryDecompressSize
* VSSetMsgScanLayer
* VSSetNormalizeMemScanFlag
* VSSetOleEmbedCallBackFunc
* VSSetOleEmbedScanLayer
* VSSetPatternPath
* VSSetPostExtractArchFunc
* VSSetPreExtractArchFunc
* VSSetProcessAllFileFlag
* VSSetProcessAllFileInArcFlag
* VSSetProcessAllSubDirFlag
* VSSetProcessFileCallBackFunc
* VSSetProcessMemScanFlag
* VSSetRTFScanLayer
* VSSetRealTimeFlag
* VSSetRedAlertFlag
* VSSetRenameFileNameFunc
* VSSetScanBPFlag
* VSSetScanGenericMacroFlag
* VSSetScanJavaFlag
* VSSetScanLiteFileFlag
* VSSetScanMacroFlag
* VSSetScanMemoryFlag
* VSSetScriptTrapFlag
* VSSetSmartDecompressFlag
* VSSetSoftMiceFlag
* VSSetStripMacroFlag
* VSSetTempPath
* VSSetUserDecodeFunc
* VSSetUserLogFunc
* VSSetVSCInfo
* VSSetVSVerboseLevel
* VSSetVerboseLevel
* VSSetVirusAction
* VSSetVirusHospitalPath
* VSShareVirusPattern
* VSStoreVSCData
* VSStricmp
* VSStrip
* VSStrnicmp
* VSSwapLong
* VSSwapLongTable
* VSSwapShort
* VSSwapShortTable
* VSToLowerString
* VSToUpperString
* VSUpdateZip
* VSVirusScan
* VSVirusScanFile
* VSVirusScanFileW
* VSVirusScanFileWithoutFNFilter
* VSWriteFile
* VSWriteResource
* VsapiEntry
* _VSBackSearchChar
* _VSGetThreadTidsAndInitThreadsGlobalArray
* _VSIScanEnableSignature
* _VSIScanGetVirusInfo
* _VSIScanGetVirusInfoEx
* _VSResetMemUsage
* _VSScanVirusInMemory
* mwcstombs
* mwcstombsn
* mwctomb

{{< /details >}}

#### Sections
{{< details "Expand" >}}
* .text
* .rdata
* .data
* .pdata
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
      "CertificateType": "Leaf (Code Signing)",
      "IsCA": false,
      "IsCertificateAuthority": false,
      "IsCodeSigning": true,
      "SerialNumber": "3300000110bbda1909b3f83897000000000110",
      "Signature": "59e526577072d951ca2b437f0eef40e4b19e73d0b8ec1c64d0e9a996978612e67bf32d77f143ae724db9ab2e2221da438aaab784799b2885c4a196315f7a6bfeda8be53518cd47cbb271d5e3dbdaa5917275d75b03097fe23504897a00797315aaa7e88d0b492956428b2086a866f4974bd1a282af175e3a27acd56c206d313cdecad2289c10867c8a3a7f24ea28831f9b574c47c86af5504c7d5647925cfa16e88c943f93aa6cc6bc3494d57661007189adf6498751ea2a8a607dfc79125d5e1398b8f98466b39427ac43b65c327c2e8347d4940c769054829ce7ca3ca32e0714532a075ed193bdc42fc8d102419acc65a565e0bd031efe41d7437148ca28af",
      "SignatureAlgorithmOID": "1.2.840.113549.1.1.11",
      "Subject": "C=US, ST=Washington, L=Redmond, O=Microsoft Corporation, CN=Microsoft Windows Hardware Compatibility Publisher",
      "TBS": {
        "MD5": "dca6a67d48ad7ecdb2e445f502a8eb98",
        "SHA1": "3a7630b4eeaf580dd8212039061c044504cd2741",
        "SHA256": "c7cd78241a66b6992cbe11a2773e8df626ecc6443c09204075b1818d6409caf7",
        "SHA384": "a7a55fd7f70b614325a6b8a0a5dc29e051bf46a88c85471ec7b58e4860942ad1bb6a1cabac8d28ce59e79c8f26fc5799"
      },
      "ValidFrom": "2024-05-16 22:16:05",
      "ValidTo": "2025-05-14 22:16:05",
      "Version": 3
    },
    {
      "CertificateType": "CA",
      "IsCA": true,
      "IsCertificateAuthority": true,
      "IsCodeSigning": false,
      "SerialNumber": "610baac1000000000009",
      "Signature": "5a8a67daccd5fd0d264177bf0a4678b4b3de12692b7723c2652f015fd203f461ba509d2e8c3972f36c3e6ab11e766decb7f382dcccbbc56970287366173f54ebee011648c446d91b80ae813a8d0f796d68b09eea2d3f39d3ca387ebd5e7c086e19dcc6c2f438336861e2524783e1000156d2bacb878205310a418b4ee77f5f5fed5fd3392d45eba213bffd1ec298417161165fc80a70257c59693124e471e70abb0417f79f721ec9d2bb1abe3d02fe090cb243b4591a99539396215fe0d6b72601429536ac27fdbef48577683d18bdf4be98882211865216f345ec0397107087a37043713cdbc98603170cf5735bc67de15c64edd7c548d7ed32e2d1aad3cfa7f6574e61f977eb67f288b3de00da038fd08a34373e1dd862b8d2b1f3e12f8b723b81967c6ffcec667672601b24f2a0896d5b6d002eef28dd868705c2b4b9e5be64c22af24a155c98e2c42785ff52e3627e0fb2020bd766c70ab2d33d200414503259830a7d9bed5a38120152ba2f5e20728e4af1fde771028c3be107bec973f4dd47d8b4efb4a4b330b9893e76cab90098567eabea8ab8a5d038ab6977130b142fe9aa411ff7babd3a2b348aee0aab63e663f788248e200d2b3b9de3c24952ac9f1f0e393b5dd46e506ae67d523aaa7c3315290d265e0158a74ea93d7a846f743f609fe4324f3600af6d71d33ea646655f8174f1fec171da4ca0415a82ddf11f",
      "SignatureAlgorithmOID": "1.2.840.113549.1.1.11",
      "Subject": "C=US, ST=Washington, L=Redmond, O=Microsoft Corporation, CN=Microsoft Windows Third Party Component CA 2012",
      "TBS": {
        "MD5": "a569061297e8e824767dbc3184a69bea",
        "SHA1": "adbb26a587a8f44b4fccaecb306f980d1c55a150",
        "SHA256": "cec1afd0e310c55c1dcc601ab8e172917706aa32fb5eaf826813547fdf02dd46",
        "SHA384": "e947cac936803f5683196e4ff1b259096073395d0b908522ddce90d57597c9f7b57f7ddcdbe021ba863d843c340da8ba"
      },
      "ValidFrom": "2012-04-18 23:48:38",
      "ValidTo": "2027-04-18 23:58:38",
      "Version": 3
    }
  ],
  "CertificatesInfo": "",
  "Signer": [
    {
      "Issuer": "C=US, ST=Washington, L=Redmond, O=Microsoft Corporation, CN=Microsoft Windows Third Party Component CA 2012",
      "SerialNumber": "3300000110bbda1909b3f83897000000000110",
      "Version": 1
    }
  ],
  "SignerInfo": ""
}
```

{{< /details >}}
-----



[*source*](https://github.com/magicsword-io/LOLDrivers/blob/main/yaml/8b8bbbfe-798b-47bf-991b-21a0a0becef3.yaml)

*last_updated:* 2026-10-26

{{< /column >}}
{{< /block >}}
