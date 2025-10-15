+++

description = ""
title = "c734bcff-aaaa-4450-a9a9-25ee52aa7ff1"
weight = 10
displayTitle = "ktes.sys"
+++


{{< block "grid-1" >}}
{{< column "mt-2 pt-1">}}


# ktes.sys


{{< tip "warning" >}}
We were not able to verify the hash of this driver successfully, it has not been confirmed.
{{< /tip >}}


### Description

BlackCat Ransomware Deploys New Signed Kernel Driver. BlackCat ransomware incident that occurred in February 2023.
- **UUID**: c734bcff-aaaa-4450-a9a9-25ee52aa7ff1
- **Created**: 2023-06-05
- **Author**: Guus Verbeek
- **Acknowledgement**:  | [](https://twitter.com/)


### Commands

```
sc.exe create ktes.sys binPath=C:\windows\temp\ktes.sys type=kernel &amp;&amp; sc.exe start ktes.sys
```


| Use Case | Privileges | Operating System | 
|:---- | ---- | ---- |
| Elevate privileges | kernel | Windows 10 |



### Detections


{{< block "grid-3" >}}
{{< column >}}
#### YARA 🏹
{{< details "Expand" >}}

{{< button "https://github.com/magicsword-io/LOLDrivers/blob/main/detections/yara/other/yara-rules_mal_drivers_strict.yar" "Exact Match" >}}{{< tip >}}with header and size limitation{{< /tip >}} 

{{< button "https://github.com/magicsword-io/LOLDrivers/blob/main/detections/yara/yara-rules_mal_drivers.yar" "Threat Hunting" >}}{{< tip >}}without header and size limitation{{< /tip >}} 



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
<li><a href="https://www.trendmicro.com/en_us/research/23/e/blackcat-ransomware-deploys-new-signed-kernel-driver.html">https://www.trendmicro.com/en_us/research/23/e/blackcat-ransomware-deploys-new-signed-kernel-driver.html</a></li>
<br>


### Known Vulnerable Samples

| Property           | Value |
|:-------------------|:------|
| Filename           | ktes.sys |
| Creation Timestamp           |  |
| MD5                | [](https://www.virustotal.com/gui/file/) |
| SHA1               | [5ed22c0033aed380aa154e672e8db3a2d4c195c4](https://www.virustotal.com/gui/file/5ed22c0033aed380aa154e672e8db3a2d4c195c4) |
| SHA256             | [](https://www.virustotal.com/gui/file/) |



#### Imports
{{< details "Expand" >}}

{{< /details >}}
#### Imported Functions
{{< details "Expand" >}}

{{< /details >}}
#### Exported Functions
{{< details "Expand" >}}

{{< /details >}}

#### Sections
{{< details "Expand" >}}

{{< /details >}}
#### Signature
{{< details "Expand" >}}

{{< /details >}}
-----



[*source*](https://github.com/magicsword-io/LOLDrivers/blob/main/yaml/c734bcff-aaaa-4450-a9a9-25ee52aa7ff1.yaml)

*last_updated:* 2025-08-28

{{< /column >}}
{{< /block >}}
