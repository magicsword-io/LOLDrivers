+++

description = ""
title = "cacc48e6-6ed8-431c-abee-88ee6c2dc3c1"
weight = 10
displayTitle = "nt2.sys"
+++


{{< block "grid-1" >}}
{{< column "mt-2 pt-1">}}


# nt2.sys


{{< tip "warning" >}}
We were not able to verify the hash of this driver successfully, it has not been confirmed.
{{< /tip >}}


### Description

nt2.sys is a vulnerable driver and more information will be added as found.
- **UUID**: cacc48e6-6ed8-431c-abee-88ee6c2dc3c1
- **Created**: 2023-01-09
- **Author**: Michael Haag
- **Acknowledgement**:  | [](https://twitter.com/)


### Commands

```
sc.exe create nt2.sys binPath=C:\windows\temp \n \n \n  t2.sys type=kernel &amp;&amp; sc.exe start nt2.sys
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
| Filename           | nt2.sys |
| Creation Timestamp           |  |
| MD5                | [](https://www.virustotal.com/gui/file/) |
| SHA1               | [](https://www.virustotal.com/gui/file/) |
| SHA256             | [cb9890d4e303a4c03095d7bc176c42dee1b47d8aa58e2f442ec1514c8f9e3cec](https://www.virustotal.com/gui/file/cb9890d4e303a4c03095d7bc176c42dee1b47d8aa58e2f442ec1514c8f9e3cec) |



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



[*source*](https://github.com/magicsword-io/LOLDrivers/tree/main/yaml/cacc48e6-6ed8-431c-abee-88ee6c2dc3c1.yaml)

*last_updated:* 2025-03-03

{{< /column >}}
{{< /block >}}
