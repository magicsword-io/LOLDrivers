+++
title = "LOLDrivers"
[dataset1]
  fileLink = "content/drivers_table.csv"
  colors = ["#ef7f1a", "#627c62", "#11819b", "#4e1154"] # chart colors
  columnTitles = ['Tag','SHA256','Category', 'Created'] # optional if not table will be displayed from dataset
  baseChartOn = 4 # number of column the chart(s) and graph should be drawn from # can be overridden directly via shortcode parameter # it's therefore optional
  charts = ["table"]
  title = "Driver List"

[dataset2]
  fileLink = "content/drivers_top_5_products.csv"
  colors = ["#ef7f1a", "#627c62", "#11819b", "#4e1154", "#a1c9a2", "#38a9d9", "#f9b34c", "#824da4", "#e0c7c2", "#c2c2a3", "#d6a994", "#f2c057"] # chart colors
  columnTitles = ["Count", "Name"] # optional if not table will be displayed from dataset
  baseChartOn = 2 # number of column the chart(s) and graph should be drawn from # can be overridden directly via shortcode parameter # it's therefore optional
  piechart = true
  barchart = true
  title = "Top Products"


[dataset3]
  fileLink = "content/drivers_top_5_publishers.csv"
  colors = ["#ef7f1a", "#627c62", "#11819b", "#4e1154", "#a1c9a2", "#38a9d9", "#f9b34c", "#824da4", "#e0c7c2", "#c2c2a3", "#d6a994", "#f2c057"] # chart colors
  columnTitles = ["Count", "Name"] # optional if not table will be displayed from dataset
  baseChartOn = 2 # number of column the chart(s) and graph should be drawn from # can be overridden directly via shortcode parameter # it's therefore optional
  piechart = true
  barchart = true
  title = "Top Publishers"
+++

{{< block "grid-3" >}}

{{< column "mt-4">}}

# Living Off The Land Drivers 
Living Off The Land Drivers is a curated list of Windows drivers used by adversaries to bypass security controls and carry out attacks. The project helps security professionals stay informed and mitigate potential threats. 

{{< tip  >}}
Feel free to open a [PR](https://github.com/magicsword-io/LOLDrivers/pulls), raise an [issue](https://github.com/magicsword-io/LOLDrivers/issues/new/choose "Open a Github Issue")(s) or request new driver(s) be added.
{{< /tip >}}

{{< tip >}}
You can also get the malicious driver list via **API** using [CSV](api/drivers.csv) or [JSON](api/drivers.json). Sysmon users check out the pre-built [config](https://github.com/magicsword-io/LOLDrivers/blob/main/detections/sysmon/sysmon_config_vulnerable_hashes.xml). There is a [Sigma rule](https://github.com/magicsword-io/LOLDrivers/blob/main/detections/sigma/driver_load_win_vuln_drivers.yml) for SIEMs. If you've found this project valuable, you'll absolutely love our sister projects, [LOLBAS](https://lolbas-project.github.io/#) and [GTFOBins](https://gtfobins.github.io), check them out!  
{{< /tip >}}

{{< /column >}}

{{< column "mt-4">}}

# Top Products

{{% chart "dataset2" "pie" %}}

{{< /column >}}

{{< column "mt-4">}}

{{% chart "dataset3" "bar" %}}

{{< /column >}}

{{< /block >}}

{{< block "grid-1" >}}
{{< column >}}
<div style="display:flex; align-items:center; gap:16px; padding:14px 16px; background:#ffffff; border:1px solid #e6f4f2; border-radius:14px; box-shadow:0 8px 24px rgba(0,0,0,0.08);">
  <img src="images/magicsword-logo.png" alt="MagicSword Logo" style="height:84px; width:auto; display:block; filter: drop-shadow(0 6px 14px rgba(0,194,168,0.35));" />
  <div style="line-height:1.5; color:#111;">
    <div>Block <strong style="color:red;">Living‑off‑the‑Land</strong> techniques RMM tools, LOLBAS, and BYOVD with native Windows controls.</div>
    <a href="https://www.magicsword.io" style="display:inline-block; margin-top:8px; padding:12px 18px; background: rgb(0 170 108 / var(--tw-bg-opacity,1)); color:#ffffff; border-radius:12px; font-weight:800; text-decoration:none;">Block with MagicSword</a>
  </div>
</div>

{{< /column >}}
{{< /block >}}

{{< block "grid-1" >}}
{{< column >}}

# SIEM Detections

Use the following queries to detect known vulnerable or malicious drivers (LOLDrivers) in your environment. Click a tab to switch views.

<style>
.siem-tabbar { display: flex; gap: 8px; margin: 8px 0 12px; flex-wrap: wrap; }
.siem-tabbar button { display: inline-flex; align-items: center; gap: 10px; padding: 10px 16px; border: 1px solid #ccc; background: #fff; cursor: pointer; border-radius: 8px; }
.siem-tabbar button.active { background: #eaeaea; border-color: #999; font-weight: 600; }
.siem-tabicon { width: 22px; height: 22px; display: inline-block; }
.siem-tabcontent { display: none; }
.siem-tabcontent.active { display: block; }
/* Make code blocks fully expanded vertically and prevent horizontal page overflow */
.siem-tabcontent .highlight,
.siem-tabcontent pre,
.siem-tabcontent .chroma {
  max-height: none !important;
  max-width: 100% !important;
  overflow-y: visible !important;
  overflow-x: auto !important; /* horizontal scroll if needed */
}
/* Allow breaking long tokens inside lines so unbroken JSON/URLs don't stretch the layout */
.siem-tabcontent code,
.siem-tabcontent .cl {
  white-space: pre-wrap; /* keep formatting but allow wrapping */
  overflow-wrap: anywhere;
  word-break: break-word;
}
</style>

<div class="siem-tabbar" role="tablist" aria-label="SIEM Detections">
  <button type="button" role="tab" aria-selected="true" aria-controls="tab-mde" id="tabbtn-mde" class="active" data-tab="mde">
    <svg class="siem-tabicon" viewBox="0 0 24 24" aria-hidden="true">
      <rect x="2" y="2" width="9" height="9" fill="#00A4EF"/>
      <rect x="13" y="2" width="9" height="9" fill="#7FBA00"/>
      <rect x="2" y="13" width="9" height="9" fill="#FFB900"/>
      <rect x="13" y="13" width="9" height="9" fill="#F25022"/>
    </svg>
    Microsoft Defender
  </button>
  <button type="button" role="tab" aria-selected="false" aria-controls="tab-splunk" id="tabbtn-splunk" data-tab="splunk" style="min-width:100px; justify-content:center;">
    <img src="images/splunk_logo.png" alt="Splunk Logo" class="siem-tabicon" style="width:75px; height:50px; object-fit:contain;">
    Splunk
  </button>
  <span style="display:none" id="siem-tabs-state" data-default="mde"></span>
  <script>
    (function(){
      var btns = document.querySelectorAll('.siem-tabbar button');
      function expandCodeInTab(name){
        var tab = document.getElementById('tab-'+name);
        if(!tab) return;
        // expand any code blocks within this tab
        var blocks = tab.querySelectorAll('.highlight pre, .highlight code, pre, code');
        blocks.forEach(function(el){
          el.style.maxHeight = 'none';
          el.style.overflow = 'visible';
          var outer = el.closest('.highlight');
          if(outer){ outer.classList.add('panel_expanded'); }
        });
      }
      function showTab(name){
        document.querySelectorAll('.siem-tabcontent').forEach(function(el){ el.classList.remove('active'); });
        document.getElementById('tab-'+name).classList.add('active');
        btns.forEach(function(b){ b.classList.toggle('active', b.dataset.tab===name); b.setAttribute('aria-selected', String(b.dataset.tab===name)); });
        // ensure code is fully visible for this tab
        expandCodeInTab(name);
        // ensure inner code lines wrap and container doesn't overflow viewport
        var tab = document.getElementById('tab-'+name);
        if(tab){
          tab.style.maxWidth = '100%';
          var highlights = tab.querySelectorAll('.highlight, pre, code');
          highlights.forEach(function(el){
            el.style.maxWidth = '100%';
            el.style.whiteSpace = 'pre-wrap';
            el.style.overflowWrap = 'anywhere';
            el.style.wordBreak = 'break-word';
          });
        }
      }
      btns.forEach(function(b){ b.addEventListener('click', function(){ showTab(b.dataset.tab); }); });
      // delay initial expansion to allow theme JS to process blocks first
      setTimeout(function(){ showTab('mde'); }, 50);
    })();
  </script>
</div>

<div id="tab-mde" class="siem-tabcontent active" role="tabpanel" aria-labelledby="tabbtn-mde">

```sql
 let LOLDrivers = externaldata (Category:string, KnownVulnerableSamples:dynamic, Verified:string ) [h@"https://www.loldrivers.io/api/drivers.json"]
     with (
       format=multijson,
       ingestionMapping=@'
[
  {"Column":"Category","Properties":{"Path":"$.Category"}},
  {"Column":"KnownVulnerableSamples","Properties":{"Path":"$.KnownVulnerableSamples"}},
  {"Column":"Verified","Properties":{"Path":"$.Verified"}}
]'
     )
| mv-expand KnownVulnerableSamples
| extend SHA1 = tostring(KnownVulnerableSamples.SHA1), SHA256 = tostring(KnownVulnerableSamples.SHA256)
;
// you can filter the drivers further based on category or verified status
DeviceEvents
| where ActionType == "DriverLoad"
| join kind=inner (LOLDrivers | where isnotempty(SHA256)) on SHA256
| union (
  DeviceEvents
  | where ActionType == "DriverLoad"
  | join kind=inner (LOLDrivers | where isnotempty(SHA1)) on SHA1
)
```

**Credit**: Mehmet Ergene ([@Cyb3rMonk](https://x.com/Cyb3rMonk)). **Source**: [Detecting Vulnerable Drivers using MDE](https://academy.bluraven.io/blog/detecting-vulnerable-drivers-using-defender-for-endpoint-kql).

</div>

<div id="tab-splunk" class="siem-tabcontent" role="tabpanel" aria-labelledby="tabbtn-splunk">

```sql
index=YOUR_INDEX sourcetype=YOUR_DRIVER_LOAD_SOURCE
| stats min(_time) as firstTime max(_time) as lastTime count by ImageLoaded dest dvc process_hash process_path signature signature_id user_id vendor_product
| lookup loldrivers driver_name AS ImageLoaded OUTPUT is_driver driver_description
| search is_driver=TRUE
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| `windows_vulnerable_driver_loaded_filter`
```

Note: The maintained lookup CSV can be found here: [splunk/security_content lookups/loldrivers.csv](https://github.com/splunk/security_content/blob/develop/lookups/loldrivers.csv).

**Credit**: Michael Haag. **Source**: [Windows Vulnerable Driver Loaded](https://research.splunk.com/endpoint/a2b1f1ef-221f-4187-b2a4-d4b08ec745f4/).

</div>

{{< details "🧰 Tools (expand to view)" >}}

<div style="display:grid; grid-template-columns: repeat(auto-fit, minmax(260px,1fr)); gap:14px;">
  <a href="https://www.tenable.com/plugins/nessus/204959" target="_blank" rel="noopener" style="display:flex; align-items:center; gap:12px; padding:14px; border:1px solid #e9ecef; border-radius:12px; background:#fff; text-decoration:none; box-shadow:0 6px 14px rgba(0,0,0,0.05);">
    <span style="width:34px; height:34px; display:inline-flex; align-items:center; justify-content:center; border-radius:10px; background:#2c7be5; color:#fff; font-weight:800;">N</span>
    <span>
      <div style="font-weight:700; color:#0d0d0d;">Nessus Plugin: LOLDriver Detection (Windows)</div>
      <div style="font-size:12px; color:#666;">Quickly detect LOLDrivers on endpoints</div>
    </span>
  </a>

  <a href="https://gist.github.com/api0cradle/d52832e36aaf86d443b3b9f58d20c01d#file-check_vulnerabledrivers-ps1" target="_blank" rel="noopener" style="display:flex; align-items:center; gap:12px; padding:14px; border:1px solid #e9ecef; border-radius:12px; background:#fff; text-decoration:none; box-shadow:0 6px 14px rgba(0,0,0,0.05);">
    <span style="width:34px; height:34px; display:inline-flex; align-items:center; justify-content:center; border-radius:10px; background:#0078d7; color:#fff; font-weight:800;">PS</span>
    <span>
      <div style="font-weight:700; color:#0d0d0d;">PowerShell: Check Vulnerable Drivers (api0cradle)</div>
      <div style="font-size:12px; color:#666;">Compare local drivers with LOLDrivers JSON</div>
    </span>
  </a>

  <a href="https://github.com/rtfmkiesel/loldrivers-client" target="_blank" rel="noopener" style="display:flex; align-items:center; gap:12px; padding:14px; border:1px solid #e9ecef; border-radius:12px; background:#fff; text-decoration:none; box-shadow:0 6px 14px rgba(0,0,0,0.05);">
    <span style="width:34px; height:34px; display:inline-flex; align-items:center; justify-content:center; border-radius:10px; background:#111; color:#fff; font-weight:800;">Go</span>
    <span>
      <div style="font-weight:700; color:#0d0d0d;">LOLDrivers-client (Windows)</div>
      <div style="font-size:12px; color:#666;">Blazingly fast client to scan for vulnerable/malicious drivers</div>
    </span>
  </a>

  <a href="https://docs.velociraptor.app/exchange/artifacts/pages/windows.hunter.yara.loldrivers/" target="_blank" rel="noopener" style="display:flex; align-items:center; gap:12px; padding:14px; border:1px solid #e9ecef; border-radius:12px; background:#fff; text-decoration:none; box-shadow:0 6px 14px rgba(0,0,0,0.05);">
    <span style="width:34px; height:34px; display:inline-flex; align-items:center; justify-content:center; border-radius:10px; background:#28a745; color:#fff; font-weight:800;">Y</span>
    <span>
      <div style="font-weight:700; color:#0d0d0d;">Velociraptor: Windows.Hunter.Yara.LOLDrivers</div>
      <div style="font-size:12px; color:#666;">Scan driver dirs with YARA; optional upload; defaults use rules from <strong>detections/yara</strong></div>
    </span>
  </a>
</div>

- [Nessus Plugin: LOLDriver Detection (Windows)](https://www.tenable.com/plugins/nessus/204959)
- [PowerShell: Check Vulnerable Drivers (api0cradle)](https://gist.github.com/api0cradle/d52832e36aaf86d443b3b9f58d20c01d#file-check_vulnerabledrivers-ps1)
- [LOLDrivers-client (Windows)](https://github.com/rtfmkiesel/loldrivers-client)
  - The first blazingly fast client for LOLDrivers (Living Off The Land Drivers) by MagicSword. Scan your computer for known vulnerable and known malicious Windows drivers.
- [Velociraptor: Windows.Hunter.Yara.LOLDrivers](https://docs.velociraptor.app/exchange/artifacts/pages/windows.hunter.yara.loldrivers/)
  - This artifact scans system driver directories using two user-supplied YARA rules (malware and vulnerability). If no rules are supplied, it runs encoded defaults derived from Florian Roth’s rules in [detections/yara](https://github.com/magicsword-io/LOLDrivers/tree/main/detections/yara). Matching files are labeled as “malware” or “vulnerability,” and can be optionally uploaded.

{{< /details >}}

{{< /column >}}
{{< /block >}}

{{< block "grid-1" >}}
{{< column >}}
{{% chart "dataset1" "table" %}}
{{< /column >}}
{{< /block >}}
