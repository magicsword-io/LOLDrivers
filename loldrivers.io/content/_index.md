+++
title = "LOLDrivers"
[dataset1]
  fileLink = "content/drivers_table.csv"
  colors = ["#ef7f1a", "#627c62", "#11819b", "#4e1154"] # chart colors
  columnTitles = ['Name','Author','Created','Command'] # optional if not table will be displayed from dataset
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

{{< tip "warning" >}}
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
{{% chart "dataset1" "table" %}}
{{< /column >}}
{{< /block >}}
