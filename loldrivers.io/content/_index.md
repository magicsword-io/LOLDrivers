+++
title = "LOLDrivers"
[dataset1]
  fileLink = "content/projects.csv"
  colors = ["#ef7f1a", "#627c62", "#11819b", "#4e1154"] # chart colors
  columnTitles = ["Name", "Category", "Privileges", "MitreID"] # optional if not table will be displayed from dataset
  baseChartOn = 3 # number of column the chart(s) and graph should be drawn from # can be overridden directly via shortcode parameter # it's therefore optional
  piechart = true
  title = "Driver List"

[dataset2]
  fileLink = "../drivers.csv" 
  colors = ["#ef7f1a", "#627c62", "#11819b", "#4e1154"] # chart colors
  columnTitles = ["Theme", "Latest Version", "Repo Owner"] # Optional if no table will be displayed from dataset
  baseChartOn = 2 # number of column the chart(s) and graph should be drawn from # can be overridden directly via shortcode parameter # it's therefore optional
  title = "Drivers by Publisher"
  bargraph = true
+++

{{< block "grid-3" >}}
{{< column "mt-2 pt-1">}}

# `` 
# Living Off The Land Drivers 
Living Off The Land Drivers is a curated list of Windows drivers used by adversaries to bypass security controls and carry out attacks. The project helps security professionals stay informed and mitigate potential threats.

{{< tip "warning" >}}
Feel free to open a [PR](https://github.com/magicsword-io/LOLDrivers/pulls), raise an [issue](https://github.com/magicsword-io/LOLDrivers/issues/new/choose "Open a Github Issue")(s) or request new driver(s) be added. 
{{< /tip >}}

{{< tip >}}
You can also get the malicious driver list via [CSV](), [JSON]() or [API]().
{{< /tip >}}
{{< /column >}}

{{< column >}}
{{< picture "loling.png" "loling.png" "LMAO" >}}
{{< /column >}}

{{< column "mt-4">}}
{{% chart "dataset1" "pie" %}}

{{< /column >}}
{{< /block >}}

{{< block "grid-1" >}}
{{< column >}}
{{% chart "dataset1" "table" %}}
{{< /column >}}
{{< /block >}}


