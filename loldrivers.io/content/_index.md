+++
title = "LOLDrivers"
[dataset1]
  fileLink = "content/projects.csv"
  colors = ["#ef7f1a", "#627c62", "#11819b", "#4e1154"] # chart colors
  columnTitles = ["Verified", "Status", "Author"] # optional if not table will be displayed from dataset
  baseChartOn = 3 # number of column the chart(s) and graph should be drawn from # can be overridden directly via shortcode parameter # it's therefore optional
  piechart = true
  title = "Drivers by Categories"

[dataset2]
  fileLink = "../drivers.csv" 
  colors = ["#ef7f1a", "#627c62", "#11819b", "#4e1154"] # chart colors
  columnTitles = ["Theme", "Latest Version", "Repo Owner"] # Optional if no table will be displayed from dataset
  baseChartOn = 2 # number of column the chart(s) and graph should be drawn from # can be overridden directly via shortcode parameter # it's therefore optional
  title = "Drivers by Publisher"
  bargraph = true
+++

{{< block "grid-2" >}}
{{< column "mt-1 pt-1">}}

# `` 
# Living Off The Land Drivers 
Living Off The Land Drivers is a curated list of Windows drivers used by adversaries to bypass security controls and carry out attacks. The project helps security professionals stay informed and mitigate potential threats.

{{< tip "warning" >}}
Feel free to open a [PR](https://github.com/magicsword-io/LOLDrivers/pulls), raise an [issue](https://github.com/magicsword-io/LOLDrivers/issues/new/choose "Open a Github Issue")(s) or request new driver(s) be added. 
{{< /tip >}}

{{< tip >}}
You can also get the malicious driver list via [CSV](), [JSON]() or [API]().
{{< /tip >}}

{{< button "docs/compose/" "Drivers" >}}
{{< /column >}}

{{< column >}}
<video width="640" height="480" controls autoplay loop>
  <source src="images/chickens.mp4" type="video/mp4">
  Your browser does not support the video tag.
</video>

{{% chart "dataset1" "pie,table" %}}

| animal | sound |
|--------|-------|
| dog    | meow  |
| cat    | woof  |


{{< /column >}}
{{< /block >}}
