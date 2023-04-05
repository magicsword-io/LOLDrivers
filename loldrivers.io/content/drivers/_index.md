+++
title = "Driver List"
[dataset1]
  fileLink = "content/drivers_table.csv"
  colors = ["#ef7f1a", "#627c62", "#11819b", "#4e1154"] # chart colors
  columnTitles = ["Name", "Category", "Privileges", "MitreID"] # optional if not table will be displayed from dataset
  baseChartOn = 4 # number of column the chart(s) and graph should be drawn from # can be overridden directly via shortcode parameter # it's therefore optional
  charts = ["table"]
  title = "Driver List"
+++

{{< block "grid-1" >}}
{{< column "mt-1 pt-1">}}
# Driver List

{{% chart "dataset1" "table" %}}

{{< /column >}}
{{< /block >}}

