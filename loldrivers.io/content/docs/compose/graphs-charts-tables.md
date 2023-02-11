+++
title = "Graphs, charts & dynamic tables"
weight = 9
[dataset1]
  fileLink = "content/projects.csv" # path to where csv is stored
  colors = ["#ef7f1a", "#627c62", "#11819b", "#4e1154"] # chart colors
  columnTitles = ["Section", "Status", "Author"] # optional if not table will be displayed from dataset
  baseChartOn = 3 # number of column the chart(s) and graph should be drawn from # can be overridden directly via shortcode parameter # it's therefore optional
  title = "Projects"

[dataset2]
  fileLink = "content/themes.csv" # path to where csv is stored
  colors = ["#ef7f1a", "#627c62", "#11819b", "#4e1154"] # chart colors
  columnTitles = ["Theme", "Latest Version", "Repo Owner"] # Optional if no table will be displayed from dataset
  baseChartOn = 2 # number of column the chart(s) and graph should be drawn from # can be overridden directly via shortcode parameter # it's therefore optional
  title = "Hugo Themes"
+++

Using [chart js library](https://www.chartjs.org/) you can display data you have stored in a `csv` file as a pie chart, bar graph or doughnut chart.

At this point if you want to display data from a json or yaml file, you would need to [convert it into csv](http://convertcsv.com/json-to-csv.htm) first. Else the template will error out.

Once you have a csv file, you display the charts as follows:

#### Show a pie, doughnut & bar chart at once

Firstly define the data you want to display from the front matter:

```markdown
# from front matter
...
[dataset1] # this key will in the chart shortcode
  fileLink = "content/projects.csv" # path to where csv is stored
  colors = ["#627c62", "#11819b", "#ef7f1a", "#4e1154"] # chart colors
  columnTitles = ["Section", "Status", "Author"]
  charts = ["bar", "doughnut", "pie", "table"]
  baseChartOn = 3 # number of column the chart(s) and graph should be drawn from
  piechart = true
  doughnutchart = true
  bargraph = true
  title = "Projects"
  table = true # show table listing the chart data

// from page content
...
{{</* grid " mt-2" */>}}
  {{</* chart "dataset1" */>}}
{{</* /grid */>}}
...
```

{{< grid "3 mt-2 mb-2" >}}
  {{< chart "dataset1" "pie,doughnut,bar" >}}
{{< /grid >}}

#### __Show Table at once__

{{< block >}}
  {{< chart "dataset1" "table" >}}
{{< /block >}}

Firstly define the data you want to display from the front matter:

```toml
# from page front matter
[dataset2]
  fileLink = "content/themes.csv" # path to where csv is stored # this key will in the chart shortcode
  colors = ["#627c62", "#11819b", "#ef7f1a", "#4e1154"] # chart colors
  columnTitles = ["Theme", "Latest Version", "Owner"]
  title = "Hugo Themes"
  baseChartOn = 2 # number of column the chart(s) and graph should be drawn from
  piechart = false
  doughnutchart = true
  bargraph = true
  table = false # show table listing the chart data
```

#### Show only a pie and a doughnut chart

```markdown
// from page content
...
{{</* grid " mt-2" */>}}
  {{</* chart "dataset2" */>}}
{{</* /grid */>}}
...
```

{{< grid "3 mt-2 mb-2" >}}
  {{< chart "dataset2" "pie,doughnut" "1" >}}
{{< /grid >}}

#### Show table with filter

{{< grid "3" >}}
  {{< chart "dataset2" "table" >}}
{{< /grid >}}

#### Show table only

{{< grid "3" >}}
  {{< chart "dataset2" "table,noFilter" >}}
{{< /grid >}}
