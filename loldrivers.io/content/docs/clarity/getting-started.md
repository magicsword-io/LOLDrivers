---
title: Getting started
weight: 11
---

## Prerequisites

Firstly, __ensure you have installed the [extended version of Hugo](https://github.com/gohugoio/hugo/releases)__. See installation steps from [Hugo's official docs](https://gohugo.io/getting-started/installing/).

## Getting up and running

Read the [prerequisites](#prerequisites) above and verify you're using the extended version of Hugo. There are at least two ways of quickly getting started with Hugo and the VMware Clarity theme:

### Option 1 (recommended)

Generate a new Hugo site and add this theme as a Git submodule inside your themes folder:

```bash
hugo new site yourSiteName
cd yourSiteName
git init
git submodule add https://github.com/chipzoller/hugo-clarity themes/hugo-clarity
cp -a themes/hugo-clarity/exampleSite/* .
```

Then run

```bash
hugo server
```

Hurray!

### Option 2 (Great for testing quickly)

You can run your site directly from the `exampleSite`. To do so, use the following commands:

```bash
git clone https://github.com/chipzoller/hugo-clarity
cd hugo-clarity/exampleSite/
hugo server --themesDir ../..
```

> Although, option 2 is great for quick testing, it is somewhat problematic when you want to update your theme. You would need to be careful not to overwrite your changes.

### Option 3 (The new, most fun & painless approach)

This option enables you to load this theme as a hugo module. It arguably requires the least effort to run and maintain in your website.

First things first, ensure you have `go` binary [installed on your machine](https://golang.org/doc/install).

```bash
git clone https://github.com/chipzoller/hugo-clarity.git clarity
cd clarity/exampleSite/
hugo mod init my-site
```
Open config.toml file in your code editor, replace `theme = "hugo-clarity"` with `theme = ["github.com/chipzoller/hugo-clarity"]` or just `theme = "github.com/chipzoller/hugo-clarity"`.

Hurray you can now run

```yaml
hugo server
```

To pull in theme updates, run `hugo mod get -u ./...` from the theme folder. If unsure, [learn how to update hugo modules](https://gohugo.io/hugo-modules/use-modules/#update-modules)

> There [is more you could do with hugo modules](https://discourse.gohugo.io/t/hugo-modules-for-dummies/20758), but this will suffice for our use case here.
