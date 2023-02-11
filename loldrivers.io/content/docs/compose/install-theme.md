---
title: "Install theme"
weight: 2
description: >
  This page tells you how to get started with the Compose theme.
---

### Prerequisites

First ensure that you have hugo installed.

You need a [recent **extended** version](https://github.com/gohugoio/hugo/releases) (we recommend version 0.61 or later) of [Hugo](https://gohugo.io/) to do local builds and previews of sites (like this one) that uses this theme.

If you install from the release page, make sure to get the `extended` Hugo version, which supports [sass](https://sass-lang.com/documentation/file.SCSS_FOR_SASS_USERS.html); you may need to scroll down the list of releases to see it. 

For comprehensive Hugo documentation, see [gohugo.io](https://gohugo.io/).

## Run your site with compose theme

You could go with the options right below.

### Option 1 (my favorite)

This option enables you to load compose theme as a hugo module. First things first, ensure you have `go` binary [installed on your machine](https://golang.org/doc/install).

```shell
$ git clone https://github.com/onweru/compose/
cd compose/exampleSite/
hugo server
```

To pull in theme updates, run `hugo mod get -u ./...` from the theme folder. If unsure, [learn how to update hugo modules](https://gohugo.io/hugo-modules/use-modules/#update-modules)

{{< tip "warning" >}}
The exampleSite uses the theme as a hugo module by default.

If you choose __Option 2__ or __Option 3__ below, ensure you edit [these lines in the config.toml file](https://github.com/onweru/compose/blob/b3e30e0816621223224897edc45eeeabd0d9cd16/exampleSite/config.toml#L4-L7) as advised on the comments. Else, you will not be able to pull theme updates.
{{< /tip >}}

### Option 2 (recommended)

Generate a new Hugo site and add this theme as a Git submodule inside your themes folder:

```bash
hugo new site yourSiteName
cd yourSiteName
git init
git submodule add https://github.com/onweru/compose/ themes/compose
cp -a themes/compose/exampleSite/* .
```

Then run

```bash
hugo server
```

Hurray!

### Option 3 (Great for testing quickly)

You can run your site directly from the `exampleSite`. To do so, use the following commands:

```bash
git clone https://github.com/onweru/compose/
cd compose/exampleSite/
hugo server --themesDir ../..
```

{{< tip >}}
Although, option 3 is great for quick testing, it is somewhat problematic when you want to update your theme. You would need to be careful not to overwrite your changes.
{{< /tip >}}

Once set, jump over to the [config.toml](https://github.com/onweru/compose/blob/afdf1cd76408aeac11547a6abd51bdc5138a295f/exampleSite/config.toml#L4-L7) file and start configuring your site.

