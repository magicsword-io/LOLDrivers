+++
title = "Content organization"
weight = 4
+++

This theme is primarily meant for documentation.

#### Documentation

By default, the theme will look for all your documentation content within the `docs` directory.

However, if you would like to have your docs content across multiple directories, please list those directories inside `config/_default/params.toml` under `docSections` like so:

```
...
docSections = ["docs", "tutorials"]
...
```

Unlike other regular pages, the documentation pages will have a left sidebar. This sidebar will list links to all the pages in the documentation pages. Beneath each link, there will be a collapsible list of __table of contents'__ links. These nested lists will unfold automatically on the active/current page.

#### Home Page

At the root level there's an `_index.md` page which is the homepage. Feel free to edit it as you like.

#### Other pages

You can also add as many regular pages as you like e.g `about.md`, `contact.md`...

Take advantage of [shortcodes](../shortcodes) to customize the layouts of these pages and any other.

#### Does this theme support blogging function?

Currently, no.
