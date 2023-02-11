---
title: "Customization"
weight: 14
---

## Configuration

If set, jump over to the `config.toml` file and start [configuring](#configuration) your site.

This section will mainly cover settings that are unique to this theme. If something is not covered here (or elsewhere in this file), there's a good chance it is covered in [this Hugo docs page](https://gohugo.io/getting-started/configuration/#configuration-file).

### Global Parameters

These options set global values that some pages or all pages in the site use by default.

| Parameter | Value Type | Overidable on Page |
|:---- | ---- | ---- |
| author | string | no |
| twitter | string | no |
| largeTwitterCard | boolean | no |
| ga_analytics | string | no |
| description | string | yes |
| introDescription | string | no |
| numberOfTagsShown | integer | no |
| fallBackOgImage | file path (string) | no |
| codeMaxLines | integer | yes |
| codeLineNumbers | boolean | yes |
| mainSections | array/string | no |
| centerLogo | boolean | no |
| logo | file path (string) | no |
| mobileNavigation | string | no |
| figurePositionShow | boolean | yes |
| figurePositionLabel | string | no |
| customCSS | array of file path (string) | no |
| customJS | array of file path (string) | no |
| enforceLightMode | boolean | N/A |
| enforceDarkMode | boolean | N/A |
| titleSeparator| string | no |
| comment | boolean | no |

### Page Parameters

These options can be set from a page [frontmatter](https://gohugo.io/content-management/front-matter#readout) or via [archetypes](https://gohugo.io/content-management/archetypes/#readout).

| Parameter | Value Type | Overrides Global |
|:---- | ---- | ---- |
| title | string | N/A |
| date | date | N/A |
| description | string | N/A |
| draft | boolean | N/A |
| featured | boolean | N/A |
| tags | array/string | N/A |
| categories | array/string | N/A |
| toc | boolean | N/A |
| thumbnail | file path (string) | N/A |
| featureImage | file path (string) | N/A |
| shareImage | file path (string) | N/A |
| codeMaxLines | integer | yes |
| codeLineNumbers | boolean | yes |
| figurePositionShow | boolean | yes |
| figurePositionLabel | string | no |
| comment | boolean | no |

### Modify links menu

To add, remove, or reorganize top menu items, [edit this YAML file](https://github.com/chipzoller/hugo-clarity/blob/master/exampleSite/data/menu.yaml). These menu items also display any categories (taxonomies) that might be configured for articles.

### Social media

To edit your social media profile links, [edit this YAML file](https://github.com/chipzoller/hugo-clarity/blob/master/exampleSite/data/social.yaml).

If you wish to globally use a [large Twitter summary card](https://developer.twitter.com/en/docs/twitter-for-websites/cards/overview/summary-card-with-large-image) when sharing posts, set the global parameter `largeTwitterCard` to `true`.

### Search engine

If using Google Analytics, configure the `ga_analytics` global parameter in your site with your ID.

### Forcing light or dark mode

By default, sites authored using Clarity will load in the browser with the user's system-wide settings. I.e., if the underlying OS is set to dark mode, the site will automatically load in dark mode. Regardless of the default mode, a UI control switch exists to override the theme mode at the user's discretion.

In order to override this behavior and force one mode or another, add either `enforceLightMode` or `enforceDarkMode` to your `config.toml` file. If neither value is present, add it.

To enforce Light Mode by default, turn `enforceLightMode`  to `true`.

To enforce Dark Mode by default, turn `enforceDarkMode`  to `true`

```yaml
[params]
...
enforceLightMode = true # Force the site to always load in light mode.
...
```

Please note that you cannot enforce both modes at the same time. It wouldn't make sense, would it?

{{< tip "warning" >}}
> Please also note that the mode toggle UI will remain in place. That way, if a user prefers dark mode, they can have their way. The best of both worlds.
{{< /tip >}}

### I18N

This theme supports Multilingual (i18n / internationalization / translations)

The `exampleSite` gives you some examples already.
You may extend the multilingual functionality by following the [official documentation](https://gohugo.io/content-management/multilingual/).

Things to consider in multilingual:

* **supported languages** are configured in [config/_default/languages.toml](./exampleSite/config/_default/languages.toml)
* **add new language support** by creating a new file inside [i18n](./i18n/) directory.
  Check for missing translations using `hugo server --i18n-warnings`
* **taxonomy** names (tags, categories, etc...) are translated in [i18n](./i18n/) as well (translate the key)
* **menus** are translated manually in the config files [config/_default/menus/menu.xx.toml](./exampleSite/config/_default/menus/)
* **menu's languages list** are semi-hardcoded. You may chose another text for the menu entry with [languageMenuName](./exampleSite/config.toml). Please, do better and create a PR for that.
* **content** must be translated individually. Read the [official documentation](https://gohugo.io/content-management/multilingual/#translate-your-content) for information on how to do it.

**note:** if you do NOT want any translations (thus removing the translations menu entry), then you must not have any translations.
In the exampleSite that's as easy as removing the extra translations from the `config/_default/...` or executing this onliner:

```shell
sed '/^\[pt]$/,$d' -i config/_default/languages.toml   &&   rm config/_default/menus/menu.pt.toml
```

### Comments

Clarity supports Hugo built-in Disqus partial, you can enable Disqus simply by setting [`disqusShortname`](https://gohugo.io/templates/internal/#configure-disqus) in your configuration file.

{{< tip >}}
> `disqusShortname` should be placed in root level of configuration.
{{< /tip >}}

You can also create a file named `layouts/partials/comments.html` for customizing the comments, checkout [Comments Alternatives](https://gohugo.io/content-management/comments/#comments-alternatives) for details.
