+++
title = "Theme Overrides"
weight=18
+++

### Custom CSS and JS

To minimize HTTP requests per page, we would recommend loading CSS styles and JavaScript helpers in single bundles. That is to say, one CSS file and one JavaScript file. Using Hugo minify functions, these files will be minified to optimize the size.

Going by the above 👆🏻 reason, we recommend adding custom CSS and JS via the custom SASS file ([Compose](https://github.com/onweru/compose/blob/master/assets/sass/_custom.sass), [Clarity](https://github.com/chipzoller/hugo-clarity/blob/master/assets/sass/_custom.sass)) and the custom JS file ([Compose](https://github.com/onweru/compose/hugo-compose/blob/master/assets/js/custom.js), [Clarity](https://github.com/chipzoller/hugo-clarity/blob/master/assets/js/custom.js)).

However, sometimes you may need to load additional style or script files. In such cases, you can add custom `.css` and `.js` files by listing them in the `config.toml` file (see the snippet below). Similar to images, these paths should be relative to the `static` directory.

```yaml
[params]
...
customCSS = ["css/custom.css"] # Include custom CSS files
customJS = ["js/custom.js"] # Include custom JS files
...
```

> __Pro Tip__: You can change the theme colors via the [this variable's SASS file](https://github.com/chipzoller/hugo-clarity/blob/master/assets/sass/_variables.sass)

### Hooks

Clarity provides some hooks for adding code on page.

If you need to add some code(CSS import, HTML meta or similar) to the head section on every page, add a partial to your project:

```
layouts/partials/hooks/head-end.html
```

Similar, if you want to add some code right before the body end, create your own version of the following file:

```
layouts/partials/hooks/body-end.html
```
