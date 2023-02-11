+++
title = "Use forestry CMS"
description = ""
weight = 3
+++

Do you prefer managing your site using a CMS? Or would you like to make it easier for someone (a non-techie, perhaps) in your team to make edits easily? If interested, follow along. Else, skip to the [next section](../overview/)

Let's sync your site with forestry CMS.

## Prerequisites !!

Obviously you  ought to have __a github account__. This is where your website source will live. Basically, forestry will read from github and write (commmit) to your github repo.

{{< tip "warning" >}}
Gitlab or bitbucket will work too. Just check their [implementation here](https://forestry.io/docs/git-sync/gitlab/). Happy fishing.
{{< /tip >}}

### Requirement 1 : A Forestry account

Jump over to [forestry](https://bit.ly/forestry-account) and sign up for an account. Consider signing up using your github account. That way, you don't have to deal with passwords.

### Requirement 2: A Netlify account _(optional)_

If you intend to host with something other than Netlify _e.g github pages_, please scroll on. Hosting with Netlify is a lot of fun though; I highly recommend it.

### Step 1 : Fork or Clone Compse theme

First we will fork [this theme's](https://github.com/onweru/compose) template.

### Step 2 : Add your repository in Forestry

{{< tip >}}
The exampleSite already comes with prefilled default forestry settings. If you set up your site using [option 2](../getting-started/#option-2-recommended), look for a file `.forestry/settings.yml` and remove all `exampleSite/` strings from it.
{{< /tip >}}

Go to your [forestry](https://bit.ly/forestry-account)  account and click on `import your site now`.

1. Choose `hugo`
2. `github` or `gitlab`. wherever your repo is at.
3. Select your repo
