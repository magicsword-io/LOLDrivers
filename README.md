# LOLDrivers
Living Off The Land Drivers

# Requirements

* python 3.10
* [Poetry](https://python-poetry.org/docs/#installation)
* [Golang](https://go.dev/dl/)
* [Hugo](https://gohugo.io/)

# Run locally

* `poetry install`
* `poetry shell`
* `cd loldrivers.io && hugo serve`

# Build site from csv

To build all the yamls from the `drivers.csv` file using `bin/genyaml.py`. To do this run:

```
poetry shell
python bin/genyaml.py
```

# Building site from yamls

To build the site using the files under the `/yaml` folder simply run:


```
poetry shell
python bin/site.py
```


