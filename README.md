# LOLDrivers 🚗💨

Living Off The Land Drivers (LOLDrivers) is a curated list of Windows drivers used by adversaries to bypass security controls and carry out attacks. The project helps security professionals stay informed and mitigate potential threats. Visit our website at loldrivers.io for more information.

LOLDrivers demo

##  🏗️ Building and Testing Locally

### Requirements

* python 3.10
* [Poetry](https://python-poetry.org/docs/#installation)
* [Golang](https://go.dev/dl/)
* [Hugo](https://gohugo.io/)

### Steps to Build and Test Locally

1. Clone the repository:

```
git clone https://github.com/magicsword-io/LOLDrivers.git
```

2. Change to the project directory:

```
cd LOLDrivers
```

3. Install dependencies:

```
poetry install
```

4. Activate the virtual environment:

```
poetry shell
```

5. Build the site using the files under the /yaml folder:

```
python bin/site.py
```

6. Run the website locally:

```
cd loldrivers.io && hugo serve
```

## 🤝 Contributing & Making PRs

We welcome contributions! If you'd like to contribute, please follow these steps:

1. Fork the repository
2. Create a new branch for your changes
3. Make your changes and commit them to your branch
4. Push your changes to your fork
5. Open a Pull Request (PR) against the upstream repository

For more detailed instructions, please refer to the [CONTRIBUTING.md](CONTRIBUTING.md) file. To create a new YAML file for a driver, use the provided [YML-Template](YML-Template.md).

## 🚨 Sigma and Sysmon Detection

LOLDrivers includes Sigma and Sysmon detection rules to help you identify potential threats. Check out the [sigma](detections/sigma/driver_load_win_vuln_drivers.yml) and [sysmon](detections/sysmon/sysmon_config_vulnerable_hashes.xml) files under the detection folder for more information.

Happy hunting! 🕵️‍♂️