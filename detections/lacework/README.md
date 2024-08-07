# Lacework LQL for Detecting LOLDrivers

This detection contains a python script `loldriver_lql_gen.py` that generates a Lacework LQL (Lacework Query Language) detection yaml using the LOLDrivers malicious hashes to create a Lacework LQL yaml. This script can be easily configured using cron to always have a fresh copy from LOLDrivers. 

## What is LQL?

LQL (Lacework Query Language) is a powerful tool provided by Lacework for querying your environment's data. It allows you to create complex queries to analyze your data and detect potential threats or create CSMP policies. You can learn more about LQL from the [official Lacework documentation](https://docs.lacework.net/cli/lql-queries).

## How to Use

1. First, you need to install and configure the Lacework CLI. You can follow the instructions provided in the [official Lacework CLI documentation](https://docs.lacework.net/cli/).

2. Once you have the Lacework CLI installed and configured, you can run the LQL script provided in this project. The script is located in the file [LOLDriver_Malicious_Hashes.yaml](LOLDriver_Malicious_Hashes.yaml).

3. To run the script, use the following command:
`lacework query run --start "-120d@d" --end "@h" -f LOLDriver_Malicious_Hashes.yaml`


## Install script

To run the script, you need to install Poetry, a tool for Python dependency management. Follow these steps:

1. Install Poetry: Poetry is a tool for dependency management in Python. It allows you to declare the libraries your project depends on and it will manage (install/update) them for you. You can install it by following the instructions on the [official Poetry documentation](https://python-poetry.org/docs/#installation).
2. Once Poetry is installed, navigate to the project directory and install the project dependencies: `poetry install`
3. Enter the project's virtual environment: `poetry shell`
4. Now, you can run the script: `python loldriver_lql_gen.py`


By following these steps, you should be able to generate a fresh Lacework LQL yaml using the LOLDrivers malicious hashes.
