import os
import argparse
import urllib.parse
import yaml

# Parse command line arguments
parser = argparse.ArgumentParser(description='Generate an SVG counter for a folder with a list of YAML files.')
parser.add_argument('-f', '--folder', metavar='FOLDER', type=str, default='yaml/', help='the folder to search for YAML files (default: yaml/)')
args = parser.parse_args()

# Find YAML files in the specified folder
sample_count = 0
for filename in os.listdir(args.folder):
    if filename.endswith('.yaml'):
        with open(os.path.join(args.folder, filename), 'r') as f:
            yaml_data = yaml.safe_load(f)
            if yaml_data is not None and 'KnownVulnerableSamples' in yaml_data:
                sample_count += len(yaml_data['KnownVulnerableSamples'])

# Generate the shields.io badge URL
params = {
    'label': 'Drivers',
    'message': str(sample_count),
    'style': 'flat'
}
url = 'https://img.shields.io/badge/{}-{}-{}.svg'.format(
    urllib.parse.quote_plus(params['label']),
    urllib.parse.quote_plus(params['message']),
    urllib.parse.quote_plus(params['style'])
)

# Save shields URL in Github Output to be used in the next step.
with open(os.environ['GITHUB_OUTPUT'], 'a') as fh:
    print(f'result={url}', file=fh)
