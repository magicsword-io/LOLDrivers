import yaml
import os

def find_and_modify_revoked_bootloaders(directory):
    for filename in os.listdir(directory):
        if filename.endswith(".yaml"):
            filepath = os.path.join(directory, filename)
            with open(filepath, 'r') as file:
                try:
                    data = yaml.safe_load(file)
                    if 'Category' in data and data['Category'] == 'Revoked Bootloaders':
                        # Get the bootloader filename from the 'Tags' key and remove any leading/trailing whitespace
                        data['Tags'] = [tag.strip() for tag in data['Tags']]

                        # Write back to the file
                        with open(filepath, 'w') as file:
                            yaml.safe_dump(data, file, default_flow_style=False, allow_unicode=True)

                except yaml.YAMLError as error:
                    print(f"Error reading file {filename}: {error}")

# Replace the path below with the path to your directory.
find_and_modify_revoked_bootloaders('../yaml')
