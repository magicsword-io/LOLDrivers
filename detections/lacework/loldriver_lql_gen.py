import requests
import textwrap

def fetch_hashes(url):
    response = requests.get(url)
    if response.status_code != 200:
        print("Error fetching data.")
        return None
    return response.text.strip().split("\n")

def generate_lql(hashes):
    hashes_condition = "\n            OR ".join(f"files.FILEDATA_HASH = '{hash_}'" for hash_ in hashes)
    query = textwrap.dedent(f"""\
    queryId: LOLDriver_Malicious_Hashes
    queryText: |-
        {{
            source {{
                LW_HE_FILES files
            }}
            filter {{
                {hashes_condition}
            }}
            return distinct {{
                files.FILEDATA_HASH,
                files.FILE_ACCESSED_TIME,
                files.FILE_CREATED_TIME,
                files.FILE_MODIFIED_TIME,
                files.FILE_NAME,
                files.FILE_PERMISSIONS,
                files.FILE_TYPE,
                files.HARD_LINK_COUNT,
                files.LINK_ABS_DEST_PATH,
                files.LINK_DEST_PATH,
                files.MID,
                files.OWNER_GID,
                files.OWNER_UID,
                files.OWNER_USERNAME,
                files.PATH,
                files.RECORD_CREATED_TIME,
                files.SIZE
            }}
        }}""")

    with open('LOLDriver_Malicious_Hashes.yaml', 'w') as file:
        file.write(query)

    print("Query saved to 'LOLDriver_Malicious_Hashes.yaml'.")

url = 'https://raw.githubusercontent.com/magicsword-io/LOLDrivers/main/detections/hashes/samples_malicious.sha256'
hashes = fetch_hashes(url)
if hashes:
    generate_lql(hashes)

