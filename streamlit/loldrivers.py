from cryptography import x509
from datetime import date
from datetime import date
from datetime import datetime
from os import listdir
from os.path import isfile, join
import hashlib
import io
import json
import lief
import matplotlib.pyplot as plt
import os
import os, shutil
import pandas as pd
import streamlit as st
import uuid
import vt  # pip install vt-py
import yaml
from pathlib import Path


def delete_tmp_folder_content(path):
    for filename in os.listdir(path):
        file_path = os.path.join(path, filename)
        try:
            if os.path.isfile(file_path) or os.path.islink(file_path):
                os.unlink(file_path)
            elif os.path.isdir(file_path):
                shutil.rmtree(file_path)
        except Exception as e:
            print("Failed to delete %s. Reason: %s" % (file_path, e))


def download_file_vt(API, hash):
    try:
        client = vt.Client(API)
        try:
            Path("tmp/").mkdir(parents=True, exist_ok=True)
        except:
            print("Error Creating /tmp Folder")
        with open(f"tmp/{hash}.bin", "wb") as f:
            client.download_file(hash, f)
            client.close()
    except:
        return False
    return True


# Calculate Rich Header hash based on https://github.com/lief-project/LIEF/issues/587
def get_rich_header_hash(pe):
    clear_rich = ""
    for entry in pe.rich_header.entries:
        rich_header_hex = f"{entry.build_id.to_bytes(2, byteorder='little').hex()}{entry.id.to_bytes(2, byteorder='little').hex()}"
        clear_rich = f"{rich_header_hex}{entry.count.to_bytes(4, byteorder='little').hex()}{clear_rich}"
    clear_rich = bytes.fromhex(f"44616e53{'0'*24}{clear_rich}")

    md5 = hashlib.md5(clear_rich).hexdigest()
    sha1 = hashlib.sha1(clear_rich).hexdigest()
    sha256 = hashlib.sha256(clear_rich).hexdigest()

    return md5, sha1, sha256


def get_sections(pe):
    sections_info = {}
    for section in pe.sections:
        # TODO: Add offset, content, characteristics etc.
        sections_info[section.name] = {
            "Entropy": section.entropy,
            "Virtual Size": hex(section.virtual_size),
        }
    return sections_info


def get_hashes(driver_):
    md5 = hashlib.md5(driver_).hexdigest()
    sha1 = hashlib.sha1(driver_).hexdigest()
    sha256 = hashlib.sha256(driver_).hexdigest()
    return md5, sha1, sha256


def get_metadata(driver, bytes_form):
    """
    Generates a dict of metadata info extracted from driver
    """

    pe = lief.PE.parse(driver)

    if not isinstance(pe, lief._lief.PE.Binary):
        return None, None, None, None

    metadata = {}
    md5, sha1, sha256 = get_hashes(bytes_form)

    imphash = lief.PE.get_imphash(pe, lief.PE.IMPHASH_MODE.PEFILE)

    metadata["Name"] = pe.name
    metadata["Libraries"] = pe.libraries

    if pe.imported_functions:
        metadata["ImportedFunctions"] = [i.name for i in pe.imported_functions]
    else:
        metadata["ImportedFunctions"] = ""

    if pe.exported_functions:
        metadata["ExportedFunctions"] = [i.name for i in pe.exported_functions]
    else:
        metadata["ExportedFunctions"] = ""
    metadata["MD5"] = md5
    metadata["SHA1"] = sha1
    metadata["SHA256"] = sha256
    metadata["Imphash"] = imphash

    metadata["Machine"] = pe.header.machine.name
    metadata["MagicHeader"] = " ".join([hex(i)[2:] for i in pe.header.signature])
    metadata["CreationTimestamp"] = str(
        datetime.fromtimestamp(pe.header.time_date_stamps)
    )

    rich_md5, rich_sha1, rich_sha256 = get_rich_header_hash(pe)

    metadata["RichPEHeaderMD5"] = rich_md5
    metadata["RichPEHeaderSHA1"] = rich_sha1
    metadata["RichPEHeaderSHA256"] = rich_sha256

    metadata["AuthentihashMD5"] = pe.authentihash_md5.hex()
    metadata["AuthentihashSHA1"] = pe.authentihash_sha1.hex()
    metadata["AuthentihashSHA256"] = pe.authentihash_sha256.hex()

    metadata["Sections"] = get_sections(pe)

    try:
        version_info = pe.resources_manager.version.string_file_info.langcode_items[
            0
        ].items

        metadata["CompanyName"] = version_info.get("CompanyName", b"").decode("utf-8")
        metadata["FileDescription"] = version_info.get("FileDescription", b"").decode(
            "utf-8"
        )
        metadata["InternalName"] = version_info.get("InternalName", b"").decode("utf-8")
        metadata["OriginalFilename"] = version_info.get("OriginalFilename", b"").decode(
            "utf-8"
        )
        metadata["FileVersion"] = version_info.get("FileVersion", b"").decode("utf-8")
        metadata["ProductName"] = version_info.get("ProductName", b"").decode("utf-8")
        metadata["LegalCopyright"] = version_info.get("LegalCopyright", b"").decode(
            "utf-8"
        )
        metadata["ProductVersion"] = version_info.get("ProductVersion", b"").decode(
            "utf-8"
        )

    except Exception as e:
        metadata["CompanyName"] = ""
        metadata["FileDescription"] = ""
        metadata["InternalName"] = ""
        metadata["OriginalFilename"] = ""
        metadata["FileVersion"] = ""
        metadata["ProductName"] = ""
        metadata["LegalCopyright"] = ""
        metadata["ProductVersion"] = ""

    if len(pe.signatures) > 0:
        metadata["Signatures"] = []
        for sig in pe.signatures:
            sig_info = {"CertificatesInfo": "", "SignerInfo": ""}
            # Getting the Cert information
            if len(sig.certificates) > 0:
                sig_info["Certificates"] = []
                for cert in sig.certificates:
                    tmp_cert_dict = {}
                    # TODO: Add more info
                    tmp_cert_dict["Subject"] = cert.subject.replace("\\", "").replace(
                        "-", ","
                    )  # We remove these special character for YAML
                    # Note: This long python foo is just to convert the date from a list to a string
                    tmp_cert_dict["ValidFrom"] = str(
                        datetime.fromisoformat(
                            "-".join(
                                [
                                    str(i) if i >= 10 else "0" + str(i)
                                    for i in cert.valid_from[0:3]
                                ]
                            )
                            + " "
                            + ":".join(
                                [
                                    str(i) if i >= 10 else "0" + str(i)
                                    for i in cert.valid_from[3:]
                                ]
                            )
                        )
                    )
                    tmp_cert_dict["ValidTo"] = str(
                        datetime.fromisoformat(
                            "-".join(
                                [
                                    str(i) if i >= 10 else "0" + str(i)
                                    for i in cert.valid_to[0:3]
                                ]
                            )
                            + " "
                            + ":".join(
                                [
                                    str(i) if i >= 10 else "0" + str(i)
                                    for i in cert.valid_to[3:]
                                ]
                            )
                        )
                    )
                    tmp_cert_dict["Signature"] = cert.signature.hex()
                    tmp_cert_dict["SignatureAlgorithmOID"] = cert.signature_algorithm
                    tmp_cert_dict["IsCertificateAuthority"] = cert.is_ca
                    tmp_cert_dict["SerialNumber"] = cert.serial_number.hex()
                    tmp_cert_dict["Version"] = cert.version

                    # Calculate TBS Hashes // Thanks @yarden_shafir - https://twitter.com/yarden_shafir
                    raw_cert = x509.load_der_x509_certificate(cert.raw)
                    tmp_cert_dict["TBS"] = {
                        "MD5": hashlib.md5(raw_cert.tbs_certificate_bytes).hexdigest(),
                        "SHA1": hashlib.sha1(
                            raw_cert.tbs_certificate_bytes
                        ).hexdigest(),
                        "SHA256": hashlib.sha256(
                            raw_cert.tbs_certificate_bytes
                        ).hexdigest(),
                        "SHA384": hashlib.sha384(
                            raw_cert.tbs_certificate_bytes
                        ).hexdigest(),
                    }

                    sig_info["Certificates"].append(tmp_cert_dict)

            # Getting Signer Information
            if len(sig.signers) > 0:
                sig_info["Signer"] = []
                for signer in sig.signers:
                    tmp_signer_dict = {}
                    tmp_signer_dict["SerialNumber"] = signer.serial_number.hex()
                    tmp_signer_dict["Issuer"] = signer.issuer.replace("\\", "").replace(
                        "-", ","
                    )  # We remove these special character for YAML
                    tmp_signer_dict["Version"] = signer.version

                    sig_info["Signer"].append(tmp_signer_dict)

            metadata["Signatures"].append(sig_info)

    else:
        metadata["Signatures"] = {}

    return metadata, md5.lower(), sha1.lower(), sha256.lower()


# Load the CSV data
@st.cache_data
def load_data(file):
    df = pd.read_csv(file)
    df["Created"] = pd.to_datetime(df["Created"])  # Ensure 'Created' is datetime type
    return df


# Search Function
def search_dataframe(df, query):
    query = query.lower()
    return df[
        df.apply(
            lambda row: row.astype(str).str.lower().str.contains(query).any(), axis=1
        )
    ]


def new_loldriver_page():
    st.title("Create a New LOLDriver")
    st.subheader(
        "Create a new LOLDriver yaml file quick and easy. Fill in as much details as possible and click Generate."
    )

    if "settings" not in st.session_state:
        st.session_state["settings"] = {
            "upload_method": "Paste Hash Values",
        }

    def create_yaml_template():
        template = {
            "Id": "",
            "Author": "",
            "Created": "",
            "MitreID": "",
            "Category": "",
            "Verified": "",
            "Commands": {
                "Command": "",
                "Description": "",
                "Usecase": "",
                "Privileges": "",
                "OperatingSystem": "",
            },
            "Resources": [""],
            "Acknowledgement": {
                "Person": "",
                "Handle": "",
            },
            "Detection": [],
            "KnownVulnerableSamples": [
                {
                    "Filename": "",
                    "MD5": "",
                    "SHA1": "",
                    "SHA256": "",
                    "Signature": "",
                    "Date": "",
                    "Publisher": "",
                    "Company": "",
                    "Description": "",
                    "Product": "",
                    "ProductVersion": "",
                    "FileVersion": "",
                    "MachineType": "",
                    "OriginalFilename": "",
                }
            ],
            "Tags": [""],
        }
        return template

    verified_options = ["TRUE", "FALSE"]
    category_options = ["vulnerable driver", "malicious"]

    yaml_template = create_yaml_template()
    yaml_template["Tags"][0] = st.text_input("Name", yaml_template["Tags"][0])
    yaml_template["Author"] = st.text_input("Author", yaml_template["Author"])
    yaml_template["Created"] = st.text_input(
        "Created", date.today().strftime("%Y-%m-%d")
    )
    yaml_template["MitreID"] = st.text_input("MitreID", "T1068")
    yaml_template["Category"] = st.selectbox("Category", category_options, index=0)
    yaml_template["Verified"] = st.selectbox("Verified", verified_options, index=1)

    updated_command = f'sc.exe create {yaml_template["Tags"][0]} binPath=C:\\windows\\temp\\{yaml_template["Tags"][0]} type=kernel && sc.exe start {yaml_template["Tags"][0]}'
    yaml_template["Commands"]["Command"] = st.text_area("Command", updated_command)
    yaml_template["Commands"]["Description"] = st.text_area(
        "Description", yaml_template["Commands"]["Description"]
    )
    yaml_template["Commands"]["Usecase"] = st.text_input(
        "Usecase", "Elevate privileges"
    )
    yaml_template["Commands"]["Privileges"] = st.text_input("Privileges", "kernel")
    yaml_template["Commands"]["OperatingSystem"] = st.text_input(
        "OperatingSystem", "Windows 10"
    )
    yaml_template["Resources"][0] = st.text_input(
        "Resources", yaml_template["Resources"][0]
    )
    st.text("Binary Metadata")

    upload_method = st.radio(
        "Choose Option",
        options=["Paste Hash Values", "Upload Driver", "Download Driver Via VT"],
        index=["Paste Hash Values", "Upload Driver", "Download Driver Via VT"].index(
            st.session_state["settings"]["upload_method"]
        ),
        key="upload_method",
    )

    if upload_method == "Paste Hash Values":
        # Search by UUID
        yaml_template["KnownVulnerableSamples"][0]["MD5"] = st.text_input(
            "MD5", yaml_template["KnownVulnerableSamples"][0]["MD5"]
        )
        yaml_template["KnownVulnerableSamples"][0]["SHA1"] = st.text_input(
            "SHA1", yaml_template["KnownVulnerableSamples"][0]["SHA1"]
        )
        yaml_template["KnownVulnerableSamples"][0]["SHA256"] = st.text_input(
            "SHA256", yaml_template["KnownVulnerableSamples"][0]["SHA256"]
        )
        if st.button("Generate"):
            yaml_template["Id"] = str(uuid.uuid4())
            generated_yaml = yaml.dump(yaml_template, sort_keys=False)
            st.code(generated_yaml, language="yaml")
    elif upload_method == "Upload Driver":
        uploaded_file = st.file_uploader("Choose a file", accept_multiple_files=True)
        if uploaded_file is not None:
            if uploaded_file != 0:
                known_vuln_samples = []
                for file_ in uploaded_file:
                    # To read file as bytes:
                    bytes_data = file_.getvalue()
                    metadata_, md5, sha1, sha256 = get_metadata(
                        list(bytes_data), bytes_data
                    )

                    if metadata_ == None:
                        st.error("Some of the uploaded files are not in a PE format")
                    else:
                        known_vuln_samples.append(metadata_)
                yaml_template["KnownVulnerableSamples"] = known_vuln_samples
                if st.button("Generate"):
                    yaml_template["Id"] = str(uuid.uuid4())
                    generated_yaml = yaml.dump(yaml_template, sort_keys=False)
                    st.code(generated_yaml, language="yaml")

    elif upload_method == "Download Driver Via VT":
        vt_api = st.text_input(
            "VirusTotal API Key",
        )
        hashes = st.text_area("Driver Hashes (newline-separated)")
        hashes = hashes.split("\n")

        if st.button("Download & Generate Via VT"):
            if len(vt_api) != 64:
                st.error("You have entered an invalid API key")
            else:
                delete_tmp_folder_content("tmp/")
                for hash in hashes:
                    dw_res = download_file_vt(vt_api, hash)
                    if not dw_res:
                        st.error(
                            f"Error during download. Cannot download the file with the hash {hash}"
                        )
                downloaded_files = [
                    "tmp/" + f for f in listdir("tmp/") if isfile(join("tmp/", f))
                ]
                known_vuln_samples = []
                for file in downloaded_files:
                    with open(file, "rb") as f:
                        driver_data = f.read()
                        metadata_, md5, sha1, sha256 = get_metadata(
                            list(driver_data), driver_data
                        )
                        if metadata_ == None:
                            st.error(f"The file {file} is not in a PE format")
                        else:
                            known_vuln_samples.append(metadata_)
                yaml_template["KnownVulnerableSamples"] = known_vuln_samples
                st.success("VT download and enrichment complete")
                yaml_template["Id"] = str(uuid.uuid4())
                generated_yaml = yaml.dump(yaml_template, sort_keys=False)
                st.code(generated_yaml, language="yaml")


def csv_viewer_and_searcher():
    st.title("CSV Viewer and Searcher")

    uploaded_file = st.file_uploader("Choose a CSV file", type="csv")
    if uploaded_file is not None:
        df = load_data(uploaded_file)

        # Search
        query = st.text_input("Search Query", "")
        if query:
            search_df = search_dataframe(df.copy(), query)
        else:
            search_df = df.copy()

        # Generate clickable links
        search_df["Id"] = search_df["Id"].apply(
            lambda id: f"https://www.loldrivers.io/drivers/{id}/"
        )

        st.write(search_df, unsafe_allow_html=True)

        # Top 10 list for 'KnownVulnerableSample_Company' and 'Publisher'
        col1, col2, col3 = st.columns(3)

        with col1:
            st.header("Top 10 Company")
            st.write(df["KnownVulnerableSamples_Company"].value_counts().head(10))

        with col2:
            st.header("Top 10 Publisher")
            st.write(df["KnownVulnerableSamples_Publisher"].value_counts().head(10))

        with col3:
            st.header("Top 10 Description")
            st.write(df["KnownVulnerableSamples_Description"].value_counts().head(10))

        # Time series plot of contributions over time
        st.header("Contributions over time")
        contributions = df.resample(
            "M", on="Created"
        ).size()  # Resample to monthly frequency
        contributions.plot(kind="line")
        plt.ylabel("Number of contributions")
        st.pyplot(plt)

    else:
        st.write("Please upload a file.")


@st.cache_data
def load_json(file):
    with open(file) as f:
        data = json.load(f)
    return data


# Function to flatten json
def flatten_json(y):
    out = {}

    def flatten(x, name=""):
        if type(x) is dict:
            for a in x:
                flatten(x[a], name + a + "_")
        elif type(x) is list:
            i = 0
            for a in x:
                flatten(a, name + str(i) + "_")
                i += 1
        else:
            out[name[:-1]] = x

    flatten(y)
    return out


# Convert to DataFrame
def json_to_df(data):
    flat_data = [flatten_json(d) for d in data]
    df = pd.DataFrame(flat_data)
    return df


def json_viewer_and_searcher():
    st.title("JSON Viewer and Searcher")

    uploaded_file = st.file_uploader("Choose a JSON file", type="json")
    if uploaded_file is not None:
        data = json.load(uploaded_file)
        df = json_to_df(data)

        query = st.text_input("Search Query", "")
        if query:
            search_df = search_dataframe(df.copy(), query)
            st.dataframe(search_df)
        else:
            st.write("Please enter a search term.")
    else:
        st.write("Please upload a file.")


def main():
    st.set_page_config(page_title="LOLDriver")

    pages = {
        "Create a New LOLDriver": new_loldriver_page,
        "CSV Viewer and Searcher": csv_viewer_and_searcher,
        "JSON Viewer and Searcher": json_viewer_and_searcher,
    }

    st.sidebar.title("Navigation")
    page = st.sidebar.radio("Go to", list(pages.keys()))

    pages[page]()


if __name__ == "__main__":
    main()
