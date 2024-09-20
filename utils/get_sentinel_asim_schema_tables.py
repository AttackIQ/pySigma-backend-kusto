import re
from datetime import datetime, timezone
from typing import Dict, List, Optional, Tuple

import requests
from bs4 import BeautifulSoup

BASE_URL = "https://learn.microsoft.com/en-us/azure/sentinel"
OUTPUT_FILE = "sigma/pipelines/sentinelasim/tables.py"

# TODO: Add a function to get the common fields from the ASIM schemas
# TODO: Add a function to write the table data to a file


def get_request(url: str) -> requests.Response:
    """
    Sends a GET request to the specified URL and returns the response.

    :param url: The URL to send the GET request to.
    :return: The response from the GET request.
    """
    response = requests.get(url)
    response.raise_for_status()

    return response


def extract_asim_schema_hrefs(items: List[dict]) -> List[str]:
    """Extracts hrefs for ASIM schemas from the JSON data."""
    for item in items:
        if item.get("toc_title") == "Reference":
            return extract_asim_schemas(item.get("children", []))
    return []


def extract_asim_schemas(items: List[dict]) -> List[str]:
    """Finds the ASIM schemas section and returns the relevant hrefs."""
    for item in items:
        if item.get("toc_title").lower() == "advanced security information model (asim)":
            return find_schema_hrefs(item.get("children", []))
    return []


def find_schema_hrefs(items: List[dict]) -> List[str]:
    """Extracts the schema hrefs, excluding legacy schemas."""
    hrefs = []
    for item in items:
        if item.get("toc_title").lower() == "asim schemas":
            for schema in item.get("children", []):
                if schema.get("toc_title") != "Legacy network normalization schema":
                    hrefs.append(schema.get("href"))
    return hrefs


def get_sentinel_asim_schema_tables() -> List[str]:
    """Fetches the ASIM schema table hrefs from Azure Sentinel documentation."""
    url = f"{BASE_URL}/toc.json"
    response = requests.get(url)
    response.raise_for_status()  # Ensures proper error handling
    data = response.json()
    return extract_asim_schema_hrefs(data.get("items", []))


def extract_table_name_and_fields(url: str) -> Dict[str, List[Dict[str, str]]]:
    """
    Extracts the table name and field schema from a Sentinel ASIM schema page.

    :param url: Full URL of the schema page.
    :return: A dictionary with the table name and a list of field schemas.
    """
    response = get_request(url)
    soup = BeautifulSoup(response.content, "html.parser")

    table_name = extract_table_name(soup)
    if table_name is None:
        print(f"No ASIM table found for {url}. Skipping...")
        return None

    field_data = extract_field_data(soup)

    return {table_name: field_data}


def extract_table_name(soup: BeautifulSoup) -> Optional[str]:
    """
    Extracts the table name from the BeautifulSoup object.

    :param soup: BeautifulSoup object of the schema page.
    :return: The extracted table name or None if not found.
    """
    def extract_from_code():
        code_element = soup.find("code", class_="lang-kql")
        if not code_element:
            return None
        table_name = code_element.text.strip().split()[0]
        return extract_table_name_from_string(table_name)

    def extract_from_text():
        whole_text = soup.get_text()
        match = re.search(r"(?i)im(\w+)<?vendor>?<?Product>?", whole_text)
        return f"im{match.group(1)}" if match else None

    def extract_table_name_from_string(text):
        match = re.search(r"(?i)(im|_im_)(\w+)", text)
        return f"{match.group(1)}{match.group(2)}" if match else None

    return extract_from_code() or extract_from_text()


def extract_field_data(soup: BeautifulSoup) -> List[Dict[str, str]]:
    """
    Extracts field data from a Sentinel ASIM schema page.

    :param soup: BeautifulSoup object of the schema page.
    :return: A list of dictionaries with the field name and type.
    """
    schema_details_section = soup.find(id="schema-details")
    field_data = {}

    if schema_details_section:
        # Loop through all tables in the section and its subsections
        tables = soup.find_all("table")
        for table in tables:
            # Each table has columns: Field, Class, Type, Description
            headers = [th.text.strip() for th in table.find_all("th")]
            if "Field" in headers and "Class" in headers:
                # Parse each row of the table
                for row in table.find_all("tr")[1:]:  # Skip header row
                    cols = [td.text.strip() for td in row.find_all("td")]
                    if len(cols) == 4:  # Ensure we have all four columns
                        field_data[cols[0]] = {"class": cols[1], "data_type": cols[2], "description": cols[3]}
    return field_data


def get_common_field_data() -> List[Dict[str, str]]:
    """
    Extracts common field data from a Sentinel ASIM schema page.

    :return: A list of dictionaries with the field name and type.
    """
    full_url = f"{BASE_URL}/normalization-common-fields"
    response = get_request(full_url)
    soup = BeautifulSoup(response.content, "html.parser")
    common_field_info = extract_field_data(soup)

    return common_field_info


def write_schema(output_file: str, schema_tables: Dict[str, dict], common_field_data: Dict[str, dict]):
    """Write the schema tables to a Python file."""
    with open(output_file, "w") as f:
        f.write("# This file is auto-generated. Do not edit manually.\n")
        f.write(f"# Last updated: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S')} UTC\n\n")
        f.write("SENTINEL_ASIM_TABLES = {\n")
        for table, fields in schema_tables.items():
            f.write(f'    "{table}": {{\n')
            for field, info in fields.items():
                f.write(
                    f'        "{field.strip("`")}": {{"data_type": "{info["data_type"].strip("`")}", "description": {repr(info["description"])}, "class": "{info["class"].strip("`")}"}},\n'
                )
            f.write("    },\n")
        f.write("}\n")
        f.write("SENTINEL_ASIM_COMMON_FIELDS = {\n")
        f.write(f'    "COMMON": {{\n')
        for field, info in common_field_data.items():
            f.write(
                f'        "{field.strip("`")}": {{"data_type": "{info["data_type"].strip("`")}", "description": {repr(info["description"])}, "class": "{info["class"].strip("`")}"}},\n'
            )
        f.write("    },\n")
        f.write("}\n")


def process_asim_schemas() -> Tuple[Dict[str, dict], Dict[str, dict]]:
    """Processes all ASIM schemas and extracts table names and field schemas."""
    tables = get_sentinel_asim_schema_tables()
    schema_data = {}
    common_field_data = get_common_field_data()

    for href in tables:
        full_url = f"{BASE_URL}/{href}"
        print(f"Processing {full_url}...")
        if schema_info := extract_table_name_and_fields(full_url):
            schema_data.update(schema_info)

    return schema_data, common_field_data


if __name__ == "__main__":
    schema_data, common_field_data = process_asim_schemas()
    write_schema(OUTPUT_FILE, schema_data, common_field_data)
    print(f"Schema written to {OUTPUT_FILE}")
    