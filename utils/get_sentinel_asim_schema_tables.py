from typing import Dict, List

import requests
from bs4 import BeautifulSoup

BASE_URL = "https://learn.microsoft.com/en-us/azure/sentinel"

# TODO: Add a function to get the common fields from the ASIM schemas
# TODO: Add a function to write the table data to a file


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
    response = requests.get(url)
    response.raise_for_status()
    soup = BeautifulSoup(response.content, "html.parser")

    # Extract the table name (e.g. 'imAuditEvent')
    table_name = soup.find("code", class_="lang-kql").text.strip().split()[0]
    # Extract the field schema details under "Schema details"
    field_data = extract_field_data(soup)

    return {"table_name": table_name, "fields": field_data}


def extract_field_data(soup: BeautifulSoup) -> List[Dict[str, str]]:
    """
    Extracts field data from a Sentinel ASIM schema page.

    :param soup: BeautifulSoup object of the schema page.
    :return: A list of dictionaries with the field name and type.
    """
    schema_details_section = soup.find(id="schema-details")
    field_data = []

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
                        field_data.append({"Field": cols[0], "Class": cols[1], "Type": cols[2], "Description": cols[3]})
    return field_data


def get_common_field_data() -> List[Dict[str, str]]:
    """
    Extracts common field data from a Sentinel ASIM schema page.

    :return: A list of dictionaries with the field name and type.
    """
    full_url = f"{BASE_URL}/normalization-common-fields"
    common_field_info = extract_table_name_and_fields(full_url)


def process_asim_schemas() -> List[Dict[str, List[Dict[str, str]]]]:
    """Processes all ASIM schemas and extracts table names and field schemas."""
    tables = get_sentinel_asim_schema_tables()
    schema_data = []
    common_field_data = get_common_field_data()

    for href in tables:
        full_url = f"{BASE_URL}/{href}"
        print(f"Processing {full_url}...")
        schema_info = extract_table_name_and_fields(full_url)
        schema_data.append(schema_info)

    return schema_data


if __name__ == "__main__":
    asim_schema_data = process_asim_schemas()
    for schema in asim_schema_data:
        print(f"Table Name: {schema['table_name']}")
        print("Fields:")
        for field in schema["fields"]:
            print(f"  - {field}")
