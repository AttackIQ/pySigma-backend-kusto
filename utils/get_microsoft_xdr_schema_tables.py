import base64
import os
import re
from datetime import datetime, timezone
from typing import Dict, List

import requests
import yaml
from dotenv import load_dotenv

load_dotenv()

# GitHub API configuration
GITHUB_API_KEY = os.getenv("GITHUB_API_KEY")
BASE_URL = "https://api.github.com/repos/MicrosoftDocs/defender-docs/contents/defender-xdr"
HEADERS = {"Accept": "application/vnd.github.v3+json"}
if GITHUB_API_KEY:
    HEADERS["Authorization"] = f"token {GITHUB_API_KEY}"

OUTPUT_FILE = "sigma/pipelines/microsoft365defender/tables.py"


def fetch_content(file_name: str) -> str:
    """Fetch the file content from GitHub and decode it."""
    url = f"{BASE_URL}/{file_name}"
    response = requests.get(url, headers=HEADERS)
    if response.ok:
        return base64.b64decode(response.json()["content"]).decode("utf-8")
    print(f"Failed to retrieve content for {file_name}: {response.reason}")
    return None


def extract_table_urls(toc_content: str) -> List[str]:
    """Extract table URLs from the TOC.yml file."""
    toc_data = yaml.safe_load(toc_content)
    data_schema_section = toc_data[0]["items"]
    for section_name in [
        "Investigate and respond to threats",
        "Search for threats with advanced hunting",
        "Data schema",
    ]:
        data_schema_section = next((item for item in data_schema_section if item.get("name") == section_name), None)[
            "items"
        ]
    return [item["href"] for item in data_schema_section[2:] if "href" in item]


def extract_table_schema(content: str) -> dict:
    """Extract table schema from markdown content."""
    match = re.search(r"\|\s?Column name\s?\|\s?Data type\s?\|\s?Description\s?\|([\s\S]+?)\n\n", content)
    if not match:
        return {}

    schema_data = {}
    for row in match.group(1).strip().split("\n")[1:]:
        columns = [col.strip() for col in row.strip("|").split("|")]
        if len(columns) == 3:
            schema_data[columns[0]] = {"data_type": columns[1], "description": columns[2]}
    return schema_data


def process_table(file_path: str) -> dict:
    """Process a table file and extract the schema."""
    content = fetch_content(file_path)
    if not content:
        return {}

    table_name = re.search(r"^# (.+)", content, re.MULTILINE)
    table_name = table_name.group(1) if table_name else "Unknown"
    return {table_name: extract_table_schema(content)}


def write_schema(output_file: str, schema_tables: Dict[str, dict]):
    """Write the schema tables to a Python file."""
    with open(output_file, "w") as f:
        f.write("# This file is auto-generated. Do not edit manually.\n")
        f.write(f"# Last updated: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S')} UTC\n\n")
        f.write("MICROSOFT_XDR_TABLES = {\n")
        for table, fields in schema_tables.items():
            f.write(f'    "{table}": {{\n')
            for field, info in fields.items():
                f.write(
                    f'        "{field.strip("`")}": {{"data_type": "{info["data_type"].strip("`")}", "description": {repr(info["description"])}}},\n'
                )
            f.write("    },\n")
        f.write("}\n")


def get_all_tables() -> dict:
    """Retrieve all tables from the TOC and process them."""
    toc_content = fetch_content("TOC.yml")
    if not toc_content:
        return {}
    table_urls = extract_table_urls(toc_content)
    return {table: schema for url in table_urls for table, schema in process_table(url).items()}


if __name__ == "__main__":
    if not GITHUB_API_KEY:
        print("Warning: GITHUB_API_KEY not set. You may encounter rate limiting.")
    tables = get_all_tables()
    write_schema(OUTPUT_FILE, tables)
    print(f"Schema written to {OUTPUT_FILE}")
