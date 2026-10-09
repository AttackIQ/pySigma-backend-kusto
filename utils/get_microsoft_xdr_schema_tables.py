from datetime import datetime, timezone
from typing import Dict

import requests
from dotenv import load_dotenv

load_dotenv()

BASE_URL = "https://learn.microsoft.com/en-us/defender-xdr"
HEADERS = {"Accept": "text/markdown"}

OUTPUT_FILE = "sigma/pipelines/microsoftxdr/tables.py"


def fetch_content(file_name: str) -> str:
    """Fetch the file content from MS Learn and decode it."""
    url = f"{BASE_URL}/{file_name}?accept=text/markdown"
    response = requests.get(url, headers=HEADERS)
    if response.ok:
        return response.content.decode("utf-8")
    print(f"Failed to retrieve content for {file_name}: {response.reason}")
    return None

def parse_markdown(content: str) -> dict[str, str]:
    """Divide Markdown content into sections based on headers"""
    lines = content.splitlines()
    sections = {}

    # Create a fallback if there's no initial header
    current_header = "Introduction"
    current_content = []

    for line in lines:
        if line.startswith("#"):
            if current_content:
                sections[current_header] = "\n".join(current_content).strip()
            current_header = line.replace("#", "").strip()
            current_content = []
        else:
            current_content.append(line)

    if current_content:
        sections[current_header] = "\n".join(current_content).strip()

    return sections

def extract_table_urls(toc_content: str) -> list[dict[str, str]]:
    """Extract table URLs from the MS Learn file."""
    toc_data = parse_markdown(toc_content)
    data_schema_section = toc_data.get("Learn the schema tables").split("\n")

    table_urls = []

    for line in data_schema_section:
        if line.startswith("|"):
            table_info = line.split("|")[1]
            if "(" in table_info and ")" in table_info and "[" in table_info and "]" in table_info:
                table_name = table_info.split("[")[1].split("]")[0]
                table_url = table_info.split("(")[1].split(")")[0]
                table_urls.append({"name": table_name, "url": table_url})
    return table_urls

def extract_table_schema(content: str) -> dict:
    """Extract table schema from markdown content."""
    lines = content.split("\n")
    schema_data = {}

    for line in lines:
        if line.startswith("|") and not line.startswith("| Column") and not line.startswith("| -"):
            parts = line.split("|")
            if len(parts) == 5:
                schema_data[parts[1].strip().replace("`", "")] = {"data_type": parts[2].strip().replace("`", ""), "description": parts[3].strip()}

    return schema_data

def process_table(table_name: str, table_url: str) -> dict:
    """Process a table file and extract the schema."""
    content = fetch_content(table_url)
    
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
    toc_content = fetch_content("advanced-hunting-schema-tables")
    if not toc_content:
        return {}
    table_urls = extract_table_urls(toc_content)
    return {table: schema for item in table_urls for table, schema in process_table(item["name"], item["url"]).items()}


if __name__ == "__main__":
    tables = get_all_tables()
    write_schema(OUTPUT_FILE, tables)
    print(f"Schema written to {OUTPUT_FILE}")
