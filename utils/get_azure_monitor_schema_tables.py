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
BASE_URL = "https://api.github.com/repos/MicrosoftDocs/azure-reference-other/contents/azure-monitor-ref/tables"
HEADERS = {"Accept": "application/vnd.github.v3+json"}
if GITHUB_API_KEY:
    HEADERS["Authorization"] = f"token {GITHUB_API_KEY}"

OUTPUT_FILE = "sigma/pipelines/azuremonitor/tables_new.py"

def fetch_content(file_name: str = None) -> str:
    """Fetch the file content from GitHub and decode it."""
    url = BASE_URL
    if file_name:
        url = f"{BASE_URL}/{file_name}"
    response = requests.get(url, headers=HEADERS)
    if response.ok:
        try:
            json_content = response.json()
            if isinstance(json_content, dict) and "content" in json_content:
                return base64.b64decode(json_content["content"]).decode("utf-8")
            else:
                return response.json()
        except ValueError:
            return response.text
    print(f"Failed to retrieve content for {file_name}: {response.reason}")
    return None


def extract_table_urls(json_content: dict) -> List[str]:
    """Extract table URLs from the json content."""
    return [entry["name"] for entry in json_content]


def extract_table_schema(content: str, table_name: str = None) -> dict:
    """Extract table schema from markdown content."""
    match = re.search(r"\|\s*Column\s*\|\s*Type\s*\|\s*Description\s*\|\n\|[-\s|]*\n((?:\|.*\|$\n?)+)", content, re.MULTILINE)
    if not match:
        match = re.search(r'\|Column\|Type\|Description\|[\r\n]+\|---\|---\|---\|[\n\r]+(.*?)(?=\n##|\Z)', content, re.DOTALL)
    if not match:
        print(f"Field table not found in {table_name}")
        return {}
    
    table_content = match.group(1)
    rows = table_content.strip().split('\n')


    schema_data = {}
    for row in match.group(1).strip().split('\n'):
        columns = [col.strip() for col in row.strip().strip("|").split("|")]
        if len(columns) >= 2:
            schema_data[columns[0]] = {
                "data_type": columns[1],
                "description": columns[2] if len(columns) > 2 else ""
            }
    if not schema_data:
        print(f"Table schema could not be parsed from {table_name}")
    return schema_data


def process_table(file_path: str) -> dict:
    """Process a table file and extract the schema."""
    print(f"Processing table: {file_path}")
    content = fetch_content(file_path)
    if not content:
        return {}
    # Try to get table name from header after ---
    table_name = re.search(r"^title:.*-\s*(.+)$", content, re.MULTILINE)
    if not table_name:
        # Try to get table name from top text between ---
        table_name = re.search(r"^ms\.custom\:\s+(.+)", content, re.MULTILINE)
    table_name = table_name.group(1).strip() if table_name else None
    if not table_name:
        print(f"Table name not found in {file_path}")
        return {}
    return {table_name: extract_table_schema(content, table_name)}


def write_schema(output_file: str, schema_tables: Dict[str, dict]):
    """Write the schema tables to a Python file."""
    with open(output_file, "w") as f:
        f.write("# This file is auto-generated. Do not edit manually.\n")
        f.write(f"# Last updated: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S')} UTC\n\n")
        f.write("AZURE_MONITOR_TABLES = {\n")
        for table, fields in schema_tables.items():
            f.write(f'    "{table}": {{\n')
            for field, info in fields.items():
                f.write(
                    f'        "{field.strip("`")}": {{"data_type": "{info["data_type"].strip("`")}", "description": {repr(info["description"])}}},\n'
                )
            f.write("    },\n")
        f.write("}\n")

def get_all_includes_tables() -> dict:
    tables_list = fetch_content("includes")
    if not tables_list:
        return {}
    table_urls = ["includes/" + url for url in extract_table_urls(tables_list) if url.endswith(".md")]
    return {table: schema for url in table_urls for table, schema in process_table(url).items() if schema}
    
    
def get_all_tables() -> dict:
    """Retrieve all tables from the TOC and process them."""
    tables_list = fetch_content()
    if not tables_list:
        return {}
    table_urls = [x for x in extract_table_urls(tables_list) if x.endswith(".md")]
    return {table: schema for url in table_urls for table, schema in process_table(url).items() if schema}


if __name__ == "__main__":
    if not GITHUB_API_KEY:
        print("Warning: GITHUB_API_KEY not set. You may encounter rate limiting.")
    #data = process_table("azurediagnostics.md")
    #print(data)
    tables = get_all_tables()
    tables_includes = get_all_includes_tables()
    tables.update(tables_includes)
    write_schema(OUTPUT_FILE, tables)
    print(f"Schema written to {OUTPUT_FILE}")
