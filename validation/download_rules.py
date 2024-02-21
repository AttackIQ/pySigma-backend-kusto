import io
import logging
import os
import re
import zipfile
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

import requests
import ruamel.yaml
from sigma.rule import SigmaRule

from sigma.backends.microsoft365defender import Microsoft365DefenderBackend

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

BASE_PATH = os.path.dirname(__file__)
RULE_PATH = os.path.join(BASE_PATH, "rules")
DETECTIONS_PATH = os.path.join(BASE_PATH, "detections")
SIGMA_URL = "https://github.com/SigmaHQ/sigma/releases/latest/download/sigma_core++.zip"


def download_rules():
    """Downloads the latest core++ Sigma rules from the official repository and extracts them to the rules folder."""
    r = requests.get(SIGMA_URL)
    z = zipfile.ZipFile(io.BytesIO(r.content))
    z.extractall(BASE_PATH)
    logger.info("Downloaded and extracted Sigma rules to %s", BASE_PATH)


def parse_and_create_detection(rule_file: str):
    rule_data = rule_file.read_text()
    rule = SigmaRule.from_yaml(rule_data)
    rule_json = {
        'id': str(rule.id),
        'name': rule.title,
        'description': rule.description,
        'severity': str(rule.level),
        'queryFrequency': '10m',
        'queryPeriod': '10m',
        'triggerOperator': 'gt',
        'triggerThreshold': 0,
        'version': '1.0.0',
        'kind': 'scheduled',
    }

    backend = Microsoft365DefenderBackend()
    try:
        rule_query = str(backend.convert_rule(rule)[0]).strip()
    except Exception as e:
        rule_query = None
    if rule_query:
        # Replace special characters in the rule name to avoid issues with the file system
        rule_filename = re.sub(r"([\\/\.\s])", "_", rule_json.get('name'))
        detection_path = os.path.join(DETECTIONS_PATH, f"{rule_filename}.yaml")
        # Create the detection file, use LiteralScalarStrings for the query to avoid escaping issues
        rule_json['query'] = ruamel.yaml.scalarstring.LiteralScalarString(rule_query)
        # Write the detection file
        with open(detection_path, "w") as f:
            ruamel.yaml.YAML().dump(rule_json, f)


def main():
    download_rules()
    with ThreadPoolExecutor() as executor:
        futures = []
        total = 0
        for rule_file in Path(RULE_PATH).rglob("*.yml"):
            try:
                futures.append(executor.submit(parse_and_create_detection, rule_file))
            except Exception as e:
                print(e)

        for future in as_completed(futures):
            total += 1
            if total % 250 == 0:
                logger.info("Processed %s rules", total)
    logger.info("Done processing %s rules", total)


if __name__ == "__main__":
    main()
    # AFTERWARDS, RUN `prevalidate sentinel unittest validation/detections validation/defaultschema`
