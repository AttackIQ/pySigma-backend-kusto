# 🛡️ pySigma Kusto Query Language (KQL) Backend

![Tests](https://github.com/AttackIQ/pySigma-backend-microsoft365defender/actions/workflows/test.yml/badge.svg)
![Coverage Badge](https://img.shields.io/endpoint?url=https://gist.githubusercontent.com/slincoln-aiq/9c0879725c7f94387801390bbb0ac8d6/raw/slincoln-aiq-pySigma-backend-microsoft365defender.json)
![Status](https://img.shields.io/badge/Status-pre--release-orange)

## 📖 Overview

This backend for [pySigma](https://github.com/SigmaHQ/pySigma) enables the transformation of Sigma Rules into queries in [Kusto Query Language (KQL)](https://learn.microsoft.com/en-us/kusto/query/?view=microsoft-fabric) for products such as [Microsoft 365 Defender Advanced Hunting Queries](https://learn.microsoft.com/en-us/microsoft-365/security/defender/advanced-hunting-query-language?view=o365-worldwide), [Azure Sentinel Queries](https://learn.microsoft.com/en-us/azure/sentinel/kusto-overview), and more!

This project was formally named pySigma Microsoft 365 Defender Backend, or pySigma-microsoft365defender-backend.

### 🔑 Key Features
- Provides `sigma.backends.kusto` package with `KustoBackend` class
- Includes `microsoft_365_defender_pipeline` and `sentinelasim_pipeline` for field renames and error handling
- Supports output format: Query string for Advanced Hunting Queries in KQL

### 🧑‍💻 Maintainer
- [Stephen Lincoln](https://github.com/slincoln-aiq) via [AttackIQ](https://github.com/AttackIQ)

## 🚀 Installation

### 📦 Using pip

```bash
pip install pysigma-backend-kusto
```


### 🔌 Using pySigma Plugins (requires pySigma >= 0.10.0)

```python
from sigma.plugins import SigmaPluginDirectory  # Requires pySigma >= 0.10.0

plugins = SigmaPluginDirectory.default_plugin_directory()
plugins.get_plugin_by_id("kusto").install()
```


## 🔧 Dependencies
- pySigma >= v0.10.0

## 📘 Usage

### 🖥️ sigma-cli

Use with `sigma-cli` per [typical sigma-cli usage](https://github.com/SigmaHQ/sigma-cli#usage):

```bash
sigma convert -t kusto -p microsoft_365_defender -f default -s ~/sigma/rules
```

### 🐍 Python Script

Use the backend and pipeline in a standalone Python script. Note, the backend automatically applies the pipeline, but
you can manually add it if you would like.

```python
from sigma.rule import SigmaRule
from sigma.backends.kusto import KustoBackend
from sigma.pipelines.microsoft365defender import microsoft_365_defender_pipeline

# Define an example rule as a YAML str
sigma_rule = SigmaRule.from_yaml("""
  title: Mimikatz CommandLine
  status: test
  logsource:
      category: process_creation
      product: windows
  detection:
      sel:
          CommandLine|contains: mimikatz.exe
      condition: sel
""")
# Create backend, which automatically adds the pipeline
kusto_backend = KustoBackend()

# Or apply the pipeline manually
pipeline = microsoft_365_defender_pipeline()
pipeline.apply(sigma_rule)

# Convert the rule
print(sigma_rule.title + " KQL Query: \n")
print(kusto_backend.convert_rule(sigma_rule)[0])
```

Output:

```
Mimikatz CommandLine KQL Query: 

DeviceProcessEvents
| where ProcessCommandLine contains "mimikatz.exe"
````

## 🛠️ Advanced Features

### 🔄 Pipeline & Backend Args (New in 0.2.0)

- `transform_parent_image`: Controls ParentImage field mapping behavior
  - When set to `True` (default), maps ParentImage to InitiatingProcessParentFileName
  - When set to `False`, maps ParentImage to InitiatingProcessFileName
  - Useful for adjusting field mappings based on specific rule requirements
  - Example usage:

```python
pipeline = microsoft_365_defender_pipeline(transform_parent_image=False)
```

This argument allows fine-tuning of the ParentImage field mapping, which can be crucial for accurate rule conversion in certain scenarios. By default, it follows the behavior of mapping ParentImage to the parent process name, but setting it to `False` allows for mapping to the initiating process name instead.

### 🗃️ Custom Table Names (New in 0.3.0) (Experimental)

- `query_table`: Allows user to override table mappings and set their own table name
  - Experimental feature, implementation is subject to change 
  - Example usage:

via YAML
```YAML
# test_table_name_pipeline.yml
transformations:
- id: test_name_name
  type: set_state
  key: "query_table"
  val: ["MyTestTable"]
```
```bash
sigma convert -t kusto -p microsoft_365_defender -p test_table_name_pipeline.yml test_rule.yml
```

via Python

```python
from sigma.pipelines.microsoft365defender import microsoft_365_defender_pipeline

my_pipeline = microsoft_365_defender_pipeline(query_table="MyTestTable")  # Or ["MyTestTable"]

## 📊 Rule Support

### 🖥️ Supported Categories (product=windows)
- process_creation
- image_load
- network_connection
- file_access, file_change, file_delete, file_event, file_rename
- registry_add, registry_delete, registry_event, registry_set

## 🔍 Processing Pipeline

The `microsoft_365_defender_pipeline` includes custom `ProcessingPipeline` `Transformation` classes:

- 🔀 ParentImageValueTransformation
  - Extracts the parent process name from the Sysmon ParentImage field
  - Maps to InitiatingProcessParentFileName (as InitiatingProcessParentFolderPath is not available)
  - Use before mapping ParentImage to InitiatingProcessFileName

- 🔢 SplitDomainUserTransformation
  - Splits the User field into separate domain and username fields
  - Handles Sysmon `User` field containing both domain and username
  - Creates new SigmaDetectionItems for Domain and Username
  - Use with field_name_condition for username fields

- 🔐 HashesValuesTransformation
  - Processes 'Hashes' field values in 'algo:hash_value' format
  - Creates new SigmaDetectionItems for each hash type
  - Infers hash type based on length if not specified
  - Use with field_name_condition for the Hashes field

- 📝 RegistryActionTypeValueTransformation
  - Adjusts registry ActionType values to match Microsoft DeviceRegistryEvents table
  - Ensures compatibility between Sysmon and Microsoft 365 Defender schemas

- ❌ InvalidFieldTransformation
  - Extends DetectionItemFailureTransformation
  - Includes the field name in the error message
  - Helps identify unsupported or invalid fields in the rule

- 🏷️ SetQueryTableStateTransformation
  - Appends rule query table to pipeline state query_table key
  - Used to set custom table names for queries

The pipeline also includes a custom `Finalizer`:

- 📊 Microsoft365DefenderTableFinalizer
  - Adds the table name as a prefix to each query
  - Uses custom table names if specified, otherwise selects based on rule category
  - Keeps individual queries separate instead of combining them
  - Allows for fine-grained control over query table selection

## ⚠️ Limitations and Constraints

- Works only for `product=windows` and listed rule categories
- Unsupported fields may cause exceptions (improvements in progress)

For more detailed information, please refer to the full documentation.

