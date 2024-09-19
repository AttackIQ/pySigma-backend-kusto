from typing import Optional

from sigma.processing.conditions import (
    ExcludeFieldCondition,
    IncludeFieldCondition,
    LogsourceCondition,
)
from sigma.processing.pipeline import ProcessingItem, ProcessingPipeline
from sigma.processing.transformations import (
    DropDetectionItemTransformation,
    FieldMappingTransformation,
    ReplaceStringTransformation,
    RuleFailureTransformation,
)

from .errors import InvalidFieldTransformation
from .finalization import Microsoft365DefenderTableFinalizer
from .mappings import (
    CATEGORY_TO_CONDITIONS_MAPPINGS,
    CATEGORY_TO_TABLE_MAPPINGS,
    MICROSOFT_XDR_FIELD_MAPPINGS,
)
from .schema import FieldInfo, MicrosoftXDRSchema, TableSchema
from .tables import MICROSOFT_XDR_TABLES
from .transformations import (
    DynamicFieldMappingTransformation,
    GenericFieldMappingTransformation,
    HashesValuesTransformation,
    ParentImageValueTransformation,
    RegistryActionTypeValueTransformation,
    SetQueryTableStateTransformation,
    SplitDomainUserTransformation,
)


def create_xdr_schema() -> MicrosoftXDRSchema:
    schema = MicrosoftXDRSchema()
    for table_name, fields in MICROSOFT_XDR_TABLES.items():
        table_schema = TableSchema()
        for field_name, field_info in fields.items():
            table_schema.fields[field_name] = FieldInfo(
                data_type=field_info["data_type"], description=field_info["description"]
            )
        schema.tables[table_name] = table_schema
    return schema


MICROSOFT_XDR_SCHEMA = create_xdr_schema()


# Mapping from ParentImage to InitiatingProcessParentFileName. Must be used alongside of ParentImageValueTransformation
parent_image_field_mapping = {"ParentImage": "InitiatingProcessParentFileName"}


## ProcessingItems to set state key 'query_table' to use in backend
## i.e. $QueryTable$ | $rest_of_query$
query_table_proc_items = [
    ProcessingItem(
        identifier=f"microsoft_xdr_set_query_table_{category}",
        transformation=SetQueryTableStateTransformation(table_name),
        rule_conditions=[CATEGORY_TO_CONDITIONS_MAPPINGS[category]],
    )
    for category, table_name in CATEGORY_TO_TABLE_MAPPINGS.items()
]

## Fieldmappings
fieldmappings_proc_item = ProcessingItem(
    identifier="microsoft_xdr_fieldmappings",
    transformation=DynamicFieldMappingTransformation(MICROSOFT_XDR_FIELD_MAPPINGS),
)

## Generic Fielp Mappings, keep this last
## Exclude any fields already mapped. For example, if process_creation events ProcessId has already
## been mapped to the same field name (ProcessId), we don't to remap it to InitiatingProcessId
generic_field_mappings_proc_item = ProcessingItem(
    identifier="microsoft_xdr_fieldmappings_generic",
    transformation=GenericFieldMappingTransformation(MICROSOFT_XDR_FIELD_MAPPINGS),
)


## Field Value Replacements ProcessingItems
replacement_proc_items = [
    # Sysmon uses abbreviations in RegistryKey values, replace with full key names as the DeviceRegistryEvents schema
    # expects them to be
    # Note: Ensure this comes AFTER field mapping renames, as we're specifying DeviceRegistryEvent fields
    #
    # Do this one first, or else the HKLM only one will replace HKLM and mess up the regex
    ProcessingItem(
        identifier="microsoft_xdr_registry_key_replace_currentcontrolset",
        transformation=ReplaceStringTransformation(
            regex=r"(?i)(^HKLM\\SYSTEM\\CurrentControlSet)",
            replacement=r"HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet001",
        ),
        field_name_conditions=[IncludeFieldCondition(["RegistryKey", "PreviousRegistryKey"])],
    ),
    ProcessingItem(
        identifier="microsoft_xdr_registry_key_replace_hklm",
        transformation=ReplaceStringTransformation(regex=r"(?i)(^HKLM)", replacement=r"HKEY_LOCAL_MACHINE"),
        field_name_conditions=[IncludeFieldCondition(["RegistryKey", "PreviousRegistryKey"])],
    ),
    ProcessingItem(
        identifier="microsoft_xdr_registry_key_replace_hku",
        transformation=ReplaceStringTransformation(regex=r"(?i)(^HKU)", replacement=r"HKEY_USERS"),
        field_name_conditions=[IncludeFieldCondition(["RegistryKey", "PreviousRegistryKey"])],
    ),
    ProcessingItem(
        identifier="microsoft_xdr_registry_key_replace_hkcr",
        transformation=ReplaceStringTransformation(regex=r"(?i)(^HKCR)", replacement=r"HKEY_LOCAL_MACHINE\\CLASSES"),
        field_name_conditions=[IncludeFieldCondition(["RegistryKey", "PreviousRegistryKey"])],
    ),
    ProcessingItem(
        identifier="microsoft_xdr_registry_actiontype_value",
        transformation=RegistryActionTypeValueTransformation(),
        field_name_conditions=[IncludeFieldCondition(["ActionType"])],
    ),
    # Extract Domain from Username fields
    ProcessingItem(
        identifier="microsoft_xdr_domain_username_extract",
        transformation=SplitDomainUserTransformation(),
        field_name_conditions=[IncludeFieldCondition(["AccountName", "InitiatingProcessAccountName"])],
    ),
    ProcessingItem(
        identifier="microsoft_xdr_hashes_field_values",
        transformation=HashesValuesTransformation(),
        field_name_conditions=[IncludeFieldCondition(["Hashes"])],
    ),
    # Processing item to essentially ignore initiated field
    ProcessingItem(
        identifier="microsoft_xdr_network_initiated_field",
        transformation=DropDetectionItemTransformation(),
        field_name_conditions=[IncludeFieldCondition(["Initiated"])],
        rule_conditions=[LogsourceCondition(category="network_connection")],
    ),
]

# ParentImage -> InitiatingProcessParentFileName
parent_image_proc_items = [
    # First apply fieldmapping from ParentImage to InitiatingProcessParentFileName for non process-creation rules
    ProcessingItem(
        identifier="microsoft_xdr_parent_image_fieldmapping",
        transformation=FieldMappingTransformation(parent_image_field_mapping),
        rule_conditions=[
            # Exclude process_creation events, there's direct field mapping in this schema table
            LogsourceCondition(category="process_creation")
        ],
        rule_condition_negation=True,
    ),
    # Second, extract the parent process name from the full path
    ProcessingItem(
        identifier="microsoft_xdr_parent_image_name_value",
        transformation=ParentImageValueTransformation(),
        field_name_conditions=[
            IncludeFieldCondition(["InitiatingProcessParentFileName"]),
        ],
        rule_conditions=[
            # Exclude process_creation events, there's direct field mapping in this schema table
            LogsourceCondition(category="process_creation")
        ],
        rule_condition_negation=True,
    ),
]

## Exceptions/Errors ProcessingItems
rule_error_proc_items = [
    # Category Not Supported
    ProcessingItem(
        identifier="microsoft_xdr_unsupported_rule_category",
        rule_condition_linking=any,
        transformation=RuleFailureTransformation(
            "Rule category not yet supported by the Microsoft 365 Defender Sigma backend."
        ),
        rule_condition_negation=True,
        rule_conditions=[x for x in CATEGORY_TO_CONDITIONS_MAPPINGS.values()],
    )
]

field_error_proc_items = [
    ProcessingItem(
        identifier=f"microsoft_xdr_unsupported_fields_{category}",
        transformation=InvalidFieldTransformation(
            f"Please use valid fields for the {table_name} table, or the following fields that have keymappings in this "
            f"pipeline:\n"
            f"{', '.join(sorted(set(MICROSOFT_XDR_FIELD_MAPPINGS.table_mappings.get(table_name, {}).keys()).union(MICROSOFT_XDR_FIELD_MAPPINGS.generic_mappings.keys()).union({'Hashes'})))}"
        ),
        field_name_conditions=[
            ExcludeFieldCondition(
                fields=MICROSOFT_XDR_SCHEMA.get_valid_fields(table_name)
                + list(MICROSOFT_XDR_FIELD_MAPPINGS.generic_mappings.keys())
                + ["Hashes"]
            )
        ],
        rule_conditions=[CATEGORY_TO_CONDITIONS_MAPPINGS[category]],
    )
    for category, table_name in CATEGORY_TO_TABLE_MAPPINGS.items()
]


def microsoft_365_defender_pipeline(
    transform_parent_image: Optional[bool] = True, query_table: Optional[str] = None
) -> ProcessingPipeline:
    return microsoft_xdr_pipeline(transform_parent_image, query_table)


def microsoft_xdr_pipeline(
    transform_parent_image: Optional[bool] = True, query_table: Optional[str] = None
) -> ProcessingPipeline:
    """Pipeline for transformations for SigmaRules to use in the Kusto Query Language backend.
    Field mappings based on documentation found here:
    https://learn.microsoft.com/en-us/microsoft-365/security/defender/advanced-hunting-query-language?view=o365-worldwide

    :param query_table: If specified, the table name will be used in the finalizer, otherwise the table name will be selected based on the category of the rule.
    :type query_table: Optional[str]
    :param transform_parent_image: If True, the ParentImage field will be mapped to InitiatingProcessParentFileName, and
    the parent process name in the ParentImage will be extracted and used. This is because the Microsoft 365 Defender
    table schema does not contain a InitiatingProcessParentFolderPath field like it does for InitiatingProcessFolderPath.
    i.e. ParentImage: C:\\Windows\\System32\\whoami.exe -> InitiatingProcessParentFileName: whoami.exe.
    Defaults to True
    :type transform_parent_image: Optional[bool]

    :return: ProcessingPipeline for Microsoft 365 Defender Backend
    :rtype: ProcessingPipeline
    """

    pipeline_items = [
        *query_table_proc_items,
        fieldmappings_proc_item,
        generic_field_mappings_proc_item,
        *replacement_proc_items,
        *rule_error_proc_items,
        *field_error_proc_items,
    ]

    if transform_parent_image:
        pipeline_items[4:4] = parent_image_proc_items

    return ProcessingPipeline(
        name="Generic Log Sources to Windows 365 Defender Transformation",
        priority=10,
        items=pipeline_items,
        allowed_backends=frozenset(["kusto"]),
        finalizers=[Microsoft365DefenderTableFinalizer(table_names=query_table)],
    )
