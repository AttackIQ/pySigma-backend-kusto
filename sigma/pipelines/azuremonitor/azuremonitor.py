from typing import Optional

from sigma.pipelines.kusto_common.postprocessing import (
    PrependQueryTablePostprocessingItem,
)
from sigma.processing.conditions import (
    ExcludeFieldCondition,
    IncludeFieldCondition,
    LogsourceCondition,
    RuleProcessingItemAppliedCondition,
    RuleProcessingStateCondition,
)
from sigma.processing.pipeline import ProcessingItem, ProcessingPipeline
from sigma.processing.transformations import (
    DropDetectionItemTransformation,
    ReplaceStringTransformation,
    RuleFailureTransformation,
)

from ..kusto_common.errors import InvalidFieldTransformation
from ..kusto_common.schema import create_schema
from ..kusto_common.transformations import (
    DynamicFieldMappingTransformation,
    RegistryActionTypeValueTransformation,
    SetQueryTableStateTransformation,
)
from .mappings import (
    AZURE_MONITOR_FIELD_MAPPINGS,
    CATEGORY_TO_TABLE_MAPPINGS,
    EVENTID_CATEGORY_TO_TABLE_MAPPINGS,
)
from .schema import AzureMonitorSchema
from .tables import AZURE_MONITOR_TABLES
from .transformations import (
    DefaultHashesValuesTransformation,
    SecurityEventHashesValuesTransformation,
)

AZURE_MONITOR_SCHEMA = create_schema(AzureMonitorSchema, AZURE_MONITOR_TABLES)

# Drop ObjectType fields
drop_fields_proc_item = ProcessingItem(
    identifier="azure_monitor_drop_fields",
    transformation=DropDetectionItemTransformation(),
    field_name_conditions=[IncludeFieldCondition(["ObjectType"])],
)

## Fieldmappings
fieldmappings_proc_item = ProcessingItem(
    identifier="azure_monitor_table_fieldmappings",
    transformation=DynamicFieldMappingTransformation(AZURE_MONITOR_FIELD_MAPPINGS),
)

## Generic Field Mappings, keep this last
## Exclude any fields already mapped, e.g. if a table mapping has been applied.
# This will fix the case where ProcessId is usually mapped to InitiatingProcessId, EXCEPT for the DeviceProcessEvent table where it stays as ProcessId.
# So we can map ProcessId to ProcessId in the DeviceProcessEvents table mapping, and prevent the generic mapping to InitiatingProcessId from being applied
# by adding a detection item condition that the table field mappings have been applied

# generic_field_mappings_proc_item = ProcessingItem(
#    identifier="azure_monitor_generic_fieldmappings",
#    transformation=GenericFieldMappingTransformation(AZURE_MONITOR_FIELD_MAPPINGS),
#    detection_item_conditions=[DetectionItemProcessingItemAppliedCondition("azure_monitor_table_fieldmappings")],
#    detection_item_condition_linking=any,
#    detection_item_condition_negation=True,
# )

REGISTRY_FIELDS = [
    "RegistryKey",
    "RegistryPreviousKey",
    "ObjectName",
]

## Field Value Replacements ProcessingItems
replacement_proc_items = [
    # Sysmon uses abbreviations in RegistryKey values, replace with full key names as the DeviceRegistryEvents schema
    # expects them to be
    # Note: Ensure this comes AFTER field mapping renames, as we're specifying DeviceRegistryEvent fields
    #
    # Do this one first, or else the HKLM only one will replace HKLM and mess up the regex
    ProcessingItem(
        identifier="azure_monitor_registry_key_replace_currentcontrolset",
        transformation=ReplaceStringTransformation(
            regex=r"(?i)(^HKLM\\SYSTEM\\CurrentControlSet)",
            replacement=r"HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet001",
        ),
        field_name_conditions=[IncludeFieldCondition(REGISTRY_FIELDS)],
    ),
    ProcessingItem(
        identifier="azure_monitor_registry_key_replace_hklm",
        transformation=ReplaceStringTransformation(regex=r"(?i)(^HKLM)", replacement=r"HKEY_LOCAL_MACHINE"),
        field_name_conditions=[IncludeFieldCondition(REGISTRY_FIELDS)],
    ),
    ProcessingItem(
        identifier="azure_monitor_registry_key_replace_hku",
        transformation=ReplaceStringTransformation(regex=r"(?i)(^HKU)", replacement=r"HKEY_USERS"),
        field_name_conditions=[IncludeFieldCondition(REGISTRY_FIELDS)],
    ),
    ProcessingItem(
        identifier="azure_monitor_registry_key_replace_hkcr",
        transformation=ReplaceStringTransformation(regex=r"(?i)(^HKCR)", replacement=r"HKEY_LOCAL_MACHINE\\CLASSES"),
        field_name_conditions=[IncludeFieldCondition(REGISTRY_FIELDS)],
    ),
    ProcessingItem(
        identifier="azure_monitor_registry_actiontype_value",
        transformation=RegistryActionTypeValueTransformation(),
        field_name_conditions=[IncludeFieldCondition(["EventType"])],
    ),
    # Processing item to transform the Hashes field in the SecurityEvent table to get rid of the hash algorithm prefix in each value
    ProcessingItem(
        identifier="azure_monitor_securityevent_hashes_field_values",
        transformation=SecurityEventHashesValuesTransformation(),
        field_name_conditions=[IncludeFieldCondition(["FileHash"])],
        rule_conditions=[RuleProcessingStateCondition("query_table", "SecurityEvent")],
    ),
    ProcessingItem(
        identifier="azure_monitor_hashes_field_values",
        transformation=DefaultHashesValuesTransformation(),
        field_name_conditions=[IncludeFieldCondition(["Hashes"])],
        rule_conditions=[RuleProcessingStateCondition("query_table", "SecurityEvent")],
        rule_condition_negation=True,
    ),
    # Processing item to essentially ignore initiated field
    ProcessingItem(
        identifier="azure_monitor_network_initiated_field",
        transformation=DropDetectionItemTransformation(),
        field_name_conditions=[IncludeFieldCondition(["Initiated"])],
        rule_conditions=[LogsourceCondition(category="network_connection")],
    ),
]

# Exceptions/Errors ProcessingItems
# Catch-all for when the query table is not set, meaning the rule could not be mapped to a table or the table name was not set
rule_error_proc_items = [
    # Category Not Supported or Query Table Not Set
    ProcessingItem(
        identifier="azure_monitor_unsupported_rule_category_or_missing_query_table",
        transformation=RuleFailureTransformation(
            "Rule category not yet supported by the Azure Monitor pipeline or query_table is not set."
        ),
        rule_conditions=[
            RuleProcessingItemAppliedCondition("azure_monitor_set_query_table"),  # type: ignore
            RuleProcessingStateCondition("query_table", None),  # type: ignore
        ],
        rule_condition_linking=all,
    )
]


def get_valid_fields(table_name):
    return (
        list(AZURE_MONITOR_SCHEMA.tables[table_name].fields.keys())
        + list(AZURE_MONITOR_FIELD_MAPPINGS.table_mappings.get(table_name, {}).keys())
        + list(AZURE_MONITOR_FIELD_MAPPINGS.generic_mappings.keys())
        + ["Hashes"]
    )


field_error_proc_items = []

for table_name in AZURE_MONITOR_SCHEMA.tables.keys():
    valid_fields = get_valid_fields(table_name)

    field_error_proc_items.append(
        ProcessingItem(
            identifier=f"azure_monitor_unsupported_fields_{table_name}",
            transformation=InvalidFieldTransformation(
                f"Please use valid fields for the {table_name} table, or the following fields that have fieldmappings in this "
                f"pipeline:\n{', '.join(sorted(set(valid_fields)))}"
            ),
            field_name_conditions=[ExcludeFieldCondition(fields=valid_fields)],
            rule_conditions=[
                RuleProcessingItemAppliedCondition("azure_monitor_set_query_table"),
                RuleProcessingStateCondition("query_table", table_name),
            ],
            rule_condition_linking=all,
        )
    )

# Add a catch-all error for custom table names
field_error_proc_items.append(
    ProcessingItem(
        identifier="azure_monitor_unsupported_fields_custom",
        transformation=InvalidFieldTransformation(
            "Invalid field name for the custom table. Please ensure you're using valid fields for your custom table."
        ),
        field_name_conditions=[
            ExcludeFieldCondition(fields=list(AZURE_MONITOR_FIELD_MAPPINGS.generic_mappings.keys()) + ["Hashes"])
        ],
        rule_conditions=[
            RuleProcessingItemAppliedCondition("azure_monitor_set_query_table"),  # type: ignore
            RuleProcessingStateCondition("query_table", None),  # type: ignore
        ],
        rule_condition_linking=all,
    )
)


def azure_monitor_pipeline(query_table: Optional[str] = None) -> ProcessingPipeline:
    """Pipeline for transformations for SigmaRules to use in the Kusto Query Language backend.

    :param query_table: If specified, the table name will be used in the finalizer, otherwise the table name will be selected based on the category of the rule.
    :type query_table: Optional[str]

    :return: ProcessingPipeline for Microsoft Azure Monitor
    :rtype: ProcessingPipeline
    """

    pipeline_items = [
        ProcessingItem(
            identifier="azure_monitor_set_query_table",
            transformation=SetQueryTableStateTransformation(
                query_table, CATEGORY_TO_TABLE_MAPPINGS, EVENTID_CATEGORY_TO_TABLE_MAPPINGS
            ),
        ),
        fieldmappings_proc_item,
        drop_fields_proc_item,
        # generic_field_mappings_proc_item,
        *replacement_proc_items,
        *rule_error_proc_items,
        *field_error_proc_items,
    ]

    return ProcessingPipeline(
        name="Generic Log Sources to Azure Monitor tables and fields",
        priority=10,
        items=pipeline_items,
        allowed_backends=frozenset(["kusto"]),
        postprocessing_items=[PrependQueryTablePostprocessingItem],  # type: ignore
    )
