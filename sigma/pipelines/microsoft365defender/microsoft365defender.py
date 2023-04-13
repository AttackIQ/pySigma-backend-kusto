from typing import Union, Optional, Iterable

from sigma.exceptions import SigmaTransformationError
from sigma.pipelines.common import logsource_windows_process_creation, \
    logsource_windows_image_load, logsource_windows_file_event, logsource_windows_file_delete, \
    logsource_windows_file_change, logsource_windows_file_access, logsource_windows_file_rename, \
    logsource_windows_registry_set, logsource_windows_registry_add, logsource_windows_registry_delete, \
    logsource_windows_registry_event, logsource_windows_network_connection
from sigma.processing.transformations import FieldMappingTransformation, \
    RuleFailureTransformation, ReplaceStringTransformation, SetStateTransformation, DetectionItemTransformation, \
    ValueTransformation, DetectionItemFailureTransformation
from sigma.processing.conditions import IncludeFieldCondition, \
    RuleProcessingItemAppliedCondition, ExcludeFieldCondition
from sigma.conditions import ConditionOR
from sigma.types import SigmaString, SigmaType
from sigma.processing.pipeline import ProcessingItem, ProcessingPipeline
from sigma.rule import SigmaDetectionItem, SigmaDetection
from collections import defaultdict


# CUSTOM TRANSFORMATIONS
## Custom DetectionItemTransformation to split domain and user, if applicable
class SplitDomainUserTransformation(DetectionItemTransformation):
    """Custom DetectionItemTransformation transformation to split a User field into separate domain and user fields,
    if applicable.  This is to handle the case where the Sysmon `User` field may contain a domain AND username, and
    Advanced Hunting queries separate out the domain and username into separate fields.
    If a matching field_name_condition field uses the schema DOMAIN\\USER, a new SigmaDetectionItem
    will be made for the Domain and put inside a SigmaDetection with the original User SigmaDetectionItem
    (minus the domain) for the matching SigmaDetectionItem.

    You should use this with a field_name_condition for `IncludeFieldName(['field', 'names', 'for', 'username']`)"""

    def apply_detection_item(self, detection_item: SigmaDetectionItem) -> Optional[
        Union[SigmaDetection, SigmaDetectionItem]]:
        to_return = []
        if not isinstance(detection_item.value, list):  # Ensure its a list, but it most likely will be
            detection_item.value = list(detection_item.value)
        for d in detection_item.value:
            username = d.to_plain().split("\\")
            username_field_mappings = {
                'AccountName': 'AccountDomain',
                'RequestAccountName': 'RequestAccountDomain',
                'InitiatingProcessAccountName': 'InitiatingProcessAccountDomain',
            }
            if len(username) == 2:
                domain = username[0]
                username = [SigmaString(username[1])]

                domain_field = username_field_mappings.get(detection_item.field, "InitiatingProcessAccountDomain")
                domain_value = [SigmaString(domain)]
                user_detection_item = SigmaDetectionItem(field=detection_item.field,
                                                         modifiers=[],
                                                         value=username,
                                                         )
                domain_detection_item = SigmaDetectionItem(field=domain_field,
                                                           modifiers=[],
                                                           value=domain_value)
                to_return.append(SigmaDetection(detection_items=[user_detection_item, domain_detection_item]))
            else:

                to_return.append(SigmaDetection([SigmaDetectionItem(field=detection_item.field,
                                                                    modifiers=detection_item.modifiers,
                                                                    value=username)]))
        return SigmaDetection(to_return)


## Custom DetectionItemTransformation to regex hash algos/values in Hashes field, if applicable
class HashesValuesTransformation(DetectionItemTransformation):
    """Custom DetectionItemTransformation to take a list of values in the 'Hashes' field, which are expected to be
    'algo:hash_value', and create new SigmaDetectionItems for each hash type, where the values is a list of
    SigmaString hashes. If the hash type is not part of the value, it will be inferred based on length.

    Use with field_name_condition for Hashes field"""

    def apply_detection_item(self, detection_item: SigmaDetectionItem) -> Optional[
        Union[SigmaDetection, SigmaDetectionItem]]:
        to_return = []
        algo_dict = defaultdict(list)  # map to keep track of algos and lists of values
        if not isinstance(detection_item.value, list):
            detection_item.value = [detection_item.value]
        for d in detection_item.value:
            hash_value = d.to_plain().split("|")
            if len(hash_value) == 2:
                hash_algo = hash_value[0].upper() if hash_value[0].upper() in ['MD5', 'SHA1', 'SHA256'] else ""
                hash_value = hash_value[1]
            else:
                hash_value = hash_value[0]
                if len(hash_value) == 32:  # MD5
                    hash_algo = 'MD5'
                elif len(hash_value) == 40:  # SHA1
                    hash_algo = 'SHA1'
                elif len(hash_value) == 64:  # SHA256
                    hash_algo = "SHA256"
                else:  # Invalid algo, no fieldname for keyword search
                    hash_algo = ''
            algo_dict[hash_algo].append(hash_value)
        for k, v in algo_dict.items():
            if k:  # Filter out invalid hash algo types
                to_return.append(SigmaDetectionItem(field=k if k != 'keyword' else None,
                                                    modifiers=[],
                                                    value=[SigmaString(x) for x in v]))
        return SigmaDetection(detection_items=to_return, item_linking=ConditionOR)


## Change ActionType value AFTER field transformations from Sysmon values to DeviceRegistryEvents values
class RegistryActionTypeValueTransformation(ValueTransformation):
    """Custom ValueTransformation transformation. The Microsoft DeviceRegistryEvents table expect the ActionType to
    be a slightly different set of values than what Sysmon specified, so this will change them to the correct value."""
    value_mappings = {  # Sysmon EventType -> DeviceRegistyEvents ActionType
        'CreateKey': 'RegistryKeyCreated',
        'DeleteKey': ['RegistryKeyDeleted', 'RegistryValueDeleted'],
        'SetValue': 'RegistryValueSet',
        'RenameKey': ['RegistryValueSet', 'RegistryKeyCreated'],
    }

    def apply_value(self, field: str, val: SigmaType) -> Optional[Union[SigmaType, Iterable[SigmaType]]]:
        mapped_vals = self.value_mappings.get(val.to_plain(), val.to_plain())
        if isinstance(mapped_vals, list):
            return [SigmaString(v) for v in mapped_vals]
        return SigmaString(mapped_vals)


class InvalidFieldTransformation(DetectionItemFailureTransformation):
    """
    Overrides the apply_detection_item() method from DetectionItemFailureTransformation to also include the field name
    in the error message
    """

    def apply_detection_item(self, detection_item: SigmaDetectionItem) -> None:
        field_name = detection_item.field
        self.message = f"Invalid SigmaDetectionItem field name encountered: {field_name}. " + self.message
        raise SigmaTransformationError(self.message)


# FIELD MAPPINGS
## Field mappings from Sysmon (where applicable) fields to Advanced Hunting Query fields based on schema in tables
## See: https://learn.microsoft.com/en-us/microsoft-365/security/defender/advanced-hunting-schema-tables?view=o365-worldwide#learn-the-schema-tables
query_table_field_mappings = {
    'DeviceProcessEvents': {  # process_creation, Sysmon EventID 1 -> DeviceProcessEvents table
        # ProcessGuid: ?,
        'ProcessId': 'ProcessId',
        'Image': 'FolderPath',
        'FileVersion': 'ProcessVersionInfoProductVersion',
        'Description': 'ProcessVersionInfoFileDescription',
        'Product': 'ProcessVersionInfoProductName',
        'Company': 'ProcessVersionInfoCompanyName',
        'OriginalFileName': 'ProcessVersionInfoOriginalFileName',
        'CommandLine': 'ProcessCommandLine',
        # CurrentDirectory: ?
        'User': 'AccountName',
        # LogonGuid: ?
        'LogonId': 'LogonId',
        # TerminalSessionId: ?
        'IntegrityLevel': 'ProcessIntegrityLevel',
        'sha1': 'SHA1',
        'sha256': 'SHA256',
        'md5': 'MD5',
        # 'ParentProcessGuid': ?,
        'ParentProcessId': 'InitiatingProcessId',
        'ParentImage': 'InitiatingProcessFolderPath',
        'ParentCommandLine': 'InitiatingProcessCommandLine',
        'ParentUser': 'InitiatingProcessAccountName',
    },
    'DeviceImageLoadEvents': {
        # 'ProcessGuid': ?,
        'ProcessId': 'InitiatingProcessId',
        'Image': 'InitiatingProcessFolderPath',  # File path of the process that loaded the image
        'CommandLine': 'InitiatingProcessCommandLine',
        'ImageLoaded': 'FolderPath',
        'FileVersion': 'InitiatingProcessVersionInfoProductVersion',
        'Description': 'InitiatingProcessVersionInfoFileDescription',
        'Product': 'InitiatingProcessVersionInfoProductName',
        'Company': 'InitiatingProcessVersionInfoCompanyName',
        'OriginalFileName': 'InitiatingProcessVersionInfoOriginalFileName',
        # 'Hashes': ?,
        'sha1': 'SHA1',
        'sha256': 'SHA256',
        'md5': 'MD5',
        # 'Signed': ?
        # 'Signature': ?
        # 'SignatureStatus': ?
        'User': 'InitiatingProcessAccountName'
    },
    'DeviceFileEvents': {  # file_*, Sysmon EventID 11 (create), 23 (delete) -> DeviceFileEvents table
        # 'ProcessGuid': ?,
        'ProcessId': 'InitiatingProcessId',
        'Image': 'InitiatingProcessFolderPath',
        'CommandLine': 'InitiatingProcessCommandLine',
        'TargetFilename': 'FolderPath',
        # 'CreationUtcTime': 'Timestamp',
        'User': 'RequestAccountName',
        # 'Hashes': ?,
        'sha1': 'SHA1',
        'sha256': 'SHA256',
        'md5': 'MD5',
    },
    'DeviceNetworkEvents': {  # network_connection, Sysmon EventID 3 -> DeviceNetworkEvents table
        # 'ProcessGuid': ?,
        'ProcessId': 'InitiatingProcessId',
        'Image': 'InitiatingProcessFolderPath',
        'CommandLine': 'InitiatingProcessCommandLine',
        'User': 'InitiatingProcessAccountName',
        'Protocol': 'Protocol',
        # 'Initiated': ?,
        # 'SourceIsIpv6': ?,
        'SourceIp': 'LocalIP',
        'SourceHostname': 'DeviceName',
        'SourcePort': 'LocalPort',
        # 'SourcePortName': ?,
        # 'DestinationIsIpv6': ?,
        'DestinationIp': 'RemoteIP',
        'DestinationHostname': 'RemoteUrl',
        'DestinationPort': 'RemotePort',
        # 'DestinationPortName': ?,
    },
    "DeviceRegistryEvents": {
        # registry_*, Sysmon EventID 12 (create/delete), 13 (value set), 14 (key/value rename) -> DeviceRegistryEvents table,
        'EventType': 'ActionType',
        # 'ProcessGuid': ?,
        'ProcessId': 'InitiatingProcessId',
        'Image': 'InitiatingProcessFolderPath',
        'CommandLine': 'InitiatingProcessCommandLine',
        'TargetObject': 'RegistryKey',
        # 'NewName': ?
        'Details': 'RegistryValueData',
        'User': 'InitiatingProcessAccountName'
    }
}

## Generic catch-all field mappings for sysmon -> microsoft 365 defender fields that appear in most tables and
## haven't been mapped already
generic_field_mappings = {
    'EventType': 'ActionType',
    'User': 'InitiatingProcessAccountName',
    'CommandLine': 'InitiatingProcessCommandLine',
    'Image': 'InitiatingProcessFolderPath',
    'SourceImage': 'InitiatingProcessFolderPath',
    'ProcessId': 'InitiatingProcessId',
    'md5': 'InitiatingProcessMD5',
    'sha1': 'InitiatingProcessSHA1',
    'sha256': 'InitiatingProcessSHA256',
    'ParentProcessId': 'InitiatingProcessParentId',
    'ParentCommandLine': 'InitiatingProcessParentCommandLine',
    'Company': 'InitiatingProcessVersionInfoCompanyName',
    'Description': 'InitiatingProcessVersionInfoFileDescription',
    'OriginalFileName': 'InitiatingProcessVersionInfoOriginalFileName',
    'Product': 'InitiatingProcessVersionInfoProductName'
}

# VALID FIELDS PER QUERY TABLE
## Will Implement field checking later once issue with removing fields is figured out, for now it fails the pipeline
## dict of {'table_name': [list, of, valid_fields]} for each table
valid_fields_per_table = {
    'DeviceProcessEvents': ['Timestamp', 'DeviceId', 'DeviceName', 'ActionType', 'FileName', 'FolderPath', 'SHA1',
                            'SHA256', 'MD5', 'FileSize', 'ProcessVersionInfoCompanyName',
                            'ProcessVersionInfoProductName', 'ProcessVersionInfoProductVersion',
                            'ProcessVersionInfoInternalFileName', 'ProcessVersionInfoOriginalFileName',
                            'ProcessVersionInfoFileDescription', 'ProcessId', 'ProcessCommandLine',
                            'ProcessIntegrityLevel', 'ProcessTokenElevation', 'ProcessCreationTime', 'AccountDomain',
                            'AccountName', 'AccountSid', 'AccountUpn', 'AccountObjectId', 'LogonId',
                            'InitiatingProcessAccountDomain', 'InitiatingProcessAccountName',
                            'InitiatingProcessAccountSid', 'InitiatingProcessAccountUpn',
                            'InitiatingProcessAccountObjectId', 'InitiatingProcessLogonId',
                            'InitiatingProcessIntegrityLevel', 'InitiatingProcessTokenElevation',
                            'InitiatingProcessSHA1', 'InitiatingProcessSHA256', 'InitiatingProcessMD5',
                            'InitiatingProcessFileName', 'InitiatingProcessFileSize',
                            'InitiatingProcessVersionInfoCompanyName', 'InitiatingProcessVersionInfoProductName',
                            'InitiatingProcessVersionInfoProductVersion',
                            'InitiatingProcessVersionInfoInternalFileName',
                            'InitiatingProcessVersionInfoOriginalFileName',
                            'InitiatingProcessVersionInfoFileDescription', 'InitiatingProcessId',
                            'InitiatingProcessCommandLine', 'InitiatingProcessCreationTime',
                            'InitiatingProcessFolderPath', 'InitiatingProcessParentId',
                            'InitiatingProcessParentFileName', 'InitiatingProcessParentCreationTime',
                            'InitiatingProcessSignerType', 'InitiatingProcessSignatureStatus', 'ReportId',
                            'AppGuardContainerId', 'AdditionalFields'],
    'DeviceImageLoadEvents': ['Timestamp', 'DeviceId', 'DeviceName', 'ActionType', 'FileName', 'FolderPath', 'SHA1',
                              'SHA256', 'MD5', 'FileSize', 'InitiatingProcessAccountDomain',
                              'InitiatingProcessAccountName', 'InitiatingProcessAccountSid',
                              'InitiatingProcessAccountUpn', 'InitiatingProcessAccountObjectId',
                              'InitiatingProcessIntegrityLevel', 'InitiatingProcessTokenElevation',
                              'InitiatingProcessSHA1', 'InitiatingProcessSHA256', 'InitiatingProcessMD5',
                              'InitiatingProcessFileName', 'InitiatingProcessFileSize',
                              'InitiatingProcessVersionInfoCompanyName', 'InitiatingProcessVersionInfoProductName',
                              'InitiatingProcessVersionInfoProductVersion',
                              'InitiatingProcessVersionInfoInternalFileName',
                              'InitiatingProcessVersionInfoOriginalFileName',
                              'InitiatingProcessVersionInfoFileDescription', 'InitiatingProcessId',
                              'InitiatingProcessCommandLine', 'InitiatingProcessCreationTime',
                              'InitiatingProcessFolderPath', 'InitiatingProcessParentId',
                              'InitiatingProcessParentFileName', 'InitiatingProcessParentCreationTime', 'ReportId',
                              'AppGuardContainerId'],
    'DeviceFileEvents': ['Timestamp', 'DeviceId', 'DeviceName', 'ActionType', 'FileName', 'FolderPath', 'SHA1',
                         'SHA256', 'MD5', 'FileOriginUrl', 'FileOriginReferrerUrl', 'FileOriginIP',
                         'PreviousFolderPath', 'PreviousFileName', 'FileSize', 'InitiatingProcessAccountDomain',
                         'InitiatingProcessAccountName', 'InitiatingProcessAccountSid', 'InitiatingProcessAccountUpn',
                         'InitiatingProcessAccountObjectId', 'InitiatingProcessMD5', 'InitiatingProcessSHA1',
                         'InitiatingProcessSHA256', 'InitiatingProcessFolderPath', 'InitiatingProcessFileName',
                         'InitiatingProcessFileSize', 'InitiatingProcessVersionInfoCompanyName',
                         'InitiatingProcessVersionInfoProductName', 'InitiatingProcessVersionInfoProductVersion',
                         'InitiatingProcessVersionInfoInternalFileName', 'InitiatingProcessVersionInfoOriginalFileName',
                         'InitiatingProcessVersionInfoFileDescription', 'InitiatingProcessId',
                         'InitiatingProcessCommandLine', 'InitiatingProcessCreationTime',
                         'InitiatingProcessIntegrityLevel', 'InitiatingProcessTokenElevation',
                         'InitiatingProcessParentId', 'InitiatingProcessParentFileName',
                         'InitiatingProcessParentCreationTime', 'RequestProtocol', 'RequestSourceIP',
                         'RequestSourcePort', 'RequestAccountName', 'RequestAccountDomain', 'RequestAccountSid',
                         'ShareName', 'InitiatingProcessFileSize', 'SensitivityLabel', 'SensitivitySubLabel',
                         'IsAzureInfoProtectionApplied', 'ReportId', 'AppGuardContainerId', 'AdditionalFields'],
    'DeviceRegistryEvents': ['Timestamp', 'DeviceId', 'DeviceName', 'ActionType', 'RegistryKey', 'RegistryValueType',
                             'RegistryValueName', 'RegistryValueData', 'PreviousRegistryKey',
                             'PreviousRegistryValueName', 'PreviousRegistryValueData', 'InitiatingProcessAccountDomain',
                             'InitiatingProcessAccountName', 'InitiatingProcessAccountSid',
                             'InitiatingProcessAccountUpn', 'InitiatingProcessAccountObjectId', 'InitiatingProcessSHA1',
                             'InitiatingProcessSHA256', 'InitiatingProcessMD5', 'InitiatingProcessFileName',
                             'InitiatingProcessFileSize', 'InitiatingProcessVersionInfoCompanyName',
                             'InitiatingProcessVersionInfoProductName', 'InitiatingProcessVersionInfoProductVersion',
                             'InitiatingProcessVersionInfoInternalFileName',
                             'InitiatingProcessVersionInfoOriginalFileName',
                             'InitiatingProcessVersionInfoFileDescription', 'InitiatingProcessId',
                             'InitiatingProcessCommandLine', 'InitiatingProcessCreationTime',
                             'InitiatingProcessFolderPath', 'InitiatingProcessParentId',
                             'InitiatingProcessParentFileName', 'InitiatingProcessParentCreationTime',
                             'InitiatingProcessIntegrityLevel', 'InitiatingProcessTokenElevation', 'ReportId',
                             'AppGuardContainerId'],
    'DeviceNetworkEvents': ['Timestamp', 'DeviceId', 'DeviceName', 'ActionType', 'RemoteIP', 'RemotePort', 'RemoteUrl',
                            'LocalIP', 'LocalPort', 'Protocol', 'LocalIPType', 'RemoteIPType', 'InitiatingProcessSHA1',
                            'InitiatingProcessSHA256', 'InitiatingProcessMD5', 'InitiatingProcessFileName',
                            'InitiatingProcessFileSize', 'InitiatingProcessVersionInfoCompanyName',
                            'InitiatingProcessVersionInfoProductName', 'InitiatingProcessVersionInfoProductVersion',
                            'InitiatingProcessVersionInfoInternalFileName',
                            'InitiatingProcessVersionInfoOriginalFileName',
                            'InitiatingProcessVersionInfoFileDescription', 'InitiatingProcessId',
                            'InitiatingProcessCommandLine', 'InitiatingProcessCreationTime',
                            'InitiatingProcessFolderPath', 'InitiatingProcessParentFileName',
                            'InitiatingProcessParentId', 'InitiatingProcessParentCreationTime',
                            'InitiatingProcessAccountDomain', 'InitiatingProcessAccountName',
                            'InitiatingProcessAccountSid', 'InitiatingProcessAccountUpn',
                            'InitiatingProcessAccountObjectId', 'InitiatingProcessIntegrityLevel',
                            'InitiatingProcessTokenElevation', 'ReportId', 'AppGuardContainerId', 'AdditionalFields']}

# OTHER MAPPINGS
## useful for creating ProcessingItems() with list comprehension

## Query Table names -> rule categories
table_to_category_mappings = {
    'DeviceProcessEvents': ['process_creation'],
    'DeviceImageLoadEvents': ['image_load'],
    'DeviceFileEvents': ['file_access', 'file_change', 'file_delete', 'file_event', 'file_rename'],
    'DeviceRegistryEvents': ['registry_add', 'registry_delete', 'registry_event', 'registry_set'],
    'DeviceNetworkEvents': ['network_connection']
}

## rule categories -> RuleConditions
category_to_conditions_mappings = {
    'process_creation': logsource_windows_process_creation(),
    'image_load': logsource_windows_image_load(),
    'file_access': logsource_windows_file_access(),
    'file_change': logsource_windows_file_change(),
    'file_delete': logsource_windows_file_delete(),
    'file_event': logsource_windows_file_event(),
    'file_rename': logsource_windows_file_rename(),
    'registry_add': logsource_windows_registry_add(),
    'registry_delete': logsource_windows_registry_delete(),
    'registry_event': logsource_windows_registry_event(),
    'registry_set': logsource_windows_registry_set(),
    'network_connection': logsource_windows_network_connection()
}

# PROCESSING_ITEMS()
## ProcessingItems to set state key 'query_table' to use in backend
## i.e. $QueryTable$ | $rest_of_query$
query_table_proc_items = [
    ProcessingItem(
        identifier=f"microsoft_365_defender_set_query_table_{table_name}",
        transformation=SetStateTransformation("query_table", table_name),
        rule_conditions=[
            category_to_conditions_mappings[rule_category] for rule_category in rule_categories
        ],
        rule_condition_linking=any,
    )
    for table_name, rule_categories in table_to_category_mappings.items()
]

## Fieldmappings
fieldmappings_proc_items = [
    ProcessingItem(
        identifier=f"microsoft_365_defender_fieldmappings_{table_name}",
        transformation=FieldMappingTransformation(query_table_field_mappings[table_name]),
        rule_conditions=[
            category_to_conditions_mappings[rule_category] for rule_category in rule_categories
        ],
        rule_condition_linking=any,
    )
    for table_name, rule_categories in table_to_category_mappings.items()
]

## Generic Fielp Mappings, keep this last
## Exclude any fields already mapped. For example, if process_creation events ProcessId has already
## been mapped to the same field name (ProcessId), we don't to remap it to InitiatingProcessId
generic_field_mappings_proc_item = [ProcessingItem(
    identifier="microsoft_365_defender_fieldmappings_generic",
    transformation=FieldMappingTransformation(
        generic_field_mappings
    ),
    rule_conditions=[
        RuleProcessingItemAppliedCondition(f"microsoft_365_defender_fieldmappings_{table_name}")
        for table_name in table_to_category_mappings.keys()
    ],
    rule_condition_linking=any,
    rule_condition_negation=True,
)
]
## Field Value Replacements ProcessingItems
replacement_proc_items = [
    # Sysmon uses abbreviations in RegistryKey values, replace with full key names as the DeviceRegistryEvents schema
    # expects them to be
    # Note: Ensure this comes AFTER field mapping renames, as we're specifying DeviceRegistryEvent fields
    #
    # Do this one first, or else the HKLM only one will replace HKLM and mess up the regex
    ProcessingItem(
        identifier="microsoft_365_defender_registry_key_replace_currentcontrolset",
        transformation=ReplaceStringTransformation(regex=r"((?i)^HKLM\\SYSTEM\\CurrentControlSet)",
                                                   replacement=r"HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet001"),
        field_name_conditions=[IncludeFieldCondition(['RegistryKey', 'PreviousRegistryKey'])]
    ),
    ProcessingItem(
        identifier="microsoft_365_defender_registry_key_replace_hklm",
        transformation=ReplaceStringTransformation(regex=r"((?i)^HKLM)",
                                                   replacement=r"HKEY_LOCAL_MACHINE"),
        field_name_conditions=[IncludeFieldCondition(['RegistryKey', 'PreviousRegistryKey'])]
    ),
    ProcessingItem(
        identifier="microsoft_365_defender_registry_key_replace_hku",
        transformation=ReplaceStringTransformation(regex=r"((?i)^HKU)",
                                                   replacement=r"HKEY_USERS"),
        field_name_conditions=[IncludeFieldCondition(['RegistryKey', 'PreviousRegistryKey'])]
    ),
    ProcessingItem(
        identifier="microsoft_365_defender_registry_key_replace_hkcr",
        transformation=ReplaceStringTransformation(regex=r"((?i)^HKCR)",
                                                   replacement=r"HKEY_LOCAL_MACHINE\\CLASSES"),
        field_name_conditions=[IncludeFieldCondition(['RegistryKey', 'PreviousRegistryKey'])]
    ),
    ProcessingItem(
        identifier="microsoft_365_defender_registry_actiontype_value",
        transformation=RegistryActionTypeValueTransformation(),
        field_name_conditions=[IncludeFieldCondition(['ActionType'])]
    ),
    # Extract Domain from Username fields
    ProcessingItem(
        identifier="microsoft_365_defender_domain_username_extract",
        transformation=SplitDomainUserTransformation(),
        field_name_conditions=[IncludeFieldCondition(["AccountName", "InitiatingProcessAccountName"])]
    ),
    ProcessingItem(
        identifier="microsoft_365_defender_hashes_field_values",
        transformation=HashesValuesTransformation(),
        field_name_conditions=[IncludeFieldCondition(['Hashes'])]
    ),
]

## Exceptions/Errors ProcessingItems
rule_error_proc_items = [
    # Category Not Supported
    ProcessingItem(
        identifier="microsoft_365_defender_unsupported_rule_category",
        rule_condition_linking=any,
        transformation=RuleFailureTransformation(
            "Rule category not yet supported by the Microsoft 365 Defender Sigma backend."
        ),
        rule_condition_negation=True,
        rule_conditions=[x for x in category_to_conditions_mappings.values()],
    )]

field_error_proc_items = [
    # Invalid fields per category
    ProcessingItem(
        identifier=f"microsoft_365_defender_unsupported_fields_{table_name}",
        transformation=InvalidFieldTransformation(
            f"Please use valid fields for the {table_name} table, or the following fields that have keymappings in this "
            f"pipeline:\n"
            # Combine field mappings for table and generic field mappings dicts, get the unique keys, add the Hashes field, sort it
            f"{', '.join(sorted(set({**query_table_field_mappings[table_name], **generic_field_mappings}.keys()).union({'Hashes'})))}"
        ),
        field_name_conditions=[ExcludeFieldCondition(fields=table_fields)],
        rule_conditions=[
            category_to_conditions_mappings[rule_category]
            for rule_category in table_to_category_mappings[table_name]
        ],
        rule_condition_linking=any,
    )
    for table_name, table_fields in valid_fields_per_table.items()
]


def microsoft_365_defender_pipeline() -> ProcessingPipeline:
    """Pipeline for transformations for SigmaRules to use in the Microsoft 365 Defender Backend
    Field mappings based on documentation found here:
    https://learn.microsoft.com/en-us/microsoft-365/security/defender/advanced-hunting-query-language?view=o365-worldwide
    :return: ProcessingPipeline for Microsoft 365 Defender Backend
    :rtype: ProcessingPipeline
    """
    return ProcessingPipeline(
        name="Generic Log Sources to Windows 365 Defender Transformation",
        priority=10,
        items=[*query_table_proc_items,
               *fieldmappings_proc_items,
               *generic_field_mappings_proc_item,
               *replacement_proc_items,
               *rule_error_proc_items,
               *field_error_proc_items,
               ]
    )
