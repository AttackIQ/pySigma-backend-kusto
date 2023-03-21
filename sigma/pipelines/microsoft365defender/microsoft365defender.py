from typing import Union, Optional, Iterable

from sigma.pipelines.common import logsource_windows_process_creation, \
    logsource_windows_image_load, logsource_windows_file_event, logsource_windows_file_delete, \
    logsource_windows_file_change, logsource_windows_file_access, logsource_windows_file_rename, \
    logsource_windows_registry_set, logsource_windows_registry_add, logsource_windows_registry_delete, \
    logsource_windows_registry_event, logsource_windows_network_connection
from sigma.processing.transformations import FieldMappingTransformation, \
    RuleFailureTransformation, ReplaceStringTransformation, SetStateTransformation, DetectionItemTransformation, \
    ValueTransformation
from sigma.processing.conditions import IncludeFieldCondition, \
    RuleProcessingItemAppliedCondition
from sigma.conditions import ConditionOR
from sigma.types import SigmaString, SigmaType
from sigma.processing.pipeline import ProcessingItem, ProcessingPipeline
from sigma.rule import SigmaDetectionItem, SigmaDetection
from collections import defaultdict


# Custom DetectionItemTransformation to split domain and user, if applicable
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


# Custom DetectionItemTransformation to regex hash algos/values in Hashes field, if applicable
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


# Field mappings from Sysmon (where applicable) fields to Advanced Hunting Query fields based on schema in tables
# See: https://learn.microsoft.com/en-us/microsoft-365/security/defender/advanced-hunting-schema-tables?view=o365-worldwide#learn-the-schema-tables


# Consolidate similar event types
def logsource_windows_file_all():
    """All logsource_windows_file_* events from common.py"""
    return [
        logsource_windows_file_access(),
        logsource_windows_file_change(),
        logsource_windows_file_delete(),
        logsource_windows_file_event(),
        logsource_windows_file_rename(),
    ]


def logsource_windows_registry_all():
    """All logsource_windows_registry_* events from common.py"""
    return [
        logsource_windows_registry_add(),
        logsource_windows_registry_delete(),
        logsource_windows_registry_event(),
        logsource_windows_registry_set(),
    ]


## FIELD MAPPINGS

device_process_events_field_mappings = {  # process_creation, Sysmon EventID 1 -> DeviceProcessEvents table
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
}

# Note for network_connection. The DeviceNetworkEvents table uses LocalIP and RemoteIP rather than
# SourceIP and DestiniationIP. Why? Idk, but we're going to have to assume that the LocalIP is the SourceIP.
# We may have to add another custom ProcessingItem to add an 'OR' for DestinationIP->LocalIP and SourceIP->RemoteIP
# as well as the Source/Dest Hostnames and ports
device_network_events_field_mappings = {  # network_connection, Sysmon EventID 3 -> DeviceNetworkEvents table
    # 'ProcessGuid': ?,
    'ProcessId': 'InitiatingProcessId',
    'Image': 'InitiatingProcessFolderPath',
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
}

device_image_load_events_field_mapping = {  # image_load, Sysmon EventID 7 -> DeviceImageLoadEvents tabl;e
    # 'ProcessGuid': ?,
    'ProcessId': 'InitiatingProcessId',
    'Image': 'InitiatingProcessFolderPath',  # File path of the process that loaded the image
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
}

device_file_events_field_mappings = {  # file_*, Sysmon EventID 11 (create), 23 (delete) -> DeviceFileEvents table
    # 'ProcessGuid': ?,
    'ProcessId': 'InitiatingProcessId',
    'Image': 'InitiatingProcessFolderPath',
    'TargetFilename': 'FolderPath',
    # 'CreationUtcTime': 'Timestamp',
    'User': 'RequestAccountName',
    # 'Hashes': ?,
    'sha1': 'SHA1',
    'sha256': 'SHA256',
    'md5': 'MD5',
}

device_registry_events_field_mappings = {
    # registry_*, Sysmon EventID 12 (create/delete), 13 (value set), 14 (key/value rename) -> DeviceRegistryEvents table,
    'EventType': 'ActionType',
    # 'ProcessGuid': ?,
    'ProcessId': 'InitiatingProcessId',
    'Image': 'InitiatingProcessFolderPath',
    'TargetObject': 'RegistryKey',
    # 'NewName': ?
    'Details': 'RegistryValueData',
    'User': 'InitiatingProcessAccountName'
}

# Generic catch-all field mappings for sysmon -> microsoft 365 defender fields that appear in most tables and
# haven't been mapped already
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

#### VALID FIELDS PER TABLE ####
# Will Implement field checking later once issue with removing fields is figured out
# dict of {'table_name': [list, of, valid_fields]} for each table
valid_fields_per_table = {
    'DeviceProcessEvents': ['Timestamp', 'DeviceId', 'DeviceName', 'ActionType', 'FileName', 'FolderPath', 'SHA1',
                            'SHA256', 'MD5', 'FileOriginUrl', 'FileOriginReferrerUrl', 'FileOriginIP',
                            'PreviousFolderPath', 'PreviousFileName', 'FileSize', 'InitiatingProcessAccountDomain',
                            'InitiatingProcessAccountName', 'InitiatingProcessAccountSid',
                            'InitiatingProcessAccountUpn',
                            'InitiatingProcessAccountObjectId', 'InitiatingProcessMD5', 'InitiatingProcessSHA1',
                            'InitiatingProcessSHA256', 'InitiatingProcessFolderPath', 'InitiatingProcessFileName',
                            'InitiatingProcessFileSize', 'InitiatingProcessVersionInfoCompanyName',
                            'InitiatingProcessVersionInfoProductName', 'InitiatingProcessVersionInfoProductVersion',
                            'InitiatingProcessVersionInfoInternalFileName',
                            'InitiatingProcessVersionInfoOriginalFileName',
                            'InitiatingProcessVersionInfoFileDescription', 'InitiatingProcessId',
                            'InitiatingProcessCommandLine', 'InitiatingProcessCreationTime',
                            'InitiatingProcessIntegrityLevel', 'InitiatingProcessTokenElevation',
                            'InitiatingProcessParentId', 'InitiatingProcessParentFileName',
                            'InitiatingProcessParentCreationTime', 'RequestProtocol', 'RequestSourceIP',
                            'RequestSourcePort', 'RequestAccountName', 'RequestAccountDomain', 'RequestAccountSid',
                            'ShareName', 'InitiatingProcessFileSize', 'SensitivityLabel', 'SensitivitySubLabel',
                            'IsAzureInfoProtectionApplied', 'ReportId', 'AppGuardContainerId', 'AdditionalFields'],
    'DeviceImageLoadEvents': ['Timestamp', 'DeviceId', 'DeviceName', 'ActionType', 'FileName', 'FolderPath', 'SHA1',
                              'SHA256', 'MD5', 'FileSize', 'InitiatingProcessAccountDomain',
                              'InitiatingProcessAccountName', 'InitiatingProcessAccountSid',
                              'InitiatingProcessAccountUpn',
                              'InitiatingProcessAccountObjectId', 'InitiatingProcessIntegrityLevel',
                              'InitiatingProcessTokenElevation', 'InitiatingProcessSHA1', 'InitiatingProcessSHA256',
                              'InitiatingProcessMD5', 'InitiatingProcessFileName', 'InitiatingProcessFileSize',
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
                         'SHA256',
                         'MD5', 'FileOriginUrl', 'FileOriginReferrerUrl', 'FileOriginIP', 'PreviousFolderPath',
                         'PreviousFileName', 'FileSize', 'InitiatingProcessAccountDomain',
                         'InitiatingProcessAccountName',
                         'InitiatingProcessAccountSid', 'InitiatingProcessAccountUpn',
                         'InitiatingProcessAccountObjectId',
                         'InitiatingProcessMD5', 'InitiatingProcessSHA1', 'InitiatingProcessSHA256',
                         'InitiatingProcessFolderPath', 'InitiatingProcessFileName', 'InitiatingProcessFileSize',
                         'InitiatingProcessVersionInfoCompanyName', 'InitiatingProcessVersionInfoProductName',
                         'InitiatingProcessVersionInfoProductVersion', 'InitiatingProcessVersionInfoInternalFileName',
                         'InitiatingProcessVersionInfoOriginalFileName', 'InitiatingProcessVersionInfoFileDescription',
                         'InitiatingProcessId', 'InitiatingProcessCommandLine', 'InitiatingProcessCreationTime',
                         'InitiatingProcessIntegrityLevel', 'InitiatingProcessTokenElevation',
                         'InitiatingProcessParentId',
                         'InitiatingProcessParentFileName', 'InitiatingProcessParentCreationTime', 'RequestProtocol',
                         'RequestSourceIP', 'RequestSourcePort', 'RequestAccountName', 'RequestAccountDomain',
                         'RequestAccountSid', 'ShareName', 'InitiatingProcessFileSize', 'SensitivityLabel',
                         'SensitivitySubLabel', 'IsAzureInfoProtectionApplied', 'ReportId', 'AppGuardContainerId',
                         'AdditionalFields'],
    'DeviceRegistryEvents': ['Timestamp', 'DeviceId', 'DeviceName', 'ActionType', 'RegistryKey', 'RegistryValueType',
                             'RegistryValueName', 'RegistryValueData', 'PreviousRegistryKey',
                             'PreviousRegistryValueName',
                             'PreviousRegistryValueData', 'InitiatingProcessAccountDomain',
                             'InitiatingProcessAccountName',
                             'InitiatingProcessAccountSid', 'InitiatingProcessAccountUpn',
                             'InitiatingProcessAccountObjectId', 'InitiatingProcessSHA1', 'InitiatingProcessSHA256',
                             'InitiatingProcessMD5', 'InitiatingProcessFileName', 'InitiatingProcessFileSize',
                             'InitiatingProcessVersionInfoCompanyName', 'InitiatingProcessVersionInfoProductName',
                             'InitiatingProcessVersionInfoProductVersion',
                             'InitiatingProcessVersionInfoInternalFileName',
                             'InitiatingProcessVersionInfoOriginalFileName',
                             'InitiatingProcessVersionInfoFileDescription',
                             'InitiatingProcessId', 'InitiatingProcessCommandLine', 'InitiatingProcessCreationTime',
                             'InitiatingProcessFolderPath', 'InitiatingProcessParentId',
                             'InitiatingProcessParentFileName',
                             'InitiatingProcessParentCreationTime', 'InitiatingProcessIntegrityLevel',
                             'InitiatingProcessTokenElevation', 'ReportId', 'AppGuardContainerId'],
    'DeviceNetworkEvents': ['Timestamp', 'DeviceId', 'DeviceName', 'ActionType', 'RemoteIP', 'RemotePort', 'RemoteUrl',
                            'LocalIP', 'LocalPort', 'Protocol', 'LocalIPType', 'RemoteIPType', 'InitiatingProcessSHA1',
                            'InitiatingProcessSHA256', 'InitiatingProcessMD5', 'InitiatingProcessFileName',
                            'InitiatingProcessFileSize', 'InitiatingProcessVersionInfoCompanyName',
                            'InitiatingProcessVersionInfoProductName', 'InitiatingProcessVersionInfoProductVersion',
                            'InitiatingProcessVersionInfoInternalFileName',
                            'InitiatingProcessVersionInfoOriginalFileName',
                            'InitiatingProcessVersionInfoFileDescription', 'InitiatingProcessId',
                            'InitiatingProcessCommandLine', 'InitiatingProcessCreationTime',
                            'InitiatingProcessFolderPath',
                            'InitiatingProcessParentFileName', 'InitiatingProcessParentId',
                            'InitiatingProcessParentCreationTime', 'InitiatingProcessAccountDomain',
                            'InitiatingProcessAccountName', 'InitiatingProcessAccountSid',
                            'InitiatingProcessAccountUpn',
                            'InitiatingProcessAccountObjectId', 'InitiatingProcessIntegrityLevel',
                            'InitiatingProcessTokenElevation', 'ReportId', 'AppGuardContainerId', 'AdditionalFields']}

##### PROCESSING ITEMS #####
# Group similar ProcessingItem's here for readability

# ProcessingItems to set state key 'query_table' to use in backend
# i.e. $QueryTable$ | $rest_of_query$
query_table_items_proc_items = [
    ProcessingItem(
        identifier="microsoft_365_defender_set_process_creation_table",
        transformation=SetStateTransformation("query_table", "DeviceProcessEvents"),
        rule_conditions=[
            logsource_windows_process_creation()
        ],
    ),
    ProcessingItem(
        identifier="microsoft_365_defender_set_image_load_table",
        transformation=SetStateTransformation("query_table", "DeviceImageLoadEvents"),
        rule_conditions=[
            logsource_windows_image_load()
        ],
    ),
    ProcessingItem(
        identifier="microsoft_365_defender_set_registry_events_table",
        transformation=SetStateTransformation("query_table", "DeviceRegistryEvents"),
        rule_conditions=logsource_windows_registry_all(),
        rule_condition_linking=any,
    ),
    ProcessingItem(
        identifier="microsoft_365_defender_set_file_events_table",
        transformation=SetStateTransformation("query_table", "DeviceFileEvents"),
        rule_conditions=logsource_windows_file_all(),
        rule_condition_linking=any,
    ),
    ProcessingItem(
        identifier="microsoft_365_defender_set_network_connection_table",
        transformation=SetStateTransformation("query_table", "DeviceNetworkEvents"),
        rule_conditions=[
            logsource_windows_network_connection()
        ],
    ),
]

# Keymapping Processing Items
keymapping_proc_items = [
    # Process Creation Events
    ProcessingItem(
        identifier="microsoft_365_defender_process_creation_fieldmapping",
        transformation=FieldMappingTransformation(
            device_process_events_field_mappings
        ),
        rule_conditions=[
            logsource_windows_process_creation()
        ]
    ),

    # Image Load Events
    ProcessingItem(
        identifier="microsoft_365_defender_image_load_fieldmapping",
        transformation=FieldMappingTransformation(
            device_image_load_events_field_mapping
        ),
        rule_conditions=[
            logsource_windows_image_load()
        ]
    ),

    # File Events
    ProcessingItem(
        identifier="microsoft_365_defender_file_events_fieldmapping",
        transformation=FieldMappingTransformation(
            device_file_events_field_mappings
        ),
        rule_conditions=logsource_windows_file_all(),
        rule_condition_linking=any
    ),

    # Registry Events
    ProcessingItem(
        identifier="microsoft_365_defender_registry_events_fieldmapping",
        transformation=FieldMappingTransformation(
            device_registry_events_field_mappings
        ),
        rule_conditions=logsource_windows_registry_all(),
        rule_condition_linking=any
    ),
    # Network Events
    ProcessingItem(
        identifier="microsoft_365_defender_network_connection_fieldmapping",
        transformation=FieldMappingTransformation(
            device_network_events_field_mappings
        ),
        rule_conditions=[
            logsource_windows_network_connection(),
        ],
    ),
    # Generic Fielp Mappings, keep this last
    # Exclude any fields already mapped. For example, if process_creation events ProcessId has already
    # been mapped to the same field name (ProcessId), we don't to remap it to InitiatingProcessId
    ProcessingItem(
        identifier="microsoft_365_defender_generic_fieldmapping",
        transformation=FieldMappingTransformation(
            generic_field_mappings
        ),
        rule_conditions=[
            RuleProcessingItemAppliedCondition("microsoft_365_defender_process_creation_fieldmapping"),
            RuleProcessingItemAppliedCondition("microsoft_365_defender_image_load_fieldmapping"),
            RuleProcessingItemAppliedCondition("microsoft_365_defender_file_events_fieldmapping"),
            RuleProcessingItemAppliedCondition("microsoft_365_defender_registry_events_fieldmapping"),
            RuleProcessingItemAppliedCondition("microsoft_365_defender_network_connection_fieldmapping")
        ],
        rule_condition_linking=any,
        rule_condition_negation=True,
    )
]

# Field Value Replacements ProcessingItems
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

# Exceptions/Errors ProcessingItems
exception_error_proc_items = [
    ProcessingItem(
        identifier="microsoft_365_defender_unsupported_rule_category",
        rule_condition_linking=any,
        transformation=RuleFailureTransformation(
            "Rule category not yet supported by the Microsoft 365 Defender Sigma backend."
        ),
        rule_condition_negation=True,
        rule_conditions=[
                            logsource_windows_process_creation(),
                            logsource_windows_image_load(),
                            logsource_windows_network_connection(),
                        ] + logsource_windows_file_all() + logsource_windows_registry_all(),
    ),
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
        items=[*query_table_items_proc_items,
               *keymapping_proc_items,
               *replacement_proc_items,
               *exception_error_proc_items,
               ]
    )
