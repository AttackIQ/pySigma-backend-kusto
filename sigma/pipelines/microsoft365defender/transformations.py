from collections import defaultdict
from dataclasses import dataclass
from typing import Any, Iterable, Optional, Union

from sigma.conditions import ConditionOR
from sigma.processing.transformations import (
    DetectionItemTransformation,
    FieldMappingTransformation,
    Transformation,
    ValueTransformation,
)
from sigma.rule import SigmaDetection, SigmaDetectionItem, SigmaString
from sigma.types import SigmaType

from .errors import InvalidHashAlgorithmError
from .mappings import CATEGORY_TO_TABLE_MAPPINGS


## Custom DetectionItemTransformation to split domain and user, if applicable
class SplitDomainUserTransformation(DetectionItemTransformation):
    """Custom DetectionItemTransformation transformation to split a User field into separate domain and user fields,
    if applicable.  This is to handle the case where the Sysmon `User` field may contain a domain AND username, and
    Advanced Hunting queries separate out the domain and username into separate fields.
    If a matching field_name_condition field uses the schema DOMAIN\\USER, a new SigmaDetectionItem
    will be made for the Domain and put inside a SigmaDetection with the original User SigmaDetectionItem
    (minus the domain) for the matching SigmaDetectionItem.

    You should use this with a field_name_condition for `IncludeFieldName(['field', 'names', 'for', 'username']`)"""

    def apply_detection_item(
        self, detection_item: SigmaDetectionItem
    ) -> Optional[Union[SigmaDetection, SigmaDetectionItem]]:
        to_return = []
        if not isinstance(detection_item.value, list):  # Ensure its a list, but it most likely will be
            detection_item.value = list(detection_item.value)
        for d in detection_item.value:
            username = d.to_plain().split("\\")
            username_field_mappings = {
                "AccountName": "AccountDomain",
                "RequestAccountName": "RequestAccountDomain",
                "InitiatingProcessAccountName": "InitiatingProcessAccountDomain",
            }
            if len(username) == 2:
                domain = username[0]
                username = [SigmaString(username[1])]

                domain_field = username_field_mappings.get(detection_item.field, "InitiatingProcessAccountDomain")
                domain_value = [SigmaString(domain)]
                user_detection_item = SigmaDetectionItem(
                    field=detection_item.field,
                    modifiers=[],
                    value=username,
                )
                domain_detection_item = SigmaDetectionItem(field=domain_field, modifiers=[], value=domain_value)
                to_return.append(SigmaDetection(detection_items=[user_detection_item, domain_detection_item]))
            else:

                to_return.append(
                    SigmaDetection(
                        [
                            SigmaDetectionItem(
                                field=detection_item.field, modifiers=detection_item.modifiers, value=username
                            )
                        ]
                    )
                )
        return SigmaDetection(to_return)


## Custom DetectionItemTransformation to regex hash algos/values in Hashes field, if applicable
class HashesValuesTransformation(DetectionItemTransformation):
    """Custom DetectionItemTransformation to take a list of values in the 'Hashes' field, which are expected to be
    'algo:hash_value', and create new SigmaDetectionItems for each hash type, where the values is a list of
    SigmaString hashes. If the hash type is not part of the value, it will be inferred based on length.

    Use with field_name_condition for Hashes field"""

    def apply_detection_item(
        self, detection_item: SigmaDetectionItem
    ) -> Optional[Union[SigmaDetection, SigmaDetectionItem]]:
        to_return = []
        no_valid_hash_algo = True
        algo_dict = defaultdict(list)  # map to keep track of algos and lists of values
        if not isinstance(detection_item.value, list):
            detection_item.value = [detection_item.value]
        for d in detection_item.value:
            hash_value = d.to_plain().split("|")  # sometimes if ALGO|VALUE
            if len(hash_value) == 1:  # and sometimes its ALGO=VALUE
                hash_value = hash_value[0].split("=")
            if len(hash_value) == 2:
                hash_algo = (
                    hash_value[0].lstrip("*").upper()
                    if hash_value[0].lstrip("*").upper() in ["MD5", "SHA1", "SHA256"]
                    else ""
                )
                if hash_algo:
                    no_valid_hash_algo = False
                hash_value = hash_value[1]
            else:
                hash_value = hash_value[0]
                if len(hash_value) == 32:  # MD5
                    hash_algo = "MD5"
                    no_valid_hash_algo = False
                elif len(hash_value) == 40:  # SHA1
                    hash_algo = "SHA1"
                    no_valid_hash_algo = False
                elif len(hash_value) == 64:  # SHA256
                    hash_algo = "SHA256"
                    no_valid_hash_algo = False
                else:  # Invalid algo, no fieldname for keyword search
                    hash_algo = ""
            algo_dict[hash_algo].append(hash_value)
        if no_valid_hash_algo:
            raise InvalidHashAlgorithmError(
                "No valid hash algo found in Hashes field.  Advanced Hunting Queries do not support the "
                "IMPHASH field. Ensure the detection item has at least one MD5, SHA1, or SHA265 hash field/value"
            )
        for k, v in algo_dict.items():
            if k:  # Filter out invalid hash algo types
                to_return.append(
                    SigmaDetectionItem(
                        field=k if k != "keyword" else None, modifiers=[], value=[SigmaString(x) for x in v]
                    )
                )
        return SigmaDetection(detection_items=to_return, item_linking=ConditionOR)


## Change ActionType value AFTER field transformations from Sysmon values to DeviceRegistryEvents values
class RegistryActionTypeValueTransformation(ValueTransformation):
    """Custom ValueTransformation transformation. The Microsoft DeviceRegistryEvents table expect the ActionType to
    be a slightly different set of values than what Sysmon specified, so this will change them to the correct value."""

    value_mappings = {  # Sysmon EventType -> DeviceRegistyEvents ActionType
        "CreateKey": "RegistryKeyCreated",
        "DeleteKey": ["RegistryKeyDeleted", "RegistryValueDeleted"],
        "SetValue": "RegistryValueSet",
        "RenameKey": ["RegistryValueSet", "RegistryKeyCreated"],
    }

    def apply_value(self, field: str, val: SigmaType) -> Optional[Union[SigmaType, Iterable[SigmaType]]]:
        mapped_vals = self.value_mappings.get(val.to_plain(), val.to_plain())
        if isinstance(mapped_vals, list):
            return [SigmaString(v) for v in mapped_vals]
        return SigmaString(mapped_vals)


# Extract parent process name from ParentImage after applying ParentImage field mapping
class ParentImageValueTransformation(ValueTransformation):
    """Custom ValueTransformation transformation.  Unfortunately, none of the table schemas have
    InitiatingProcessParentFolderPath like they do InitiatingProcessFolderPath. Due to this, we cannot directly map the
    Sysmon `ParentImage` field to a table field. However, InitiatingProcessParentFileName is an available field in
    nearly all tables, so we will extract the process name and use that instead.

    Use this transformation BEFORE mapping ParentImage to InitiatingProcessFileName
    """

    def apply_value(self, field: str, val: SigmaType) -> Optional[Union[SigmaType, Iterable[SigmaType]]]:
        parent_process_name = str(val.to_plain().split("\\")[-1].split("/")[-1])
        return SigmaString(parent_process_name)


@dataclass
class SetQueryTableStateTransformation(Transformation):
    """Sets rule query table in pipeline state query_table key"""

    val: Any = None

    def apply(
        self, pipeline: "sigma.processing.pipeline.ProcessingPipeline", rule: "sigma.rule.SigmaRule"  # noqa: F821
    ) -> None:  # noqa: F821
        super().apply(pipeline, rule)
        if "query_table" in pipeline.state:
            table_name = pipeline.state["query_table"]
        else:
            category = rule.logsource.category
            table_name = CATEGORY_TO_TABLE_MAPPINGS.get(category, self.val)
        pipeline.state["query_table"] = pipeline.state.get("query_table", []) + [table_name]


class MicrosoftXDRFieldMapping(FieldMappingTransformation):
    def __init__(self):
        super().__init__({})

    def apply(self, pipeline, rule, detection_item=None, state=None):
        if state and "query_table" in state:
            table_name = state["query_table"]
        else:
            # Fallback to category-based mapping if query_table is not set
            category = rule.logsource.category
            table_name = CATEGORY_TO_TABLE_MAPPINGS.get(category)

        if table_name:
            field = detection_item.field if detection_item else None
            if field:
                return self.get_field_mapping(table_name, field)
        return None


class DynamicFieldMappingTransformation(FieldMappingTransformation):
    def __init__(self, field_mappings):
        super().__init__({})
        self.field_mappings = field_mappings

    def apply_detection_item(self, detection_item: SigmaDetectionItem, pipeline: "ProcessingPipeline", rule: "SigmaRule") -> Optional[SigmaDetectionItem]:  # type: ignore  # noqa: F821
        query_table = pipeline.state.get("query_table", [])[-1] if pipeline.state.get("query_table") else None
        if not query_table:
            # Fallback to category-based mapping if query_table is not set
            category = rule.logsource.category
            query_table = CATEGORY_TO_TABLE_MAPPINGS.get(category)

        if query_table:
            table_mappings = self.field_mappings.table_mappings.get(query_table, {})
            if detection_item.field in table_mappings:
                detection_item.field = table_mappings[detection_item.field]
            elif detection_item.field in self.field_mappings.generic_mappings:
                detection_item.field = self.field_mappings.generic_mappings[detection_item.field]

        return detection_item

    def apply(self, pipeline: "ProcessingPipeline", rule: "SigmaRule"):  # type: ignore  # noqa: F821
        if isinstance(rule, "SigmaRule"):
            for detection in rule.detection.detections.values():
                self.apply_detection(detection, pipeline, rule)

    def apply_detection(self, detection: SigmaDetection, pipeline: "ProcessingPipeline", rule: "SigmaRule"):  # type: ignore  # noqa: F821
        for i, detection_item in enumerate(detection.detection_items):
            if isinstance(detection_item, SigmaDetection):  # recurse into nested detection items
                self.apply_detection(detection_item, pipeline, rule)
            else:
                if self.processing_item is None or self.processing_item.match_detection_item(pipeline, detection_item):
                    r = self.apply_detection_item(detection_item, pipeline, rule)
                    if r is not None:
                        detection.detection_items[i] = r


class GenericFieldMappingTransformation(FieldMappingTransformation):
    def __init__(self, field_mappings):
        super().__init__({})
        self.field_mappings = field_mappings

    def apply_detection_item(self, detection_item: SigmaDetectionItem, pipeline: "ProcessingPipeline", rule: "SigmaRule") -> Optional[SigmaDetectionItem]:  # type: ignore  # noqa: F821
        query_table = pipeline.state.get("query_table", [])[-1]  # Get the last added table name
        table_mappings = self.field_mappings.table_mappings.get(query_table, {})

        if detection_item.field not in table_mappings:
            detection_item.field = self.field_mappings.generic_mappings.get(detection_item.field, detection_item.field)
        return detection_item
