from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, List, Optional, Union

from sigma.conditions import ConditionOR
from sigma.processing.transformations import (
    DetectionItemTransformation,
    FieldMappingTransformation,
    Transformation,
    ValueTransformation,
)
from sigma.rule import SigmaDetection, SigmaDetectionItem
from sigma.types import SigmaString, SigmaType

from ..kusto_common.schema import FieldMappings
from .errors import InvalidHashAlgorithmError, SigmaTransformationError


class DynamicFieldMappingTransformation(FieldMappingTransformation):
    """
    Dynamically sets the mapping dictionary based on the pipeline state or rule's category.

    :param field_mappings: A FieldMappings schema object that contains the table_mappings and generic_mappings.
    :type field_mappings: FieldMappings schema object
    """

    def __init__(self, field_mappings: FieldMappings):
        super().__init__(field_mappings.generic_mappings)
        self.field_mappings = field_mappings

    def set_dynamic_mapping(self, pipeline):
        """
        Set the mapping dynamically based on the pipeline state 'query_table' or the rule's logsource category.
        """

        # We should always have a query_table in the pipeline state, will implement mapping based on rule category later if not
        if "query_table" in pipeline.state:
            query_table = pipeline.state["query_table"]
            self.mapping = self.field_mappings.table_mappings.get(query_table, {})
        else:
            # TODO: Implement mapping based on rule category
            pass

    def apply(
        self,
        pipeline: "sigma.processing.pipeline.ProcessingPipeline",  # noqa: F821 # type: ignore
        rule: Union["SigmaRule", "SigmaCorrelationRule"],  # noqa: F821 # type: ignore
    ) -> None:
        """Apply dynamic mapping before the field name transformations."""
        self.set_dynamic_mapping(pipeline)  # Dynamically update the mapping
        super().apply(pipeline, rule)  # Call parent method to continue the transformation process


class GenericFieldMappingTransformation(FieldMappingTransformation):
    """
    Transformation for applying generic field mappings after table-specific mappings.
    """

    def __init__(self, field_mappings: FieldMappings):
        super().__init__(field_mappings.generic_mappings)

    def apply_detection_item(
        self, detection_item: SigmaDetectionItem
    ) -> Optional[Union[SigmaDetectionItem, SigmaString]]:
        if detection_item.field in self.mapping:
            detection_item.field = self.mapping[detection_item.field]
        return detection_item


class BaseHashesValuesTransformation(DetectionItemTransformation):
    """
    Base class for transforming the Hashes field to get rid of the hash algorithm prefix in each value and create new detection items for each hash type.
    """

    def __init__(self, valid_hash_algos: List[str], field_prefix: str = None, drop_algo_prefix: bool = False):
        """
        :param valid_hash_algos: A list of valid hash algorithms that are supported by the table.
        :param field_prefix: The prefix to use for the new detection items.
        :param drop_algo_prefix: Whether to drop the algorithm prefix in the new field name, e.g. "FileHashSHA256" -> "FileHash".
        """
        self.valid_hash_algos = valid_hash_algos
        self.field_prefix = field_prefix or ""
        self.drop_algo_prefix = drop_algo_prefix

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
                    if hash_value[0].lstrip("*").upper() in self.valid_hash_algos
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
                elif len(hash_value) == 128:  # SHA512
                    hash_algo = "SHA512"
                    no_valid_hash_algo = False
                else:  # Invalid algo, no fieldname for keyword search
                    hash_algo = ""

            field_name = self.field_prefix
            if not self.drop_algo_prefix:
                field_name += hash_algo
            algo_dict[field_name].append(hash_value)
        if no_valid_hash_algo:
            raise InvalidHashAlgorithmError(
                "No valid hash algo found in Hashes field. Please use one of the following: "
                + ", ".join(self.valid_hash_algos)
            )
        for k, v in algo_dict.items():
            if k:  # Filter out invalid hash algo types
                to_return.append(
                    SigmaDetectionItem(
                        field=k if k != "keyword" else None, modifiers=[], value=[SigmaString(x) for x in v]
                    )
                )
        return SigmaDetection(detection_items=to_return, item_linking=ConditionOR)


@dataclass
class SetQueryTableStateTransformation(Transformation):
    """Sets rule query table in pipeline state query_table key

    :param val: The table name to set in the pipeline state. If not provided, the table name will be determined from the rule's logsource category.
    :param category_to_table_mappings: A dictionary mapping logsource categories to table names. If not provided, the default category_to_table_mappings will be used.

    """

    val: Any = None
    category_to_table_mappings: Dict[str, Any] = field(default_factory=dict)

    def apply(self, pipeline: "ProcessingPipeline", rule: "SigmaRule") -> None:  # type: ignore  # noqa: F821
        super().apply(pipeline, rule)
        if self.val:
            table_name = self.val
        else:
            category = rule.logsource.category
            table_name = self.category_to_table_mappings.get(category)

        if table_name:
            if isinstance(table_name, list):
                table_name = table_name[0]  # Use the first table if it's a list
            pipeline.state["query_table"] = table_name
        else:
            raise SigmaTransformationError(
                f"Unable to determine table name for category: {category}, category is not yet supported by the pipeline.  Please provide the 'query_table' parameter to the pipeline instead."
            )


## Change field value AFTER field transformations from Sysmon values to values expected in the pipelines registry table action field
class RegistryActionTypeValueTransformation(ValueTransformation):
    """Custom ValueTransformation transformation. The Microsoft DeviceRegistryEvents table expect the ActionType to
    be a slightly different set of values than what Sysmon specified, so this will change them to the correct value."""

    value_mappings = {  # Sysmon EventType -> DeviceRegistryEvents ActionType
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
