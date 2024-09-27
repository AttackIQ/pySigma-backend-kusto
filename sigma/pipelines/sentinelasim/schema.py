from dataclasses import dataclass

from sigma.pipelines.kusto_common.schema import BaseSchema, FieldMappings


@dataclass
class SentinelASIMSchema(BaseSchema):
    pass


@dataclass
class SentinelASIMFieldMappings(FieldMappings):
    pass
