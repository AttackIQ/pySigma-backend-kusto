from dataclasses import dataclass

from sigma.pipelines.kusto_common.schema import BaseSchema, FieldMappings


@dataclass
class AzureMonitorSchema(BaseSchema):
    pass


@dataclass
class AzureMonitorFieldMappings(FieldMappings):
    pass
