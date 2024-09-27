from dataclasses import dataclass

from sigma.pipelines.kusto_common.schema import BaseSchema, FieldMappings


@dataclass
class MicrosoftXDRSchema(BaseSchema):
    pass


@dataclass
class MicrosoftXDRFieldMappings(FieldMappings):
    pass
