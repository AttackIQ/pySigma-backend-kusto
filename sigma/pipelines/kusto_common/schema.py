from dataclasses import dataclass, field
from typing import Dict, List, Optional, Union


@dataclass
class FieldInfo:
    data_type: str
    description: str


@dataclass
class TableSchema:
    fields: Dict[str, FieldInfo] = field(default_factory=dict)

    def get_field_type(self, field_name: str) -> Optional[str]:
        field = self.fields.get(field_name)
        return field.data_type if field else None

    def get_field_description(self, field_name: str) -> Optional[str]:
        field = self.fields.get(field_name)
        return field.description if field else None

    def get_valid_fields(self) -> List[str]:
        return list(self.fields.keys())


@dataclass
class BaseSchema:
    tables: Dict[str, TableSchema] = field(default_factory=dict)

    def get_field_type(self, table_name: str, field_name: str) -> Optional[str]:
        table = self.tables.get(table_name)
        return table.get_field_type(field_name) if table else None

    def get_field_description(self, table_name: str, field_name: str) -> Optional[str]:
        table = self.tables.get(table_name)
        return table.get_field_description(field_name) if table else None

    def get_valid_fields(self, table_name: str) -> List[str]:
        table = self.tables.get(table_name)
        return table.get_valid_fields() if table else []


@dataclass
class FieldMappings:
    table_mappings: Dict[str, Dict[str, Union[str, List[str]]]] = field(default_factory=dict)
    generic_mappings: Dict[str, str] = field(default_factory=dict)

    def get_field_mapping(self, table_name: str, sigma_field: str) -> str:
        table_mapping = self.table_mappings.get(table_name, {})
        mapping = table_mapping.get(sigma_field)
        if mapping:
            return mapping[0] if isinstance(mapping, list) else mapping
        return self.generic_mappings.get(sigma_field, sigma_field)


def create_schema(schema_class, tables) -> BaseSchema:
    schema = schema_class()
    for table_name, fields in tables.items():
        table_schema = TableSchema()
        for field_name, field_info in fields.items():
            table_schema.fields[field_name] = FieldInfo(
                data_type=field_info["data_type"], description=field_info["description"]
            )
        schema.tables[table_name] = table_schema
    return schema
