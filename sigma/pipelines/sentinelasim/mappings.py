from sigma.pipelines.common import (
    logsource_windows_file_access,
    logsource_windows_file_change,
    logsource_windows_file_delete,
    logsource_windows_file_event,
    logsource_windows_file_rename,
    logsource_windows_image_load,
    logsource_windows_network_connection,
    logsource_windows_process_creation,
    logsource_windows_registry_add,
    logsource_windows_registry_delete,
    logsource_windows_registry_event,
    logsource_windows_registry_set,
)

#from .schema import MicrosoftXDRFieldMappings
from .tables import SENTINEL_ASIM_TABLES


# Get table names from the tables.py file
table_names = list(SENTINEL_ASIM_TABLES.keys())


# Rule Categories -> Query Table Names
# Use the table names from the tables.py file by looking for relevant terms in the table names
CATEGORY_TO_TABLE_MAPPINGS = {
    "process_creation": next((table for table in table_names if 'process' in table.lower()), "imProcessCreatrer"),
    #"image_load": next((table for table in table_names if 'image' in table.lower()), None),
    "file_access": next((table for table in table_names if 'file' in table.lower()), "imFileEvent"),
    "file_change": next((table for table in table_names if 'file' in table.lower()), "imFileEvent"),
    "file_delete": next((table for table in table_names if 'file' in table.lower()), "imFileEvent"),
    "file_event": next((table for table in table_names if 'file' in table.lower()), "imFileEvent"),
    "file_rename": next((table for table in table_names if 'file' in table.lower()), "imFileEvent"),
    "registry_add": next((table for table in table_names if 'registry' in table.lower()), "imRegistry"),
    "registry_delete": next((table for table in table_names if 'registry' in table.lower()), "imRegistry"),
    "registry_event": next((table for table in table_names if 'registry' in table.lower()), "imRegistry"),
    "registry_set": next((table for table in table_names if 'registry' in table.lower()), "imRegistry"),
    "network_connection": next((table for table in table_names if 'network' in table.lower()), "imNetworkSession"),
}

## Rule Categories -> RuleConditions
CATEGORY_TO_CONDITIONS_MAPPINGS = {
    "process_creation": logsource_windows_process_creation(),
    #"image_load": logsource_windows_image_load(),
    "file_access": logsource_windows_file_access(),
    "file_change": logsource_windows_file_change(),
    "file_delete": logsource_windows_file_delete(),
    "file_event": logsource_windows_file_event(),
    "file_rename": logsource_windows_file_rename(),
    "registry_add": logsource_windows_registry_add(),
    "registry_delete": logsource_windows_registry_delete(),
    "registry_event": logsource_windows_registry_event(),
    "registry_set": logsource_windows_registry_set(),
    "network_connection": logsource_windows_network_connection(),
}

