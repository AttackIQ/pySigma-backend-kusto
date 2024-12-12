from typing import Optional

# Event ID Categories based on Windows Security Events
EVENTID_CATEGORIES = {
    "process": [1, 5, 10, 25, 4688, 4689, 4696],  # Process creation, termination, access, tampering
    "logon": [4624, 4625, 4634, 4647, 4648, 4778, 4779, 4800, 4801, 4802, 4803],  # Logon/logoff events
    "registry": [4656, 4657, 4658, 4659, 4660, 4661, 4662, 4663, 12, 13, 14],  # Registry operations
    "file": [2, 11, 15, 23, 26, 27, 28, 29, 4656, 4658, 4660, 4663],  # File operations
    "network": [3, 22, 5140, 5145, 5156, 5157, 5158, 5159],  # Network and DNS events
    "image_load": [7],  # Image loaded
    "pipe": [17, 18],  # Pipe events
    "wmi": [19, 20, 21],  # WMI events
    "service": [4697, 4698, 4699, 4700, 4701, 4702],  # Service and scheduled task operations
    "account": [4720, 4722, 4723, 4724, 4725, 4726, 4738, 4740, 4767],  # Account management
}


def get_category_from_eventid(eventid: int) -> Optional[str]:
    """
    Determine the category based on the Event ID
    """
    return next((category for category, eventids in EVENTID_CATEGORIES.items() if eventid in eventids), None)


def get_table_from_eventid(eventid: int, category_table_mappings: dict) -> str:
    """
    Get the appropriate table name for a given EventID and backend type
    """

    category = get_category_from_eventid(eventid)
    if category and category in category_table_mappings:
        return category_table_mappings[category]
    return ""
