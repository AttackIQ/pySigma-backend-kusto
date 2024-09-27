import pytest

from sigma.backends.kusto import KustoBackend
from sigma.collection import SigmaCollection
from sigma.exceptions import SigmaTransformationError
from sigma.pipelines.azuremonitor import azure_monitor_pipeline


def test_azure_monitor_process_creation_field_mapping():
    assert (
        KustoBackend(processing_pipeline=azure_monitor_pipeline()).convert(
            SigmaCollection.from_yaml(
                """
                title: Test Process Creation
                status: test
                logsource:
                    category: process_creation
                    product: windows
                detection:
                    sel:
                        Image: C:\\Windows\\System32\\cmd.exe
                        CommandLine: whoami
                        User: SYSTEM
                        ProcessId: 1234
                    condition: sel
                """
            )
        )
        == [
            'SecurityEvent\n| where NewProcessName =~ "C:\\\\Windows\\\\System32\\\\cmd.exe" and CommandLine =~ "whoami" and SubjectUserName =~ "SYSTEM" and NewProcessId == 1234'
        ]
    )


def test_azure_monitor_network_connection_field_mapping():
    assert (
        KustoBackend(processing_pipeline=azure_monitor_pipeline()).convert(
            SigmaCollection.from_yaml(
                """
                title: Test Network Connection
                status: test
                logsource:
                    category: network_connection
                    product: windows
                detection:
                    sel:
                        DestinationIp: 8.8.8.8
                        DestinationPort: 53
                        SourcePort: 12345
                    condition: sel
                """
            )
        )
        == ['SecurityEvent\n| where DestinationIp =~ "8.8.8.8" and DestinationPort == 53 and SourcePort == 12345']
    )


def test_azure_monitor_registry_event_field_mapping():
    assert (
        KustoBackend(processing_pipeline=azure_monitor_pipeline()).convert(
            SigmaCollection.from_yaml(
                """
                title: Test Registry Event
                status: test
                logsource:
                    category: registry_event
                    product: windows
                detection:
                    sel:
                        EventID: 13
                        TargetObject: HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run
                    condition: sel
                """
            )
        )
        == [
            'SecurityEvent\n| where EventID == 13 and ObjectName =~ "HKEY_LOCAL_MACHINE\\\\Software\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Run"'
        ]
    )


def test_azure_monitor_file_event_field_mapping():
    assert (
        KustoBackend(processing_pipeline=azure_monitor_pipeline()).convert(
            SigmaCollection.from_yaml(
                """
                title: Test File Event
                status: test
                logsource:
                    category: file_event
                    product: windows
                detection:
                    sel:
                        TargetFilename: C:\\suspicious\\file.exe
                        Image: C:\\Windows\\System32\\cmd.exe
                    condition: sel
                """
            )
        )
        == [
            'SecurityEvent\n| where ObjectName =~ "C:\\\\suspicious\\\\file.exe" and NewProcessName =~ "C:\\\\Windows\\\\System32\\\\cmd.exe"'
        ]
    )


def test_azure_monitor_hashes_transformation():
    assert (
        KustoBackend(processing_pipeline=azure_monitor_pipeline()).convert(
            SigmaCollection.from_yaml(
                """
                title: Test Hashes
                status: test
                logsource:
                    category: process_creation
                    product: windows
                detection:
                    sel:
                        Hashes:
                            - md5=1234567890abcdef1234567890abcdef
                            - sha1=1234567890abcdef1234567890abcdef12345678
                            - sha256=1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef
                    condition: sel
                """
            )
        )
        == [
            'SecurityEvent\n| where FileHash in~ ("1234567890abcdef1234567890abcdef", "1234567890abcdef1234567890abcdef12345678", "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef")'
        ]
    )


def test_azure_monitor_registry_key_replacement():
    assert (
        KustoBackend(processing_pipeline=azure_monitor_pipeline()).convert(
            SigmaCollection.from_yaml(
                """
                title: Test Registry Key Replacement
                status: test
                logsource:
                    category: registry_event
                    product: windows
                detection:
                    sel:
                        TargetObject:
                            - HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run
                            - HKU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run
                            - HKCR\\Software\\Microsoft\\Windows\\CurrentVersion\\Run
                    condition: sel
                """
            )
        )
        == [
            'SecurityEvent\n| where ObjectName in~ ("HKEY_LOCAL_MACHINE\\\\Software\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Run", "HKEY_USERS\\\\Software\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Run", "HKEY_LOCAL_MACHINE\\\\CLASSES\\\\Software\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Run")'
        ]
    )


def test_azure_monitor_unsupported_category():
    with pytest.raises(SigmaTransformationError, match="Unable to determine table name for category"):
        KustoBackend(processing_pipeline=azure_monitor_pipeline()).convert(
            SigmaCollection.from_yaml(
                """
                title: Test Unsupported Category
                status: test
                logsource:
                    category: unsupported_category
                    product: windows
                detection:
                    sel:
                        Field: value
                    condition: sel
                """
            )
        )


def test_azure_monitor_invalid_field():
    with pytest.raises(
        SigmaTransformationError, match="Invalid SigmaDetectionItem field name encountered.*SecurityEvent"
    ):
        KustoBackend(processing_pipeline=azure_monitor_pipeline()).convert(
            SigmaCollection.from_yaml(
                """
                title: Test Invalid Field
                status: test
                logsource:
                    category: process_creation
                    product: windows
                detection:
                    sel:
                        InvalidField: value
                    condition: sel
                """
            )
        )


def test_azure_monitor_custom_query_table():
    assert (
        KustoBackend(processing_pipeline=azure_monitor_pipeline(query_table="CustomTable")).convert(
            SigmaCollection.from_yaml(
                """
                title: Test Custom Query Table
                status: test
                logsource:
                    category: process_creation
                    product: windows
                detection:
                    sel:
                        CommandLine: whoami
                    condition: sel
                """
            )
        )
        == ['CustomTable\n| where CommandLine =~ "whoami"']
    )


def test_azure_monitor_pipeline_custom_table_invalid_category():
    """Tests to ensure custom table names override category table name mappings and field name mappings"""
    assert (
        KustoBackend(processing_pipeline=azure_monitor_pipeline(query_table="SecurityEvent")).convert(
            SigmaCollection.from_yaml(
                """
            title: Test
            status: test
            logsource:
                product: windows
                category: blah
            detection:
                sel:
                    Image: actuallyafileevent.exe
                condition: sel
        """
            )
        )
        == ["SecurityEvent\n| " 'where NewProcessName =~ "actuallyafileevent.exe"']
    )
