import pytest
from sigma.collection import SigmaCollection
from sigma.backends.kusto import KustoBackend
from sigma.pipelines.sentinelasim import sentinel_asim_pipeline
from sigma.exceptions import SigmaTransformationError

def test_sentinel_asim_process_creation_field_mapping():
    assert (
        KustoBackend(processing_pipeline=sentinel_asim_pipeline()).convert(
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
        == ["imProcessCreate\n| where TargetProcessName =~ \"C:\\\\Windows\\\\System32\\\\cmd.exe\" and TargetProcessCommandLine =~ \"whoami\" and TargetUsername =~ \"SYSTEM\" and TargetProcessId == 1234"]
    )

def test_sentinel_asim_network_connection_field_mapping():
    assert (
        KustoBackend(processing_pipeline=sentinel_asim_pipeline()).convert(
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
                        Protocol: udp
                    condition: sel
                """
            )
        )
        == ["imNetworkSession\n| where DstIpAddr =~ \"8.8.8.8\" and DstPortNumber == 53 and NetworkProtocol =~ \"udp\""]
    )

def test_sentinel_asim_registry_event_field_mapping():
    assert (
        KustoBackend(processing_pipeline=sentinel_asim_pipeline()).convert(
            SigmaCollection.from_yaml(
                """
                title: Test Registry Event
                status: test
                logsource:
                    category: registry_event
                    product: windows
                detection:
                    sel:
                        TargetObject: HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run
                        EventType: SetValue
                    condition: sel
                """
            )
        )
        == ["imRegistry\n| where RegistryKey =~ \"HKEY_LOCAL_MACHINE\\\\SOFTWARE\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Run\" and EventType =~ \"RegistryValueSet\""]
    )

def test_sentinel_asim_custom_table():
    assert (
        KustoBackend(processing_pipeline=sentinel_asim_pipeline(query_table="imFileEvent")).convert(
            SigmaCollection.from_yaml(
                """
                title: Test Custom Table
                status: test
                logsource:
                    category: process_creation
                    product: windows
                detection:
                    sel:
                        Image: malware.exe
                    condition: sel
                """
            )
        )
        == ["imFileEvent\n| where TargetFilePath =~ \"malware.exe\""]
    )

def test_sentinel_asim_unsupported_field():
    with pytest.raises(SigmaTransformationError, match="Invalid SigmaDetectionItem field name encountered: UnsupportedField"):
        KustoBackend(processing_pipeline=sentinel_asim_pipeline()).convert(
            SigmaCollection.from_yaml(
                """
                title: Test Unsupported Field
                status: test
                logsource:
                    category: process_creation
                    product: windows
                detection:
                    sel:
                        UnsupportedField: value
                    condition: sel
                """
            )
        )

def test_sentinel_asim_file_event():
    assert (
        KustoBackend(processing_pipeline=sentinel_asim_pipeline()).convert(
            SigmaCollection.from_yaml(
                """
                title: Test File Event
                status: test
                logsource:
                    category: file_event
                    product: windows
                detection:
                    sel:
                        Image: C:\\Windows\\explorer.exe
                    condition: sel
                """
            )
        )
        == ["imFileEvent\n| where TargetFilePath =~ \"C:\\\\Windows\\\\explorer.exe\""]
    )