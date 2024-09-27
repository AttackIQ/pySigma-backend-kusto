import pytest

from sigma.backends.kusto import KustoBackend
from sigma.collection import SigmaCollection
from sigma.exceptions import SigmaTransformationError
from sigma.pipelines.sentinelasim import sentinel_asim_pipeline


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
        == [
            'imProcessCreate\n| where TargetProcessName =~ "C:\\\\Windows\\\\System32\\\\cmd.exe" and TargetProcessCommandLine =~ "whoami" and TargetUsername =~ "SYSTEM" and TargetProcessId == 1234'
        ]
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
        == ['imNetworkSession\n| where DstIpAddr =~ "8.8.8.8" and DstPortNumber == 53 and NetworkProtocol =~ "udp"']
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
        == [
            'imRegistry\n| where RegistryKey =~ "HKEY_LOCAL_MACHINE\\\\SOFTWARE\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Run" and EventType =~ "RegistryValueSet"'
        ]
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
        == ['imFileEvent\n| where TargetFilePath =~ "malware.exe"']
    )


def test_sentinel_asim_unsupported_field():
    with pytest.raises(
        SigmaTransformationError, match="Invalid SigmaDetectionItem field name encountered: UnsupportedField"
    ):
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
        == ['imFileEvent\n| where TargetFilePath =~ "C:\\\\Windows\\\\explorer.exe"']
    )


def test_sentinel_asim_pipeline_custom_table_invalid_category():
    assert (
        KustoBackend(processing_pipeline=sentinel_asim_pipeline(query_table="imFileEvent")).convert(
            SigmaCollection.from_yaml(
                """
                title: Test Custom Table
                status: test
                logsource:
                    category: blah
                    product: windows
                detection:
                    sel:
                        Image: malware.exe
                    condition: sel
                """
            )
        )
        == ['imFileEvent\n| where TargetFilePath =~ "malware.exe"']
    )


def test_sentinel_asim_processcreate_hashes_field_values():
    assert (
        KustoBackend(processing_pipeline=sentinel_asim_pipeline()).convert(
            SigmaCollection.from_yaml(
                """
                title: Test ProcessCreate Hashes Field Values
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
                            - imphash=1234567890abcdef1234567890abcdef
                            - sha512=1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef
                    condition: sel
                """
            )
        )
        == [
            'imProcessCreate\n| where TargetProcessMD5 =~ "1234567890abcdef1234567890abcdef" or TargetProcessSHA1 =~ "1234567890abcdef1234567890abcdef12345678" or TargetProcessSHA256 =~ "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef" or TargetProcessIMPHASH =~ "1234567890abcdef1234567890abcdef" or TargetProcessSHA512 =~ "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef"'
        ]
    )

def test_sentinel_asim_fileevent_hashes_field_values():
    assert (
        KustoBackend(processing_pipeline=sentinel_asim_pipeline()).convert(
            SigmaCollection.from_yaml(
                """
                title: Test FileEvent Hashes Field Values
                status: test
                logsource:
                    category: file_event
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
        == ['imFileEvent\n| where TargetFileMD5 =~ "1234567890abcdef1234567890abcdef" or TargetFileSHA1 =~ "1234567890abcdef1234567890abcdef12345678" or TargetFileSHA256 =~ "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef"']
    )

def test_sentinel_asim_webrequest_hashes_field_values():
    assert (
        KustoBackend(processing_pipeline=sentinel_asim_pipeline()).convert(
            SigmaCollection.from_yaml(
                """
                title: Test WebRequest Hashes Field Values
                status: test
                logsource:
                    category: proxy
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
        == ['imWebSession\n| where FileMD5 =~ "1234567890abcdef1234567890abcdef" or FileSHA1 =~ "1234567890abcdef1234567890abcdef12345678" or FileSHA256 =~ "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef"']
    )
