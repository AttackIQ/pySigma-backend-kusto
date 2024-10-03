import pytest

from sigma.backends.kusto import KustoBackend
from sigma.collection import SigmaCollection
from sigma.exceptions import SigmaTransformationError
from sigma.pipelines.sentinelasim import sentinel_asim_pipeline
from sigma.rule import SigmaRule


@pytest.fixture
def asim_backend():
    return KustoBackend(processing_pipeline=sentinel_asim_pipeline())


def test_sentinel_asim_process_creation_field_mapping(asim_backend):
    yaml_rule = """
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
    expected_result = [
        'imProcessCreate\n| where TargetProcessName =~ "C:\\\\Windows\\\\System32\\\\cmd.exe" and TargetProcessCommandLine =~ "whoami" and TargetUsername =~ "SYSTEM" and TargetProcessId == 1234'
    ]

    assert asim_backend.convert(SigmaCollection.from_yaml(yaml_rule)) == expected_result
    assert asim_backend.convert_rule(SigmaRule.from_yaml(yaml_rule)) == expected_result


def test_sentinel_asim_network_connection_field_mapping(asim_backend):
    yaml_rule = """
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
    expected_result = [
        'imNetworkSession\n| where DstIpAddr =~ "8.8.8.8" and DstPortNumber == 53 and NetworkProtocol =~ "udp"'
    ]

    assert asim_backend.convert(SigmaCollection.from_yaml(yaml_rule)) == expected_result
    assert asim_backend.convert_rule(SigmaRule.from_yaml(yaml_rule)) == expected_result


def test_sentinel_asim_registry_event_field_mapping(asim_backend):
    yaml_rule = """
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
    expected_result = [
        'imRegistry\n| where RegistryKey =~ "HKEY_LOCAL_MACHINE\\\\SOFTWARE\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Run" and EventType =~ "RegistryValueSet"'
    ]

    assert asim_backend.convert(SigmaCollection.from_yaml(yaml_rule)) == expected_result
    assert asim_backend.convert_rule(SigmaRule.from_yaml(yaml_rule)) == expected_result


def test_sentinel_asim_custom_table():
    yaml_rule = """
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
    expected_result = ['imFileEvent\n| where TargetFilePath =~ "malware.exe"']

    custom_backend = KustoBackend(processing_pipeline=sentinel_asim_pipeline(query_table="imFileEvent"))
    assert custom_backend.convert(SigmaCollection.from_yaml(yaml_rule)) == expected_result
    assert custom_backend.convert_rule(SigmaRule.from_yaml(yaml_rule)) == expected_result


def test_sentinel_asim_unsupported_field(asim_backend):
    yaml_rule = """
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
    with pytest.raises(
        SigmaTransformationError, match="Invalid SigmaDetectionItem field name encountered: UnsupportedField"
    ):
        asim_backend.convert(SigmaCollection.from_yaml(yaml_rule))


def test_sentinel_asim_file_event(asim_backend):
    yaml_rule = """
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
    expected_result = ['imFileEvent\n| where TargetFilePath =~ "C:\\\\Windows\\\\explorer.exe"']

    assert asim_backend.convert(SigmaCollection.from_yaml(yaml_rule)) == expected_result
    assert asim_backend.convert_rule(SigmaRule.from_yaml(yaml_rule)) == expected_result


def test_sentinel_asim_pipeline_custom_table_invalid_category():
    yaml_rule = """
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
    expected_result = ['imFileEvent\n| where TargetFilePath =~ "malware.exe"']

    custom_backend = KustoBackend(processing_pipeline=sentinel_asim_pipeline(query_table="imFileEvent"))
    assert custom_backend.convert(SigmaCollection.from_yaml(yaml_rule)) == expected_result
    assert custom_backend.convert_rule(SigmaRule.from_yaml(yaml_rule)) == expected_result


def test_sentinel_asim_processcreate_hashes_field_values(asim_backend):
    yaml_rule = """
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
    expected_result = [
        'imProcessCreate\n| where TargetProcessMD5 =~ "1234567890abcdef1234567890abcdef" or TargetProcessSHA1 =~ "1234567890abcdef1234567890abcdef12345678" or TargetProcessSHA256 =~ "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef" or TargetProcessIMPHASH =~ "1234567890abcdef1234567890abcdef" or TargetProcessSHA512 =~ "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef"'
    ]

    assert asim_backend.convert(SigmaCollection.from_yaml(yaml_rule)) == expected_result
    assert asim_backend.convert_rule(SigmaRule.from_yaml(yaml_rule)) == expected_result


def test_sentinel_asim_fileevent_hashes_field_values(asim_backend):
    yaml_rule = """
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
    expected_result = [
        'imFileEvent\n| where TargetFileMD5 =~ "1234567890abcdef1234567890abcdef" or TargetFileSHA1 =~ "1234567890abcdef1234567890abcdef12345678" or TargetFileSHA256 =~ "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef"'
    ]

    assert asim_backend.convert(SigmaCollection.from_yaml(yaml_rule)) == expected_result
    assert asim_backend.convert_rule(SigmaRule.from_yaml(yaml_rule)) == expected_result


def test_sentinel_asim_webrequest_hashes_field_values(asim_backend):
    yaml_rule = """
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
    expected_result = [
        'imWebSession\n| where FileMD5 =~ "1234567890abcdef1234567890abcdef" or FileSHA1 =~ "1234567890abcdef1234567890abcdef12345678" or FileSHA256 =~ "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef"'
    ]

    assert asim_backend.convert(SigmaCollection.from_yaml(yaml_rule)) == expected_result
    assert asim_backend.convert_rule(SigmaRule.from_yaml(yaml_rule)) == expected_result
