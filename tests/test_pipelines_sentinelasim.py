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


def test_sentinel_asim_pipeline_unsupported_rule_type(asim_backend):
    yaml_rule = """
        title: test
        status: test
        logsource:
            category: invalid_category
            product: invalid_product
        detection:
            sel:
                field: whatever
            condition: sel
    """
    with pytest.raises(SigmaTransformationError, match="Unable to determine table name from rule. "):
        asim_backend.convert(SigmaCollection.from_yaml(yaml_rule))


def test_sentinel_asim_eventid_mapping(asim_backend):
    """Test that EventID is used to determine table when category is missing"""
    yaml_rule = """
        title: Test EventID Mapping
        status: test
        logsource:
            product: windows
        detection:
            sel:
                EventID: 1
                Image: C:\\Windows\\System32\\cmd.exe
            condition: sel
    """
    # EventID 1 should map to process category -> imProcessCreate table
    expected_result = ['imProcessCreate\n| where TargetProcessName =~ "C:\\\\Windows\\\\System32\\\\cmd.exe"']

    assert asim_backend.convert(SigmaCollection.from_yaml(yaml_rule)) == expected_result
    assert asim_backend.convert_rule(SigmaRule.from_yaml(yaml_rule)) == expected_result


def test_sentinel_asim_category_precedence(asim_backend):
    """Test that category takes precedence over EventID when both are present"""
    yaml_rule = """
        title: Test Category Precedence
        status: test
        logsource:
            category: file_event
            product: windows
        detection:
            sel:
                EventID: 1  # Process creation EventID, but should use file_event category
                Image: C:\\Windows\\System32\\cmd.exe
            condition: sel
    """
    # Should use imFileEvent table based on category, not imProcessCreate from EventID
    expected_result = ['imFileEvent\n| where TargetFilePath =~ "C:\\\\Windows\\\\System32\\\\cmd.exe"']

    assert asim_backend.convert(SigmaCollection.from_yaml(yaml_rule)) == expected_result
    assert asim_backend.convert_rule(SigmaRule.from_yaml(yaml_rule)) == expected_result


# pySigma 1.0.0 Compatibility Edge Case Tests - Cross-Pipeline
# This test validates that our fix works across all pipeline implementations


def test_all_pipelines_field_validation():
    """
    Test that field validation works across all three pipelines.
    Edge case: Ensure our fix (SetQueryTableStateTransformation marking itself as applied) works for all pipeline variants.
    This validates that the pySigma 1.0.0 compatibility fix applies universally.
    """
    from sigma.pipelines.azuremonitor import azure_monitor_pipeline
    from sigma.pipelines.microsoftxdr import microsoft_xdr_pipeline
    from sigma.pipelines.sentinelasim import sentinel_asim_pipeline

    pipelines = [
        ("Azure Monitor", azure_monitor_pipeline()),
        ("Microsoft XDR", microsoft_xdr_pipeline()),
        ("Sentinel ASIM", sentinel_asim_pipeline()),
    ]

    invalid_rule = """
        title: Invalid Field Test
        status: test
        logsource:
            category: process_creation
            product: windows
        detection:
            sel:
                CompletelyInvalidFieldName: value
            condition: sel
    """

    for name, pipeline in pipelines:
        backend = KustoBackend(processing_pipeline=pipeline)
        with pytest.raises(SigmaTransformationError, match="Invalid SigmaDetectionItem field name"):
            backend.convert(SigmaCollection.from_yaml(invalid_rule))
