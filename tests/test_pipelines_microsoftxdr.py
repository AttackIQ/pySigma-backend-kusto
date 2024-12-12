import pytest

from sigma.backends.kusto import KustoBackend
from sigma.collection import SigmaCollection
from sigma.exceptions import SigmaTransformationError
from sigma.pipelines.kusto_common.errors import InvalidHashAlgorithmError
from sigma.pipelines.microsoft365defender import microsoft_365_defender_pipeline
from sigma.pipelines.microsoftxdr import microsoft_xdr_pipeline
from sigma.rule import SigmaRule


@pytest.fixture
def xdr_backend():
    return KustoBackend(processing_pipeline=microsoft_xdr_pipeline())


def test_microsoft_xdr_pipeline_alias():
    assert microsoft_xdr_pipeline() == microsoft_365_defender_pipeline()


def test_microsoft_xdr_username_transformation(xdr_backend):
    yaml_rule = """
        title: Test
        status: test
        logsource:
            category: process_creation
            product: windows
        detection:
            sel1:
                CommandLine: command1
                AccountName: username1
            sel2:
                CommandLine: command2
                AccountName: domain2\\username2
            sel3:
                CommandLine: command3
                InitiatingProcessAccountName:
                    - username3
                    - domain4\\username4
            sel4:
                AccountName: username5
            condition: any of sel*
    """
    expected_result = [
        "DeviceProcessEvents\n| "
        'where (ProcessCommandLine =~ "command1" and AccountName =~ "username1") or '
        '(ProcessCommandLine =~ "command2" and (AccountName =~ "username2" and AccountDomain =~ "domain2")) or '
        '(ProcessCommandLine =~ "command3" and (InitiatingProcessAccountName =~ "username3" or '
        '(InitiatingProcessAccountName =~ "username4" and InitiatingProcessAccountDomain =~ "domain4"))) or '
        'AccountName =~ "username5"'
    ]

    assert xdr_backend.convert(SigmaCollection.from_yaml(yaml_rule)) == expected_result
    assert xdr_backend.convert_rule(SigmaRule.from_yaml(yaml_rule)) == expected_result


def test_microsoft_xdr_hashes_values_transformation(xdr_backend):
    yaml_rule = """
        title: Test
        status: test
        logsource:
            category: process_creation
            product: windows
        detection:
            sel1:
                Hashes:
                    - md5|e708864855f3bb69c4d9a213b9108b9f
                    - sha1|00ea1da4192a2030f9ae023de3b3143ed647bbab
                    - sha256|6bbb0da1891646e58eb3e6a63af3a6fc3c8eb5a0d44824cba581d2e14a0450cf
            sel2:
                Hashes:
                    - 0b49939d6415354c950b142a0b1e696a
                    - 4b2b79b6f371ca18f1216461cffeaddf6848a50e
                    - 8f16f88cfa1cf0d17c75403aa9614d806ebc00419763e0ecac3860decbcd9988
                    - invalidhashvalue
            condition: any of sel*
    """
    expected_result = [
        "DeviceProcessEvents\n"
        '| where (MD5 =~ "e708864855f3bb69c4d9a213b9108b9f" or SHA1 =~ "00ea1da4192a2030f9ae023de3b3143ed647bbab" '
        'or SHA256 =~ "6bbb0da1891646e58eb3e6a63af3a6fc3c8eb5a0d44824cba581d2e14a0450cf") or '
        '(MD5 =~ "0b49939d6415354c950b142a0b1e696a" or SHA1 =~ "4b2b79b6f371ca18f1216461cffeaddf6848a50e" or '
        'SHA256 =~ "8f16f88cfa1cf0d17c75403aa9614d806ebc00419763e0ecac3860decbcd9988")'
    ]

    assert xdr_backend.convert(SigmaCollection.from_yaml(yaml_rule)) == expected_result
    assert xdr_backend.convert_rule(SigmaRule.from_yaml(yaml_rule)) == expected_result


def test_microsoft_xdr_process_creation_simple(xdr_backend):
    yaml_rule = """
        title: Test
        status: test
        logsource:
            category: process_creation
            product: windows
        detection:
            sel:
                CommandLine: val1
                Image: val2
            condition: sel
    """
    expected_result = ['DeviceProcessEvents\n| where ProcessCommandLine =~ "val1" and FolderPath =~ "val2"']

    assert xdr_backend.convert(SigmaCollection.from_yaml(yaml_rule)) == expected_result
    assert xdr_backend.convert_rule(SigmaRule.from_yaml(yaml_rule)) == expected_result


def test_microsoft_xdr_image_load_simple(xdr_backend):
    yaml_rule = """
        title: Test
        status: test
        logsource:
            category: image_load
            product: windows
        detection:
            sel:
                ImageLoaded: val1
                sha1: val2
            condition: sel
    """
    expected_result = ['DeviceImageLoadEvents\n| where FolderPath =~ "val1" and SHA1 =~ "val2"']

    assert xdr_backend.convert(SigmaCollection.from_yaml(yaml_rule)) == expected_result
    assert xdr_backend.convert_rule(SigmaRule.from_yaml(yaml_rule)) == expected_result


def test_microsoft_xdr_file_access_simple(xdr_backend):
    yaml_rule = """
        title: Test
        status: test
        logsource:
            category: file_access
            product: windows
        detection:
            sel:
                TargetFilename: val1
                Image: val2
            condition: sel
    """
    expected_result = ['DeviceFileEvents\n| where FolderPath =~ "val1" and InitiatingProcessFolderPath =~ "val2"']

    assert xdr_backend.convert(SigmaCollection.from_yaml(yaml_rule)) == expected_result
    assert xdr_backend.convert_rule(SigmaRule.from_yaml(yaml_rule)) == expected_result


def test_microsoft_xdr_file_change_simple(xdr_backend):
    yaml_rule = """
        title: Test
        status: test
        logsource:
            category: file_change
            product: windows
        detection:
            sel:
                TargetFilename: val1
                Image: val2
            condition: sel
    """
    expected_result = ['DeviceFileEvents\n| where FolderPath =~ "val1" and InitiatingProcessFolderPath =~ "val2"']

    assert xdr_backend.convert(SigmaCollection.from_yaml(yaml_rule)) == expected_result
    assert xdr_backend.convert_rule(SigmaRule.from_yaml(yaml_rule)) == expected_result


def test_microsoft_xdr_file_delete_simple(xdr_backend):
    yaml_rule = """
        title: Test
        status: test
        logsource:
            category: file_delete
            product: windows
        detection:
            sel:
                TargetFilename: val1
                Image: val2
            condition: sel
    """
    expected_result = ['DeviceFileEvents\n| where FolderPath =~ "val1" and InitiatingProcessFolderPath =~ "val2"']

    assert xdr_backend.convert(SigmaCollection.from_yaml(yaml_rule)) == expected_result
    assert xdr_backend.convert_rule(SigmaRule.from_yaml(yaml_rule)) == expected_result


def test_microsoft_xdr_file_event_simple(xdr_backend):
    yaml_rule = """
        title: Test
        status: test
        logsource:
            category: file_change
            product: windows
        detection:
            sel:
                TargetFilename: val1
                Image: val2
            condition: sel
    """
    expected_result = ['DeviceFileEvents\n| where FolderPath =~ "val1" and InitiatingProcessFolderPath =~ "val2"']

    assert xdr_backend.convert(SigmaCollection.from_yaml(yaml_rule)) == expected_result
    assert xdr_backend.convert_rule(SigmaRule.from_yaml(yaml_rule)) == expected_result


def test_microsoft_xdr_file_rename_simple(xdr_backend):
    yaml_rule = """
        title: Test
        status: test
        logsource:
            category: file_rename
            product: windows
        detection:
            sel:
                TargetFilename: val1
                Image: val2
            condition: sel
    """
    expected_result = ['DeviceFileEvents\n| where FolderPath =~ "val1" and InitiatingProcessFolderPath =~ "val2"']

    assert xdr_backend.convert(SigmaCollection.from_yaml(yaml_rule)) == expected_result
    assert xdr_backend.convert_rule(SigmaRule.from_yaml(yaml_rule)) == expected_result


def test_microsoft_xdr_registry_add_simple(xdr_backend):
    yaml_rule = """
        title: Test
        status: test
        logsource:
            category: registry_add
            product: windows
        detection:
            sel:
                Image: val1
                TargetObject: val2
            condition: sel
    """
    expected_result = ['DeviceRegistryEvents\n| where InitiatingProcessFolderPath =~ "val1" and RegistryKey =~ "val2"']

    assert xdr_backend.convert(SigmaCollection.from_yaml(yaml_rule)) == expected_result
    assert xdr_backend.convert_rule(SigmaRule.from_yaml(yaml_rule)) == expected_result


def test_microsoft_xdr_registry_delete_simple(xdr_backend):
    yaml_rule = """
        title: Test
        status: test
        logsource:
            category: registry_delete
            product: windows
        detection:
            sel:
                Image: val1
                TargetObject: val2
            condition: sel
    """
    expected_result = ['DeviceRegistryEvents\n| where InitiatingProcessFolderPath =~ "val1" and RegistryKey =~ "val2"']

    assert xdr_backend.convert(SigmaCollection.from_yaml(yaml_rule)) == expected_result
    assert xdr_backend.convert_rule(SigmaRule.from_yaml(yaml_rule)) == expected_result


def test_microsoft_xdr_registry_event_simple(xdr_backend):
    yaml_rule = """
        title: Test
        status: test
        logsource:
            category: registry_event
            product: windows
        detection:
            sel:
                Image: val1
                TargetObject: val2
            condition: sel
    """
    expected_result = ['DeviceRegistryEvents\n| where InitiatingProcessFolderPath =~ "val1" and RegistryKey =~ "val2"']

    assert xdr_backend.convert(SigmaCollection.from_yaml(yaml_rule)) == expected_result
    assert xdr_backend.convert_rule(SigmaRule.from_yaml(yaml_rule)) == expected_result


def test_microsoft_xdr_registry_set_simple(xdr_backend):
    yaml_rule = """
        title: Test
        status: test
        logsource:
            category: registry_set
            product: windows
        detection:
            sel:
                Image: val1
                TargetObject: val2
            condition: sel
    """
    expected_result = ['DeviceRegistryEvents\n| where InitiatingProcessFolderPath =~ "val1" and RegistryKey =~ "val2"']

    assert xdr_backend.convert(SigmaCollection.from_yaml(yaml_rule)) == expected_result
    assert xdr_backend.convert_rule(SigmaRule.from_yaml(yaml_rule)) == expected_result


def test_microsoft_xdr_process_creation_field_mapping(xdr_backend):
    yaml_rule = """
        title: Test
        status: test
        logsource:
            category: process_creation
            product: windows
        detection:
            sel:
                Image: C:\\Path\\to\\notmalware.exe
                FileVersion: 1
                Description: A Description
                Product: pySigma
                Company: AttackIQ
                OriginalFileName: malware.exe
                ProcessId: 2
                CommandLine: definitely not malware
                User: heyitsmeyourbrother
                IntegrityLevel: 1
                sha1: a123123123
                sha256: a123123123
                md5: a123123123
                ParentProcessId: 1
                ParentImage: C:\\Windows\\Temp\\freemoney.pdf
                ParentCommandLine: freemoney.pdf test exe please ignore
                ParentUser: heyitsmeyourparent
            condition: sel
    """
    expected_result = [
        "DeviceProcessEvents\n| "
        'where FolderPath =~ "C:\\\\Path\\\\to\\\\notmalware.exe" and '
        "ProcessVersionInfoProductVersion == 1 and "
        'ProcessVersionInfoFileDescription =~ "A Description" and '
        'ProcessVersionInfoProductName =~ "pySigma" and '
        'ProcessVersionInfoCompanyName =~ "AttackIQ" and '
        'ProcessVersionInfoOriginalFileName =~ "malware.exe" and '
        "ProcessId == 2 and "
        'ProcessCommandLine =~ "definitely not malware" and '
        'AccountName =~ "heyitsmeyourbrother" and '
        "ProcessIntegrityLevel == 1 and "
        'SHA1 =~ "a123123123" and '
        'SHA256 =~ "a123123123" and '
        'MD5 =~ "a123123123" and '
        "InitiatingProcessId == 1 and "
        'InitiatingProcessFolderPath =~ "C:\\\\Windows\\\\Temp\\\\freemoney.pdf" and '
        'InitiatingProcessCommandLine =~ "freemoney.pdf test exe please ignore" and '
        'InitiatingProcessAccountName =~ "heyitsmeyourparent"'
    ]

    assert xdr_backend.convert(SigmaCollection.from_yaml(yaml_rule)) == expected_result
    assert xdr_backend.convert_rule(SigmaRule.from_yaml(yaml_rule)) == expected_result


def test_microsoft_xdr_image_load_field_mapping(xdr_backend):
    yaml_rule = """
        title: Test
        status: test
        logsource:
            category: image_load
            product: windows
        detection:
            sel:
                ProcessId: 1
                Image: C:\\Temp\\notmalware.exe
                ImageLoaded: C:\\Temp\\definitelynotmalware.exe
                FileVersion: 1
                Description: A Description
                Product: A Product
                Company: AttackIQ
                OriginalFileName: freemoney.pdf.exe
                md5: e708864855f3bb69c4d9a213b9108b9f
                sha1: 00ea1da4192a2030f9ae023de3b3143ed647bbab
                sha256: 6bbb0da1891646e58eb3e6a63af3a6fc3c8eb5a0d44824cba581d2e14a0450cf
                User: username
            condition: sel
    """
    expected_result = [
        "DeviceImageLoadEvents\n| "
        'where InitiatingProcessId == 1 and InitiatingProcessFolderPath =~ "C:\\\\Temp\\\\notmalware.exe" and '
        'FolderPath =~ "C:\\\\Temp\\\\definitelynotmalware.exe" and InitiatingProcessVersionInfoProductVersion == 1 '
        'and InitiatingProcessVersionInfoFileDescription =~ "A Description" and '
        'InitiatingProcessVersionInfoProductName =~ "A Product" and '
        'InitiatingProcessVersionInfoCompanyName =~ "AttackIQ" and '
        'InitiatingProcessVersionInfoOriginalFileName =~ "freemoney.pdf.exe" and '
        'MD5 =~ "e708864855f3bb69c4d9a213b9108b9f" and SHA1 =~ "00ea1da4192a2030f9ae023de3b3143ed647bbab" and '
        'SHA256 =~ "6bbb0da1891646e58eb3e6a63af3a6fc3c8eb5a0d44824cba581d2e14a0450cf" and '
        'InitiatingProcessAccountName =~ "username"'
    ]

    assert xdr_backend.convert(SigmaCollection.from_yaml(yaml_rule)) == expected_result
    assert xdr_backend.convert_rule(SigmaRule.from_yaml(yaml_rule)) == expected_result


def test_microsoft_xdr_file_event_field_mapping(xdr_backend):
    yaml_rule = """
        title: Test
        status: test
        logsource:
            category: file_event
            product: windows
        detection:
            sel:
                ProcessId: 1
                Image: C:\\Path\\To\\process.exe
                TargetFilename: C:\\Temp\\passwords.txt
                User: username
                md5: e708864855f3bb69c4d9a213b9108b9f
                sha1: 00ea1da4192a2030f9ae023de3b3143ed647bbab
                sha256: 6bbb0da1891646e58eb3e6a63af3a6fc3c8eb5a0d44824cba581d2e14a0450cf
            condition: sel
    """
    expected_result = [
        "DeviceFileEvents\n| "
        'where InitiatingProcessId == 1 and InitiatingProcessFolderPath =~ "C:\\\\Path\\\\To\\\\process.exe" and '
        'FolderPath =~ "C:\\\\Temp\\\\passwords.txt" and RequestAccountName =~ "username" and '
        'MD5 =~ "e708864855f3bb69c4d9a213b9108b9f" and SHA1 =~ "00ea1da4192a2030f9ae023de3b3143ed647bbab" and '
        'SHA256 =~ "6bbb0da1891646e58eb3e6a63af3a6fc3c8eb5a0d44824cba581d2e14a0450cf"'
    ]

    assert xdr_backend.convert(SigmaCollection.from_yaml(yaml_rule)) == expected_result
    assert xdr_backend.convert_rule(SigmaRule.from_yaml(yaml_rule)) == expected_result


def test_microsoft_xdr_registry_event_field_mapping(xdr_backend):
    yaml_rule = """
        title: Test
        status: test
        logsource:
            category: registry_set
            product: windows
        detection:
            sel:
                EventType: CreateKey
                ProcessId: 1
                Image: C:\\Temp\\reg.exe
                TargetObject: HKEY_LOCAL_MACHINE\\SYSTEM\\ControlSet001\\services\\TrustedInstaller
                Details: attackiq
                User: username
            condition: sel
    """
    expected_result = [
        "DeviceRegistryEvents\n| "
        'where ActionType =~ "RegistryKeyCreated" and InitiatingProcessId == 1 and '
        'InitiatingProcessFolderPath =~ "C:\\\\Temp\\\\reg.exe" and '
        'RegistryKey =~ "HKEY_LOCAL_MACHINE\\\\SYSTEM\\\\ControlSet001\\\\services\\\\TrustedInstaller" and '
        'RegistryValueData =~ "attackiq" and InitiatingProcessAccountName =~ "username"'
    ]

    assert xdr_backend.convert(SigmaCollection.from_yaml(yaml_rule)) == expected_result
    assert xdr_backend.convert_rule(SigmaRule.from_yaml(yaml_rule)) == expected_result


def test_microsoft_xdr_network_connection_field_mapping(xdr_backend):
    yaml_rule = """
        title: Test
        status: test
        logsource:
            category: network_connection
            product: windows
        detection:
            sel:
                ProcessId: 1
                Image: C:\\Temp\\notcobaltstrike.exe
                User: admin
                Protocol: TCP
                SourceIp: 127.0.0.1
                SourcePort: 12345
                DestinationIp: 1.2.3.4
                DestinationPort: 50050
                DestinationHostname: notanatp.net
            condition: sel
    """
    expected_result = [
        "DeviceNetworkEvents\n| "
        "where InitiatingProcessId == 1 and "
        'InitiatingProcessFolderPath =~ "C:\\\\Temp\\\\notcobaltstrike.exe" and '
        'InitiatingProcessAccountName =~ "admin" and Protocol =~ "TCP" and LocalIP =~ "127.0.0.1" and '
        'LocalPort == 12345 and RemoteIP =~ "1.2.3.4" and RemotePort == 50050 and '
        'RemoteUrl =~ "notanatp.net"'
    ]

    assert xdr_backend.convert(SigmaCollection.from_yaml(yaml_rule)) == expected_result
    assert xdr_backend.convert_rule(SigmaRule.from_yaml(yaml_rule)) == expected_result


def test_microsoft_xdr_network_connection_cidr(xdr_backend):
    yaml_rule = """
        title: Test
        status: test
        logsource:
            category: network_connection
            product: windows
        detection:
            sel:
                SourceIp|cidr: '10.10.0.0/24'
                DestinationIp|cidr: '10.11.0.0/24'
            condition: sel
    """
    expected_result = [
        "DeviceNetworkEvents\n| "
        'where ipv4_is_in_range(LocalIP, "10.10.0.0/24") and ipv4_is_in_range(RemoteIP, "10.11.0.0/24")'
    ]

    assert xdr_backend.convert(SigmaCollection.from_yaml(yaml_rule)) == expected_result
    assert xdr_backend.convert_rule(SigmaRule.from_yaml(yaml_rule)) == expected_result


def test_microsoft_xdr_pipeline_registrykey_replacements(xdr_backend):
    yaml_rule = """
        title: Test
        status: test
        logsource:
            category: registry_event
            product: windows
        detection:
            sel1:
                RegistryKey: HKLM\\TestKey1
                PreviousRegistryKey: HKLM\\TestKey1
            sel2:
                RegistryKey: HKU\\TestKey2
                PreviousRegistryKey: HKU\\TestKey2
            sel3:
                RegistryKey: HKLM\\System\\CurrentControlSet\\TestKey3
                PreviousRegistryKey: HKLM\\System\\CurrentControlSet\\TestKey3
            sel4:
                RegistryKey: hkcr\\TestKey4
                PreviousRegistryKey: hkcr\\TestKey4
            condition: any of sel*
    """
    expected_result = [
        'DeviceRegistryEvents\n| where (RegistryKey =~ "HKEY_LOCAL_MACHINE\\\\TestKey1" and '
        'PreviousRegistryKey =~ "HKEY_LOCAL_MACHINE\\\\TestKey1") or '
        '(RegistryKey =~ "HKEY_USERS\\\\TestKey2" and PreviousRegistryKey =~ "HKEY_USERS\\\\TestKey2") or '
        '(RegistryKey =~ "HKEY_LOCAL_MACHINE\\\\SYSTEM\\\\CurrentControlSet001\\\\TestKey3" and PreviousRegistryKey =~ "HKEY_LOCAL_MACHINE\\\\SYSTEM\\\\CurrentControlSet001\\\\TestKey3") or '
        '(RegistryKey =~ "HKEY_LOCAL_MACHINE\\\\CLASSES\\\\TestKey4" and PreviousRegistryKey =~ "HKEY_LOCAL_MACHINE\\\\CLASSES\\\\TestKey4")'
    ]

    assert xdr_backend.convert(SigmaCollection.from_yaml(yaml_rule)) == expected_result
    assert xdr_backend.convert_rule(SigmaRule.from_yaml(yaml_rule)) == expected_result


def test_microsoft_xdr_pipeline_registry_actiontype_replacements(xdr_backend):
    yaml_rule = """
        title: Test
        status: test
        logsource:
            category: registry_event
            product: windows
        detection:
            sel1:
                ActionType: CreateKey
            sel2:
                ActionType: DeleteKey
            sel3:
                ActionType: SetValue
            sel4:
                ActionType: RenameKey
            condition: any of sel*
    """
    expected_result = [
        "DeviceRegistryEvents\n| "
        'where ActionType =~ "RegistryKeyCreated" or '
        '(ActionType in~ ("RegistryKeyDeleted", "RegistryValueDeleted")) or '
        'ActionType =~ "RegistryValueSet" or '
        '(ActionType in~ ("RegistryValueSet", "RegistryKeyCreated"))'
    ]

    assert xdr_backend.convert(SigmaCollection.from_yaml(yaml_rule)) == expected_result
    assert xdr_backend.convert_rule(SigmaRule.from_yaml(yaml_rule)) == expected_result


def test_microsoft_xdr_pipeline_valid_hash_in_list(xdr_backend):
    yaml_rule = """
        title: test
        status: test
        logsource:
            category: process_creation
            product: windows
        detection:
            sel:
                Hashes: 
                    - MD5=6444f8a34e99b8f7d9647de66aabe516
                    - IMPHASH=dfd6aa3f7b2b1035b76b718f1ddc689f
                    - IMPHASH=1a6cca4d5460b1710a12dea39e4a592c
            condition: sel
    """
    expected_result = ["DeviceProcessEvents\n| " 'where MD5 =~ "6444f8a34e99b8f7d9647de66aabe516"']

    assert xdr_backend.convert(SigmaCollection.from_yaml(yaml_rule)) == expected_result
    assert xdr_backend.convert_rule(SigmaRule.from_yaml(yaml_rule)) == expected_result


def test_microsoft_xdr_pipeline_generic_field(xdr_backend):
    yaml_rule = """
        title: Test
        status: test
        logsource:
            category: file_event
            product: windows
        detection:
            sel1:
                CommandLine: whoami
                ProcessId: 1  
            condition: any of sel*
    """
    expected_result = [
        "DeviceFileEvents\n| " 'where InitiatingProcessCommandLine =~ "whoami" and InitiatingProcessId == 1'
    ]

    assert xdr_backend.convert(SigmaCollection.from_yaml(yaml_rule)) == expected_result
    assert xdr_backend.convert_rule(SigmaRule.from_yaml(yaml_rule)) == expected_result


def test_microsoft_xdr_pipeline_parent_image(xdr_backend):
    yaml_rule = """
        title: Test
        status: test
        logsource:
            category: file_event
            product: windows
        detection:
            sel1:
                Image: C:\\Windows\\System32\\whoami.exe
                ParentImage: C:\\Windows\\System32\\cmd.exe  
            condition: any of sel*
    """
    expected_result = [
        "DeviceFileEvents\n| "
        'where InitiatingProcessFolderPath =~ "C:\\\\Windows\\\\System32\\\\whoami.exe" and '
        'InitiatingProcessParentFileName =~ "cmd.exe"'
    ]

    assert xdr_backend.convert(SigmaCollection.from_yaml(yaml_rule)) == expected_result
    assert xdr_backend.convert_rule(SigmaRule.from_yaml(yaml_rule)) == expected_result


def test_microsoft_xdr_pipeline_parent_image_false(xdr_backend):
    yaml_rule = """
        title: Test
        status: test
        logsource:
            category: file_event
            product: windows
        detection:
            sel1:
                Image: C:\\Windows\\System32\\whoami.exe
                ParentImage: C:\\Windows\\System32\\cmd.exe  
            condition: any of sel*
    """
    with pytest.raises(
        SigmaTransformationError, match="Invalid SigmaDetectionItem field name encountered.*DeviceFileEvents"
    ):
        KustoBackend(processing_pipeline=microsoft_xdr_pipeline(transform_parent_image=False)).convert(
            SigmaCollection.from_yaml(yaml_rule)
        )


def test_microsoft_xdr_pipeline_unsupported_rule_type(xdr_backend):
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
        xdr_backend.convert(SigmaCollection.from_yaml(yaml_rule))


def test_microsoft_xdr_pipeline_unsupported_field_process_creation(xdr_backend):
    yaml_rule = """
        title: test
        status: test
        logsource:
            category: process_creation
            product: windows
        detection:
            sel:
                CommandLine: whatever
                InvalidField: forever
            condition: sel
    """
    with pytest.raises(
        SigmaTransformationError, match="Invalid SigmaDetectionItem field name encountered.*DeviceProcessEvents"
    ):
        xdr_backend.convert(SigmaCollection.from_yaml(yaml_rule))


def test_microsoft_xdr_pipeline_unsupported_field_file_event(xdr_backend):
    yaml_rule = """
        title: test
        status: test
        logsource:
            category: file_access
            product: windows
        detection:
            sel:
                FileName: whatever
                InvalidField: forever
            condition: sel
    """
    with pytest.raises(
        SigmaTransformationError, match="Invalid SigmaDetectionItem field name encountered.*DeviceFileEvents"
    ):
        xdr_backend.convert(SigmaCollection.from_yaml(yaml_rule))


def test_microsoft_xdr_pipeline_unsupported_field_image_load(xdr_backend):
    yaml_rule = """
        title: test
        status: test
        logsource:
            category: image_load
            product: windows
        detection:
            sel:
                CommandLine: whatever
                InvalidField: forever
            condition: sel
    """
    with pytest.raises(
        SigmaTransformationError, match="Invalid SigmaDetectionItem field name encountered.*DeviceImageLoadEvents"
    ):
        xdr_backend.convert(SigmaCollection.from_yaml(yaml_rule))


def test_microsoft_xdr_pipeline_unsupported_field_registry_event(xdr_backend):
    yaml_rule = """
        title: test
        status: test
        logsource:
            category: registry_add
            product: windows
        detection:
            sel:
                CommandLine: whatever
                InvalidField: forever
            condition: sel
    """
    with pytest.raises(
        SigmaTransformationError, match="Invalid SigmaDetectionItem field name encountered.*DeviceRegistryEvents"
    ):
        xdr_backend.convert(SigmaCollection.from_yaml(yaml_rule))


def test_microsoft_xdr_pipeline_unsupported_field_network_connection(xdr_backend):
    yaml_rule = """
        title: test
        status: test
        logsource:
            category: network_connection
            product: windows
        detection:
            sel:
                CommandLine: whatever
                InvalidField: forever
            condition: sel
    """
    with pytest.raises(
        SigmaTransformationError, match="Invalid SigmaDetectionItem field name encountered.*DeviceNetworkEvents"
    ):
        xdr_backend.convert(SigmaCollection.from_yaml(yaml_rule))


def test_microsoft_xdr_pipeline_no_valid_hashes(xdr_backend):
    yaml_rule = """
        title: test
        status: test
        logsource:
            category: network_connection
            product: windows
        detection:
            sel:
                Hashes: 
                    - IMPHASH=6444f8a34e99b8f7d9647de66aabe516
                    - IMPHASH=dfd6aa3f7b2b1035b76b718f1ddc689f
                    - IMPHASH=1a6cca4d5460b1710a12dea39e4a592c
            condition: sel
    """
    with pytest.raises(InvalidHashAlgorithmError):
        xdr_backend.convert(SigmaCollection.from_yaml(yaml_rule))


def test_microsoft_xdr_pipeline_custom_table(xdr_backend):
    yaml_rule = """
        title: Test
        status: test
        logsource:
            category: process_creation
            product: windows
        detection:
            sel:
                Image: actuallyafileevent.exe
            condition: sel
    """
    expected_result = ["DeviceFileEvents\n| " 'where InitiatingProcessFolderPath =~ "actuallyafileevent.exe"']

    assert (
        KustoBackend(processing_pipeline=microsoft_xdr_pipeline(query_table="DeviceFileEvents")).convert(
            SigmaCollection.from_yaml(yaml_rule)
        )
        == expected_result
    )


def test_microsoft_xdr_pipeline_custom_table_invalid_category(xdr_backend):
    yaml_rule = """
        title: Test
        status: test
        logsource:
            product: windows
        detection:
            sel:
                Image: actuallyafileevent.exe
            condition: sel
    """
    expected_result = ["DeviceFileEvents\n| " 'where InitiatingProcessFolderPath =~ "actuallyafileevent.exe"']

    assert (
        KustoBackend(processing_pipeline=microsoft_xdr_pipeline(query_table="DeviceFileEvents")).convert(
            SigmaCollection.from_yaml(yaml_rule)
        )
        == expected_result
    )


def test_microsoft_xdr_pipeline_SigmaNumbers(xdr_backend):
    yaml_rule = r"""
title: Azure AD Health Monitoring Agent Registry Keys Access
id: ff151c33-45fa-475d-af4f-c2f93571f4fe
status: test
description: |
    This detection uses Windows security events to detect suspicious access attempts to the registry key of Azure AD Health monitoring agent.
    This detection requires an access control entry (ACE) on the system access control list (SACL) of the following securable object HKLM\SOFTWARE\Microsoft\Microsoft Online\Reporting\MonitoringAgent.
references:
    - https://o365blog.com/post/hybridhealthagent/
    - https://github.com/OTRF/Set-AuditRule/blob/c3dec5443414231714d850565d364ca73475ade5/rules/registry/aad_connect_health_monitoring_agent.yml
author: Roberto Rodriguez (Cyb3rWard0g), OTR (Open Threat Research), MSTIC
date: 2021-08-26
modified: 2022-10-09
tags:
    - attack.discovery
    - attack.t1012
logsource:
    product: windows
    service: security
detection:
    selection:
        EventID:
            - 4656
            - 4663
        ObjectType: 'Key'
        ObjectName: '\REGISTRY\MACHINE\SOFTWARE\Microsoft\Microsoft Online\Reporting\MonitoringAgent'
    filter:
        ProcessName|contains:
            - 'Microsoft.Identity.Health.Adfs.DiagnosticsAgent.exe'
            - 'Microsoft.Identity.Health.Adfs.InsightsService.exe'
            - 'Microsoft.Identity.Health.Adfs.MonitoringAgent.Startup.exe'
            - 'Microsoft.Identity.Health.Adfs.PshSurrogate.exe'
            - 'Microsoft.Identity.Health.Common.Clients.ResourceMonitor.exe'
    condition: selection and not filter
falsepositives:
    - Unknown
level: medium
"""

    expected_result = [
        r"""DeviceRegistryEvents
| where RegistryKey =~ "\\REGISTRY\\MACHINE\\SOFTWARE\\Microsoft\\Microsoft Online\\Reporting\\MonitoringAgent" and (not((InitiatingProcessFolderPath contains "Microsoft.Identity.Health.Adfs.DiagnosticsAgent.exe" or InitiatingProcessFolderPath contains "Microsoft.Identity.Health.Adfs.InsightsService.exe" or InitiatingProcessFolderPath contains "Microsoft.Identity.Health.Adfs.MonitoringAgent.Startup.exe" or InitiatingProcessFolderPath contains "Microsoft.Identity.Health.Adfs.PshSurrogate.exe" or InitiatingProcessFolderPath contains "Microsoft.Identity.Health.Common.Clients.ResourceMonitor.exe")))"""
    ]

    assert xdr_backend.convert(SigmaCollection.from_yaml(yaml_rule)) == expected_result
    assert xdr_backend.convert_rule(SigmaRule.from_yaml(yaml_rule)) == expected_result


def test_microsoft_xdr_eventid_mapping(xdr_backend):
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
    # EventID 1 should map to process_creation category -> DeviceProcessEvents table
    expected_result = ['DeviceProcessEvents\n| where FolderPath =~ "C:\\\\Windows\\\\System32\\\\cmd.exe"']

    assert xdr_backend.convert(SigmaCollection.from_yaml(yaml_rule)) == expected_result
    assert xdr_backend.convert_rule(SigmaRule.from_yaml(yaml_rule)) == expected_result


def test_microsoft_xdr_category_precedence(xdr_backend):
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
    # Should use DeviceFileEvents table based on category, not DeviceProcessEvents from EventID
    expected_result = [
        'DeviceFileEvents\n| where InitiatingProcessFolderPath =~ "C:\\\\Windows\\\\System32\\\\cmd.exe"'
    ]

    assert xdr_backend.convert(SigmaCollection.from_yaml(yaml_rule)) == expected_result
    assert xdr_backend.convert_rule(SigmaRule.from_yaml(yaml_rule)) == expected_result
