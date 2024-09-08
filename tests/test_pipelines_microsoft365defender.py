import pytest
from sigma.exceptions import SigmaTransformationError
from sigma.pipelines.microsoft365defender.microsoft365defender import InvalidHashAlgorithmError

from sigma.backends.kusto import KustoBackend
from sigma.collection import SigmaCollection
from sigma.pipelines.microsoft365defender import microsoft_365_defender_pipeline


def test_microsoft_365_defender_username_transformation():
    """Tests splitting username up into different fields if it includes a domain"""
    assert KustoBackend(processing_pipeline=microsoft_365_defender_pipeline()).convert(
        SigmaCollection.from_yaml("""
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
            """)
    ) == ['DeviceProcessEvents\n| '
          'where (ProcessCommandLine =~ "command1" and AccountName =~ "username1") or '
          '(ProcessCommandLine =~ "command2" and (AccountName =~ "username2" and AccountDomain =~ "domain2")) or '
          '(ProcessCommandLine =~ "command3" and (InitiatingProcessAccountName =~ "username3" or '
          '(InitiatingProcessAccountName =~ "username4" and InitiatingProcessAccountDomain =~ "domain4"))) or '
          'AccountName =~ "username5"']


def test_microsoft_365_defender_hashes_values_transformation():
    """Test for getting hash algo/value from Hashes field and creating new detection items from them"""
    assert KustoBackend(processing_pipeline=microsoft_365_defender_pipeline()).convert(
        SigmaCollection.from_yaml("""
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
            """)
    ) == ['DeviceProcessEvents\n'
          '| where (MD5 =~ "e708864855f3bb69c4d9a213b9108b9f" or SHA1 =~ "00ea1da4192a2030f9ae023de3b3143ed647bbab" '
          'or SHA256 =~ "6bbb0da1891646e58eb3e6a63af3a6fc3c8eb5a0d44824cba581d2e14a0450cf") or '
          '(MD5 =~ "0b49939d6415354c950b142a0b1e696a" or SHA1 =~ "4b2b79b6f371ca18f1216461cffeaddf6848a50e" or '
          'SHA256 =~ "8f16f88cfa1cf0d17c75403aa9614d806ebc00419763e0ecac3860decbcd9988")']


def test_microsoft_365_defender_process_creation_simple():
    assert KustoBackend(processing_pipeline=microsoft_365_defender_pipeline()).convert(
        SigmaCollection.from_yaml("""
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
        """)
    ) == ['DeviceProcessEvents\n| where ProcessCommandLine =~ "val1" and FolderPath =~ "val2"']


def test_microsoft_365_defender_image_load_simple():
    assert KustoBackend(processing_pipeline=microsoft_365_defender_pipeline()).convert(
        SigmaCollection.from_yaml("""
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
        """)
    ) == ['DeviceImageLoadEvents\n| where FolderPath =~ "val1" and SHA1 =~ "val2"']


def test_microsoft_365_defender_file_access_simple():
    assert KustoBackend(processing_pipeline=microsoft_365_defender_pipeline()).convert(
        SigmaCollection.from_yaml("""
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
        """)
    ) == ['DeviceFileEvents\n| where FolderPath =~ "val1" and InitiatingProcessFolderPath =~ "val2"']


def test_microsoft_365_defender_file_change_simple():
    assert KustoBackend(processing_pipeline=microsoft_365_defender_pipeline()).convert(
        SigmaCollection.from_yaml("""
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
        """)
    ) == ['DeviceFileEvents\n| where FolderPath =~ "val1" and InitiatingProcessFolderPath =~ "val2"']


def test_microsoft_365_defender_file_delete_simple():
    assert KustoBackend(processing_pipeline=microsoft_365_defender_pipeline()).convert(
        SigmaCollection.from_yaml("""
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
        """)
    ) == ['DeviceFileEvents\n| where FolderPath =~ "val1" and InitiatingProcessFolderPath =~ "val2"']


def test_microsoft_365_defender_file_event_simple():
    assert KustoBackend(processing_pipeline=microsoft_365_defender_pipeline()).convert(
        SigmaCollection.from_yaml("""
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
        """)
    ) == ['DeviceFileEvents\n| where FolderPath =~ "val1" and InitiatingProcessFolderPath =~ "val2"']


def test_microsoft_365_defender_file_rename_simple():
    assert KustoBackend(processing_pipeline=microsoft_365_defender_pipeline()).convert(
        SigmaCollection.from_yaml("""
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
        """)
    ) == ['DeviceFileEvents\n| where FolderPath =~ "val1" and InitiatingProcessFolderPath =~ "val2"']


def test_microsoft_365_defender_registry_add_simple():
    assert KustoBackend(processing_pipeline=microsoft_365_defender_pipeline()).convert(
        SigmaCollection.from_yaml("""
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
        """)
    ) == ['DeviceRegistryEvents\n| where InitiatingProcessFolderPath =~ "val1" and RegistryKey =~ "val2"']


def test_microsoft_365_defender_registry_delete_simple():
    assert KustoBackend(processing_pipeline=microsoft_365_defender_pipeline()).convert(
        SigmaCollection.from_yaml("""
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
        """)
    ) == ['DeviceRegistryEvents\n| where InitiatingProcessFolderPath =~ "val1" and RegistryKey =~ "val2"']


def test_microsoft_365_defender_registry_event_simple():
    assert KustoBackend(processing_pipeline=microsoft_365_defender_pipeline()).convert(
        SigmaCollection.from_yaml("""
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
        """)
    ) == ['DeviceRegistryEvents\n| where InitiatingProcessFolderPath =~ "val1" and RegistryKey =~ "val2"']


def test_microsoft_365_defender_registry_set_simple():
    assert KustoBackend(processing_pipeline=microsoft_365_defender_pipeline()).convert(
        SigmaCollection.from_yaml("""
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
        """)
    ) == ['DeviceRegistryEvents\n| where InitiatingProcessFolderPath =~ "val1" and RegistryKey =~ "val2"']


def test_microsoft_365_defender_process_creation_field_mapping():
    assert KustoBackend(processing_pipeline=microsoft_365_defender_pipeline()).convert(
        SigmaCollection.from_yaml("""
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
            """)
    ) == ['DeviceProcessEvents\n| '
          'where FolderPath =~ "C:\\\\Path\\\\to\\\\notmalware.exe" and '
          'ProcessVersionInfoProductVersion == 1 and '
          'ProcessVersionInfoFileDescription =~ "A Description" and '
          'ProcessVersionInfoProductName =~ "pySigma" and '
          'ProcessVersionInfoCompanyName =~ "AttackIQ" and '
          'ProcessVersionInfoOriginalFileName =~ "malware.exe" and '
          'ProcessId == 2 and '
          'ProcessCommandLine =~ "definitely not malware" and '
          'AccountName =~ "heyitsmeyourbrother" and '
          'ProcessIntegrityLevel == 1 and '
          'SHA1 =~ "a123123123" and '
          'SHA256 =~ "a123123123" and '
          'MD5 =~ "a123123123" and '
          'InitiatingProcessId == 1 and '
          'InitiatingProcessFolderPath =~ "C:\\\\Windows\\\\Temp\\\\freemoney.pdf" and '
          'InitiatingProcessCommandLine =~ "freemoney.pdf test exe please ignore" and '
          'InitiatingProcessAccountName =~ "heyitsmeyourparent"']


def test_microsoft_365_defender_image_load_field_mapping():
    assert KustoBackend(processing_pipeline=microsoft_365_defender_pipeline()).convert(
        SigmaCollection.from_yaml("""
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
            """)
    ) == ['DeviceImageLoadEvents\n| '
          'where InitiatingProcessId == 1 and InitiatingProcessFolderPath =~ "C:\\\\Temp\\\\notmalware.exe" and '
          'FolderPath =~ "C:\\\\Temp\\\\definitelynotmalware.exe" and InitiatingProcessVersionInfoProductVersion == 1 '
          'and InitiatingProcessVersionInfoFileDescription =~ "A Description" and '
          'InitiatingProcessVersionInfoProductName =~ "A Product" and '
          'InitiatingProcessVersionInfoCompanyName =~ "AttackIQ" and '
          'InitiatingProcessVersionInfoOriginalFileName =~ "freemoney.pdf.exe" and '
          'MD5 =~ "e708864855f3bb69c4d9a213b9108b9f" and SHA1 =~ "00ea1da4192a2030f9ae023de3b3143ed647bbab" and '
          'SHA256 =~ "6bbb0da1891646e58eb3e6a63af3a6fc3c8eb5a0d44824cba581d2e14a0450cf" and '
          'InitiatingProcessAccountName =~ "username"']


def test_microsoft_365_defender_file_event_field_mapping():
    assert KustoBackend(processing_pipeline=microsoft_365_defender_pipeline()).convert(
        SigmaCollection.from_yaml("""
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
            """)
    ) == ['DeviceFileEvents\n| '
          'where InitiatingProcessId == 1 and InitiatingProcessFolderPath =~ "C:\\\\Path\\\\To\\\\process.exe" and '
          'FolderPath =~ "C:\\\\Temp\\\\passwords.txt" and RequestAccountName =~ "username" and '
          'MD5 =~ "e708864855f3bb69c4d9a213b9108b9f" and SHA1 =~ "00ea1da4192a2030f9ae023de3b3143ed647bbab" and '
          'SHA256 =~ "6bbb0da1891646e58eb3e6a63af3a6fc3c8eb5a0d44824cba581d2e14a0450cf"']


def test_microsoft_365_defender_registry_event_field_mapping():
    assert KustoBackend(processing_pipeline=microsoft_365_defender_pipeline()).convert(
        SigmaCollection.from_yaml("""
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
            """)
    ) == ['DeviceRegistryEvents\n| '
          'where ActionType =~ "RegistryKeyCreated" and InitiatingProcessId == 1 and '
          'InitiatingProcessFolderPath =~ "C:\\\\Temp\\\\reg.exe" and '
          'RegistryKey =~ "HKEY_LOCAL_MACHINE\\\\SYSTEM\\\\ControlSet001\\\\services\\\\TrustedInstaller" and '
          'RegistryValueData =~ "attackiq" and InitiatingProcessAccountName =~ "username"']


def test_microsoft_365_defender_network_connection_field_mapping():
    assert KustoBackend(processing_pipeline=microsoft_365_defender_pipeline()).convert(
        SigmaCollection.from_yaml("""
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
            """)
    ) == ['DeviceNetworkEvents\n| '
          'where InitiatingProcessId == 1 and '
          'InitiatingProcessFolderPath =~ "C:\\\\Temp\\\\notcobaltstrike.exe" and '
          'InitiatingProcessAccountName =~ "admin" and Protocol =~ "TCP" and LocalIP =~ "127.0.0.1" and '
          'LocalPort == 12345 and RemoteIP =~ "1.2.3.4" and RemotePort == 50050 and '
          'RemoteUrl =~ "notanatp.net"']


def test_microsoft_365_defender_network_connection_cidr():
    assert KustoBackend(processing_pipeline=microsoft_365_defender_pipeline()).convert(
        SigmaCollection.from_yaml("""
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
            """)
    ) == ['DeviceNetworkEvents\n| '
          'where ipv4_is_in_range(LocalIP, "10.10.0.0/24") and ipv4_is_in_range(RemoteIP, "10.11.0.0/24")']


def test_microsoft_365_defender_pipeline_registrykey_replacements():
    assert KustoBackend(processing_pipeline=microsoft_365_defender_pipeline()).convert(
        SigmaCollection.from_yaml("""
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
        """)
    ) == [
               'DeviceRegistryEvents\n| where (RegistryKey =~ "HKEY_LOCAL_MACHINE\\\\TestKey1" and '
               'PreviousRegistryKey =~ "HKEY_LOCAL_MACHINE\\\\TestKey1") or '
               '(RegistryKey =~ "HKEY_USERS\\\\TestKey2" and PreviousRegistryKey =~ "HKEY_USERS\\\\TestKey2") or '
               '(RegistryKey =~ "HKEY_LOCAL_MACHINE\\\\SYSTEM\\\\CurrentControlSet001\\\\TestKey3" and PreviousRegistryKey =~ "HKEY_LOCAL_MACHINE\\\\SYSTEM\\\\CurrentControlSet001\\\\TestKey3") or '
               '(RegistryKey =~ "HKEY_LOCAL_MACHINE\\\\CLASSES\\\\TestKey4" and PreviousRegistryKey =~ "HKEY_LOCAL_MACHINE\\\\CLASSES\\\\TestKey4")']


def test_microsoft_365_defender_pipeline_registry_actiontype_replacements():
    assert KustoBackend(processing_pipeline=microsoft_365_defender_pipeline()).convert(
        SigmaCollection.from_yaml("""
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
        """)
    ) == [
               'DeviceRegistryEvents\n| '
               'where ActionType =~ "RegistryKeyCreated" or '
               '(ActionType in~ ("RegistryKeyDeleted", "RegistryValueDeleted")) or '
               'ActionType =~ "RegistryValueSet" or '
               '(ActionType in~ ("RegistryValueSet", "RegistryKeyCreated"))']


def test_microsoft_365_defender_pipeline_valid_hash_in_list():
    assert KustoBackend(processing_pipeline=microsoft_365_defender_pipeline()).convert(
            SigmaCollection.from_yaml("""
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
            """)
        ) == [ 'DeviceProcessEvents\n| ' 
               'where MD5 =~ "6444f8a34e99b8f7d9647de66aabe516"']



def test_microsoft_365_defender_pipeline_generic_field():
    """Tests"""
    assert KustoBackend(processing_pipeline=microsoft_365_defender_pipeline()).convert(
        SigmaCollection.from_yaml("""
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
            """)
    ) == [
               'DeviceFileEvents\n| '
               'where InitiatingProcessCommandLine =~ "whoami" and InitiatingProcessId == 1']


def test_microsoft_365_defender_pipeline_parent_image():
    """Tests ParentImage for non-process-creation rules"""
    assert KustoBackend(processing_pipeline=microsoft_365_defender_pipeline()).convert(
        SigmaCollection.from_yaml("""
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
            """)
    ) == [
               'DeviceFileEvents\n| '
               'where InitiatingProcessFolderPath =~ "C:\\\\Windows\\\\System32\\\\whoami.exe" and '
               'InitiatingProcessParentFileName =~ "cmd.exe"']


def test_microsoft_365_defender_pipeline_parent_image_false():
    """Tests passing transfer_parent_image=False to the pipeline"""
    with pytest.raises(SigmaTransformationError,
                       match="Invalid SigmaDetectionItem field name encountered.*DeviceFileEvents"):
        KustoBackend(processing_pipeline=microsoft_365_defender_pipeline(transform_parent_image=False)).convert(
            SigmaCollection.from_yaml("""
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
                """)
        )


def test_microsoft_365_defender_pipeline_unsupported_rule_type():
    with pytest.raises(SigmaTransformationError,
                       match="Rule category not yet supported by the Microsoft 365 Defender Sigma backend."):
        KustoBackend(processing_pipeline=microsoft_365_defender_pipeline()).convert(
            SigmaCollection.from_yaml("""
                title: test
                status: test
                logsource:
                    category: invalid_category
                    product: invalid_product
                detection:
                    sel:
                        field: whatever
                    condition: sel
            """)
        )


def test_microsoft_365_defender_pipeline_unsupported_field_process_creation():
    with pytest.raises(SigmaTransformationError,
                       match="Invalid SigmaDetectionItem field name encountered.*DeviceProcessEvents"):
        KustoBackend(processing_pipeline=microsoft_365_defender_pipeline()).convert(
            SigmaCollection.from_yaml("""
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
            """)
        )


def test_microsoft_365_defender_pipeline_unsupported_field_file_event():
    with pytest.raises(SigmaTransformationError,
                       match="Invalid SigmaDetectionItem field name encountered.*DeviceFileEvents"):
        KustoBackend(processing_pipeline=microsoft_365_defender_pipeline()).convert(
            SigmaCollection.from_yaml("""
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
            """)
        )


def test_microsoft_365_defender_pipeline_unsupported_field_image_load():
    with pytest.raises(SigmaTransformationError,
                       match="Invalid SigmaDetectionItem field name encountered.*DeviceImageLoadEvents"):
        KustoBackend(processing_pipeline=microsoft_365_defender_pipeline()).convert(
            SigmaCollection.from_yaml("""
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
            """)
        )


def test_microsoft_365_defender_pipeline_unsupported_field_registry_event():
    with pytest.raises(SigmaTransformationError,
                       match="Invalid SigmaDetectionItem field name encountered.*DeviceRegistryEvents"):
        KustoBackend(processing_pipeline=microsoft_365_defender_pipeline()).convert(
            SigmaCollection.from_yaml("""
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
            """)
        )


def test_microsoft_365_defender_pipeline_unsupported_field_network_connection():
    with pytest.raises(SigmaTransformationError,
                       match="Invalid SigmaDetectionItem field name encountered.*DeviceNetworkEvents"):
        KustoBackend(processing_pipeline=microsoft_365_defender_pipeline()).convert(
            SigmaCollection.from_yaml("""
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
            """)
        )

def test_microsoft_365_defender_pipeline_no_valid_hashes():
    with pytest.raises(InvalidHashAlgorithmError):
        KustoBackend(processing_pipeline=microsoft_365_defender_pipeline()).convert(
            SigmaCollection.from_yaml("""
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
            """)
        )

