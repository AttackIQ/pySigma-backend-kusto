import pytest
from sigma.collection import SigmaCollection
from sigma.backends.microsoft365defender import Microsoft365DefenderBackend


@pytest.fixture
def microsoft365defender_backend():
    return Microsoft365DefenderBackend()


def test_microsoft365defender_and_expression(microsoft365defender_backend: Microsoft365DefenderBackend):
    assert microsoft365defender_backend.convert(
        SigmaCollection.from_yaml("""
            title: Test
            status: test
            logsource:
                category: process_creation
                product: windows
            detection:
                sel:
                    CommandLine: valueA
                    User: valueB
                condition: sel
        """)
    ) == ['DeviceProcessEvents\n| where ProcessCommandLine =~ "valueA" and AccountName =~ "valueB"']


def test_microsoft365defender_or_expression(microsoft365defender_backend: Microsoft365DefenderBackend):
    assert microsoft365defender_backend.convert(
        SigmaCollection.from_yaml("""
            title: Test
            status: test
            logsource:
                category: process_creation
                product: windows
            detection:
                sel1:
                    CommandLine: valueA
                sel2:
                    User: valueB
                condition: 1 of sel*
        """)
    ) == ['DeviceProcessEvents\n| where ProcessCommandLine =~ "valueA" or AccountName =~ "valueB"']


def test_microsoft365defender_and_or_expression(microsoft365defender_backend: Microsoft365DefenderBackend):
    assert microsoft365defender_backend.convert(
        SigmaCollection.from_yaml("""
            title: Test
            status: test
            logsource:
                category: process_creation
                product: windows
            detection:
                sel:
                    CommandLine:
                        - valueA1
                        - valueA2
                    ProcessId:
                        - valueB1
                        - valueB2
                condition: sel
        """)
    ) == ['DeviceProcessEvents\n| where (ProcessCommandLine in~ ("valueA1", "valueA2")) and '
          '(ProcessId in~ ("valueB1", "valueB2"))']


def test_microsoft365defender_or_and_expression(microsoft365defender_backend: Microsoft365DefenderBackend):
    assert microsoft365defender_backend.convert(
        SigmaCollection.from_yaml("""
            title: Test
            status: test
            logsource:
                category: process_creation
                product: windows
            detection:
                sel1:
                    CommandLine: valueA1
                    ProcessId: valueB1
                sel2:
                    CommandLine: valueA2
                    ProcessId: valueB2
                condition: 1 of sel*
        """)
    ) == ['DeviceProcessEvents\n| where (ProcessCommandLine =~ "valueA1" and ProcessId =~ "valueB1") or '
          '(ProcessCommandLine =~ "valueA2" and ProcessId =~ "valueB2")']


def test_microsoft365defender_in_expression(microsoft365defender_backend: Microsoft365DefenderBackend):
    assert microsoft365defender_backend.convert(
        SigmaCollection.from_yaml("""
            title: Test
            status: test
            logsource:
                category: process_creation
                product: windows
            detection:
                sel:
                    CommandLine:
                        - valueA
                        - valueB
                        - valueC*
                condition: sel
        """)
    ) == ['DeviceProcessEvents\n| where ProcessCommandLine in~ ("valueA", "valueB") or '
          'ProcessCommandLine startswith "valueC"']


def test_microsoft365defender_regex_query(microsoft365defender_backend: Microsoft365DefenderBackend):
    assert microsoft365defender_backend.convert(
        SigmaCollection.from_yaml("""
            title: Test
            status: test
            logsource:
                category: process_creation
                product: windows
            detection:
                sel:
                    CommandLine|re: foo.*bar
                    ProcessId: foo
                condition: sel
        """)
    ) == ['DeviceProcessEvents\n| where ProcessCommandLine matches regex "foo.*bar" and ProcessId =~ "foo"']


def test_microsoft365defender_cidr_query(microsoft365defender_backend: Microsoft365DefenderBackend):
    assert microsoft365defender_backend.convert(
        SigmaCollection.from_yaml("""
            title: Test
            status: test
            logsource:
                category: network_connection
                product: windows
            detection:
                sel:
                    SourceIp|cidr: 192.168.0.0/16
                condition: sel
        """)
    ) == ['DeviceNetworkEvents\n| where ipv4_is_in_range(LocalIP, "192.168.0.0/16")']


def test_microsoft365defender_negation_basic(microsoft365defender_backend: Microsoft365DefenderBackend):
    assert microsoft365defender_backend.convert(
        SigmaCollection.from_yaml(r"""
            title: Test
            status: test
            logsource:
                product: windows
                category: process_creation
            detection:
                selection:
                    Image:
                        - '*\process.exe'
                    CommandLine:
                        - 'this'
                filter:
                    CommandLine:
                        - 'notthis'
                condition: selection and not filter
        """)
    ) == ['DeviceProcessEvents\n| where (FolderPath endswith "\\\\process.exe" and '
          'ProcessCommandLine =~ "this") and '
          '(not(ProcessCommandLine =~ "notthis"))']


def test_microsoft365defender_negation_contains(microsoft365defender_backend: Microsoft365DefenderBackend):
    assert microsoft365defender_backend.convert(
        SigmaCollection.from_yaml(r"""
            title: Test
            status: test
            logsource:
                product: windows
                category: process_creation
            detection:
                selection:
                    Image:
                        - '*\process.exe'
                    CommandLine:
                        - '*this*'
                filter:
                    CommandLine:
                        - '*notthis*'
                condition: selection and not filter
        """)
    ) == ['DeviceProcessEvents\n| where (FolderPath endswith "\\\\process.exe" and '
          'ProcessCommandLine contains "this") and '
          '(not(ProcessCommandLine contains "notthis"))']


def test_microsoft365defender_grouping(microsoft365defender_backend: Microsoft365DefenderBackend):
    assert microsoft365defender_backend.convert(
        SigmaCollection.from_yaml(r"""
            title: Net connection logic test
            status: test
            logsource:
                category: network_connection
                product: windows
            detection:
                selection:
                    Image:
                        - '*\powershell.exe'
                        - '*\pwsh.exe'
                    DestinationHostname: 
                        - '*pastebin.com*'
                        - '*anothersite.com*'
                condition: selection
    """)
    ) == ['DeviceNetworkEvents\n| where (InitiatingProcessFolderPath endswith "\\\\powershell.exe" or '
          'InitiatingProcessFolderPath endswith "\\\\pwsh.exe") and (RemoteUrl contains '
          '"pastebin.com" or RemoteUrl contains "anothersite.com")']
