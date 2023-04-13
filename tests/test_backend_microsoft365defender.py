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
    ) == ['DeviceProcessEvents\n| where ProcessCommandLine has_any ("valueA1", "valueA2") and '
          'ProcessId has_any ("valueB1", "valueB2")']


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
    ) == ['DeviceProcessEvents\n| where ProcessCommandLine has_any ("valueA", "valueB") or '
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
