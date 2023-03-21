import pytest
from sigma.collection import SigmaCollection
from sigma.backends.microsoft365defender import Microsoft365DefenderBackend

@pytest.fixture
def microsoft365defender_backend():
    return Microsoft365DefenderBackend()

# TODO: implement tests for some basic queries and their expected results.
def test_microsoft365defender_and_expression(microsoft365defender_backend : Microsoft365DefenderBackend):
    assert microsoft365defender_backend.convert(
        SigmaCollection.from_yaml("""
            title: Test
            status: test
            logsource:
                category: process_creation
                product: windows
            detection:
                sel:
                    fieldA: valueA
                    fieldB: valueB
                condition: sel
        """)
    ) == ['DeviceProcessEvents\n| where fieldA =~ "valueA" and fieldB =~ "valueB"']

def test_microsoft365defender_or_expression(microsoft365defender_backend : Microsoft365DefenderBackend):
    assert microsoft365defender_backend.convert(
        SigmaCollection.from_yaml("""
            title: Test
            status: test
            logsource:
                category: process_creation
                product: windows
            detection:
                sel1:
                    fieldA: valueA
                sel2:
                    fieldB: valueB
                condition: 1 of sel*
        """)
    ) == ['DeviceProcessEvents\n| where fieldA =~ "valueA" or fieldB =~ "valueB"']

def test_microsoft365defender_and_or_expression(microsoft365defender_backend : Microsoft365DefenderBackend):
    assert microsoft365defender_backend.convert(
        SigmaCollection.from_yaml("""
            title: Test
            status: test
            logsource:
                category: process_creation
                product: windows
            detection:
                sel:
                    fieldA:
                        - valueA1
                        - valueA2
                    fieldB:
                        - valueB1
                        - valueB2
                condition: sel
        """)
    ) == ['DeviceProcessEvents\n| where fieldA has_any ("valueA1", "valueA2") and fieldB has_any ("valueB1", "valueB2")']


def test_microsoft365defender_or_and_expression(microsoft365defender_backend : Microsoft365DefenderBackend):
    assert microsoft365defender_backend.convert(
        SigmaCollection.from_yaml("""
            title: Test
            status: test
            logsource:
                category: process_creation
                product: windows
            detection:
                sel1:
                    fieldA: valueA1
                    fieldB: valueB1
                sel2:
                    fieldA: valueA2
                    fieldB: valueB2
                condition: 1 of sel*
        """)
    ) == ['DeviceProcessEvents\n| where (fieldA =~ "valueA1" and fieldB =~ "valueB1") or (fieldA =~ "valueA2" and fieldB =~ "valueB2")']

def test_microsoft365defender_in_expression(microsoft365defender_backend : Microsoft365DefenderBackend):
    assert microsoft365defender_backend.convert(
        SigmaCollection.from_yaml("""
            title: Test
            status: test
            logsource:
                category: process_creation
                product: windows
            detection:
                sel:
                    fieldA:
                        - valueA
                        - valueB
                        - valueC*
                condition: sel
        """)
    ) == ['DeviceProcessEvents\n| where fieldA has_any ("valueA", "valueB") or fieldA startswith "valueC"']


def test_microsoft365defender_regex_query(microsoft365defender_backend : Microsoft365DefenderBackend):
    assert microsoft365defender_backend.convert(
        SigmaCollection.from_yaml("""
            title: Test
            status: test
            logsource:
                category: process_creation
                product: windows
            detection:
                sel:
                    fieldA|re: foo.*bar
                    fieldB: foo
                condition: sel
        """)
    ) == ['DeviceProcessEvents\n| where fieldA matches regex "foo.*bar" and fieldB =~ "foo"']

def test_microsoft365defender_cidr_query(microsoft365defender_backend : Microsoft365DefenderBackend):
    assert microsoft365defender_backend.convert(
        SigmaCollection.from_yaml("""
            title: Test
            status: test
            logsource:
                category: process_creation
                product: windows
            detection:
                sel:
                    field|cidr: 192.168.0.0/16
                condition: sel
        """)
    ) == ['DeviceProcessEvents\n| where ipv4_is_in_range(field, "192.168.0.0/16")']

def test_microsoft365defender_field_name_with_whitespace(microsoft365defender_backend : Microsoft365DefenderBackend):
    assert microsoft365defender_backend.convert(
        SigmaCollection.from_yaml("""
            title: Test
            status: test
            logsource:
                category: process_creation
                product: windows
            detection:
                sel:
                    field name: value
                condition: sel
        """)
    ) == ['DeviceProcessEvents\n| where \'field name\' =~ "value"']

