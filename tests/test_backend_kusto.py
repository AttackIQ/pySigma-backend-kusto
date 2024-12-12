import pytest
from sigma.collection import SigmaCollection
from sigma.backends.kusto import KustoBackend
from sigma.pipelines.microsoft365defender import microsoft_365_defender_pipeline


@pytest.fixture
def microsoft365defender_backend():
    return KustoBackend(processing_pipeline=microsoft_365_defender_pipeline())


def test_kusto_and_expression(microsoft365defender_backend: KustoBackend):
    assert (
        microsoft365defender_backend.convert(
            SigmaCollection.from_yaml(
                """
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
        """
            )
        )
        == ['DeviceProcessEvents\n| where ProcessCommandLine =~ "valueA" and AccountName =~ "valueB"']
    )


def test_kusto_or_expression(microsoft365defender_backend: KustoBackend):
    assert (
        microsoft365defender_backend.convert(
            SigmaCollection.from_yaml(
                """
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
        """
            )
        )
        == ['DeviceProcessEvents\n| where ProcessCommandLine =~ "valueA" or AccountName =~ "valueB"']
    )


def test_kusto_and_or_expression(microsoft365defender_backend: KustoBackend):
    assert (
        microsoft365defender_backend.convert(
            SigmaCollection.from_yaml(
                """
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
        """
            )
        )
        == [
            'DeviceProcessEvents\n| where (ProcessCommandLine in~ ("valueA1", "valueA2")) and '
            '(ProcessId in~ ("valueB1", "valueB2"))'
        ]
    )


def test_kusto_or_and_expression(microsoft365defender_backend: KustoBackend):
    assert (
        microsoft365defender_backend.convert(
            SigmaCollection.from_yaml(
                """
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
        """
            )
        )
        == [
            'DeviceProcessEvents\n| where (ProcessCommandLine =~ "valueA1" and ProcessId =~ "valueB1") or '
            '(ProcessCommandLine =~ "valueA2" and ProcessId =~ "valueB2")'
        ]
    )


def test_kusto_in_expression(microsoft365defender_backend: KustoBackend):
    assert (
        microsoft365defender_backend.convert(
            SigmaCollection.from_yaml(
                """
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
        """
            )
        )
        == [
            'DeviceProcessEvents\n| where ProcessCommandLine in~ ("valueA", "valueB") or '
            'ProcessCommandLine startswith "valueC"'
        ]
    )


def test_kusto_regex_query(microsoft365defender_backend: KustoBackend):
    assert (
        microsoft365defender_backend.convert(
            SigmaCollection.from_yaml(
                """
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
        """
            )
        )
        == ['DeviceProcessEvents\n| where ProcessCommandLine matches regex "foo.*bar" and ProcessId =~ "foo"']
    )


def test_kusto_cidr_query(microsoft365defender_backend: KustoBackend):
    assert (
        microsoft365defender_backend.convert(
            SigmaCollection.from_yaml(
                """
            title: Test
            status: test
            logsource:
                category: network_connection
                product: windows
            detection:
                sel:
                    SourceIp|cidr: 192.168.0.0/16
                condition: sel
        """
            )
        )
        == ['DeviceNetworkEvents\n| where ipv4_is_in_range(LocalIP, "192.168.0.0/16")']
    )


def test_kusto_negation_basic(microsoft365defender_backend: KustoBackend):
    assert (
        microsoft365defender_backend.convert(
            SigmaCollection.from_yaml(
                r"""
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
        """
            )
        )
        == [
            'DeviceProcessEvents\n| where (FolderPath endswith "\\\\process.exe" and '
            'ProcessCommandLine =~ "this") and '
            '(not(ProcessCommandLine =~ "notthis"))'
        ]
    )


def test_kusto_negation_contains(microsoft365defender_backend: KustoBackend):
    assert (
        microsoft365defender_backend.convert(
            SigmaCollection.from_yaml(
                r"""
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
        """
            )
        )
        == [
            'DeviceProcessEvents\n| where (FolderPath endswith "\\\\process.exe" and '
            'ProcessCommandLine contains "this") and '
            '(not(ProcessCommandLine contains "notthis"))'
        ]
    )


def test_kusto_grouping(microsoft365defender_backend: KustoBackend):
    assert (
        microsoft365defender_backend.convert(
            SigmaCollection.from_yaml(
                r"""
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
    """
            )
        )
        == [
            'DeviceNetworkEvents\n| where (InitiatingProcessFolderPath endswith "\\\\powershell.exe" or '
            'InitiatingProcessFolderPath endswith "\\\\pwsh.exe") and (RemoteUrl contains '
            '"pastebin.com" or RemoteUrl contains "anothersite.com")'
        ]
    )


def test_kusto_escape_cmdline_slash(microsoft365defender_backend: KustoBackend):
    assert (
        microsoft365defender_backend.convert(
            SigmaCollection.from_yaml(
                r"""
            title: Delete All Scheduled Tasks
            id: 220457c1-1c9f-4c2e-afe6-9598926222c1
            status: test
            description: Detects the usage of schtasks with the delete flag and the asterisk symbol to delete all tasks from the schedule of the local computer, including tasks scheduled by other users.
            references:
                - https://docs.microsoft.com/en-us/windows-server/administration/windows-commands/schtasks-delete
            author: Nasreddine Bencherchali (Nextron Systems)
            date: 2022-09-09
            tags:
                - attack.impact
                - attack.t1489
            logsource:
                category: process_creation
                product: windows
            detection:
                selection:
                    Image|endswith: '\schtasks.exe'
                    CommandLine|contains|all:
                        - ' /delete '
                        - '/tn \*'
                        - ' /f'
                condition: selection
            falsepositives:
                - Unlikely
            level: high
        """
            )
        )
        == [
            'DeviceProcessEvents\n| where FolderPath endswith "\\\\schtasks.exe" and '
            '(ProcessCommandLine contains " /delete " and '
            'ProcessCommandLine contains "/tn *" and '
            'ProcessCommandLine contains " /f")'
        ]
    )


def test_kusto_cmdline_filters(microsoft365defender_backend: KustoBackend):
    assert (
        microsoft365defender_backend.convert(
            SigmaCollection.from_yaml(
                r"""
            title: New Firewall Rule Added Via Netsh.EXE
            id: cd5cfd80-aa5f-44c0-9c20-108c4ae12e3c
            status: test
            description: Detects the addition of a new rule to the Windows firewall via netsh
            references:
                - https://www.operationblockbuster.com/wp-content/uploads/2016/02/Operation-Blockbuster-RAT-and-Staging-Report.pdf
            author: Markus Neis, Sander Wiebing
            date: 2019-01-29
            modified: 2023-02-10
            tags:
                - attack.defense_evasion
                - attack.t1562.004
                - attack.s0246
            logsource:
                category: process_creation
                product: windows
            detection:
                selection_img:
                    - Image|endswith: '\netsh.exe'
                    - OriginalFileName: 'netsh.exe'
                selection_cli:
                    CommandLine|contains|all:
                        - ' firewall '
                        - ' add '
                filter_optional_dropbox:
                    CommandLine|contains:
                        - 'advfirewall firewall add rule name=Dropbox dir=in action=allow "program=?:\Program Files (x86)\Dropbox\Client\Dropbox.exe" enable=yes profile=Any'
                        - 'advfirewall firewall add rule name=Dropbox dir=in action=allow "program=?:\Program Files\Dropbox\Client\Dropbox.exe" enable=yes profile=Any'
                condition: all of selection_* and not 1 of filter_optional_*
            falsepositives:
                - Legitimate administration activity
                - Software installations
            level: medium
            """
            )
        )
        == [
            'DeviceProcessEvents\n| where ((FolderPath endswith "\\\\netsh.exe" or '
            'ProcessVersionInfoOriginalFileName =~ "netsh.exe") and '
            '(ProcessCommandLine contains " firewall " and ProcessCommandLine contains " add ")) and '
            '(not(((ProcessCommandLine contains "advfirewall firewall add rule name=Dropbox dir=in action=allow '
            '\\"program=" and ProcessCommandLine contains ":\\\\Program Files (x86)\\\\Dropbox\\\\Client\\\\Dropbox.exe\\" '
            'enable=yes profile=Any") or (ProcessCommandLine contains "advfirewall firewall add rule name=Dropbox dir=in '
            'action=allow \\"program=" and ProcessCommandLine contains ":\\\\Program Files\\\\Dropbox\\\\Client\\\\Dropbox.exe\\" '
            'enable=yes profile=Any"))))'
        ]
    )
