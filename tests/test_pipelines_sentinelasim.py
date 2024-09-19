import pytest

from sigma.backends.kusto import KustoBackend
from sigma.collection import SigmaCollection
from sigma.pipelines.sentinelasim import sentinel_asim_pipeline


def test_sentinel_asim_basic_conversion():
    """Tests splitting username up into different fields if it includes a domain"""
    assert KustoBackend(processing_pipeline=sentinel_asim_pipeline()).convert(
        SigmaCollection.from_yaml("""
                title: Test
                status: test
                logsource:
                    category: process_creation
                    product: windows
                detection:
                    sel1:
                        CommandLine: command1
                    condition: any of sel*
            """)
    ) == ['imProcessCreate\n| '
          'where TargetProcessCommandLine =~ "command1"']
    