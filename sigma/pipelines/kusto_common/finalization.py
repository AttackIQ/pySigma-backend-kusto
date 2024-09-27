from dataclasses import dataclass
from typing import List

from sigma.processing.finalization import Finalizer


@dataclass
class QueryTableFinalizer(Finalizer):
    """Finalizer for pipelines using the Kusto Query Language to add in the table name as a prefix to the query.

    The query_table is set by the SetQueryTableStateTransformation transformation that is applied to each rule at the very beginning of the pipeline;
    the query table can be supplied as an argument to the pipeline, set in a previous ProcessingPipeline (which is combined into a single pipeline in sigma_cli), or is
    set by the rules category or other criteria from other transformations.

    The standard finalizers append all queries together into a single query string. However, this finalizer
    will keep individual queries separate and add the table name as a prefix to each query.

    A custom table name can be specified in the finalizer, otherwise the table name will be selected based on the processing pipeline's state 'query_table' key.
    """

    table_names: str = None

    def apply(self, pipeline: "sigma.processing.pipeline.ProcessingPipeline", queries: List[str]) -> List[str]:  # type: ignore # noqa: F821
        for i, query in enumerate(queries):
            if self.table_names:
                queries[i] = f"{self.table_names}\n| where {query}"
            elif "query_table" in pipeline.state:
                queries[i] = f"{pipeline.state['query_table']}\n| where {query}"
            else:
                queries[i] = f"search {query}"
        return queries
