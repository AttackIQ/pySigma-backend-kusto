from dataclasses import dataclass, field
from typing import Union, List

from sigma.processing.finalization import Finalizer


@dataclass
class Microsoft365DefenderTableFinalizer(Finalizer):
    """Finalizer for Microsoft 365 Defender Backend to add in the table name as a prefix to the query.

    The standard finalizers append all queries together into a single query string. However, this finalizer
    will keep individual queries separate and add the table name as a prefix to each query, per ordering in the
    pipeline's state 'query_table' key which is appended to for each rule by  set for each rule by the
    SetQueryTableStateTransformation transformation.
    
    A custom table name can be specified in the finalizer, otherwise the table name will be selected based on the category of the rule.
    """

    table_names: Union[str, List[str]] = field(default_factory=list)

    def apply(self, pipeline: "sigma.processing.pipeline.ProcessingPipeline", queries: List[str]) -> List[str]:
        if isinstance(self.table_names, str):
            self.table_names = [self.table_names] * len(queries)

        for i, query in enumerate(queries):
            if self.table_names:
                queries[i] = f"{self.table_names[i]}\n| where {query}"
            elif 'query_table' in pipeline.state:
                queries[i] = f"{pipeline.state['query_table'][i]}\n| where {query}"
            else:
                queries[i] = f"search {query}"
        return queries
