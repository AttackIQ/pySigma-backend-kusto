from sigma.processing.pipeline import QueryPostprocessingItem
from sigma.processing.postprocessing import QueryPostprocessingTransformation
from sigma.rule import SigmaRule

from ..kusto_common.conditions import QueryTableSetCondition


class PrependQueryTablePostprocessingItem(QueryPostprocessingTransformation):
    def apply(self, pipeline: "sigma.processing.pipeline.ProcessingPipeline", rule: SigmaRule, query: str) -> str:  # type: ignore # noqa: F821
        return f"{pipeline.state['query_table']}\n| where {query}"


PrependQueryTablePostprocessingItem = QueryPostprocessingItem(
    identifier="kusto_prepend_query_table",
    transformation=PrependQueryTablePostprocessingItem(),
    rule_conditions=[
        QueryTableSetCondition(),
    ],
)
