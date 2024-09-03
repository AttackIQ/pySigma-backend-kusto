from sigma.processing.transformations import Transformation
from dataclasses import dataclass
from typing import Any


@dataclass
class SetQueryTableStateTransformation(Transformation):
    """Appends rule query table to pipeline state query_table key"""

    val: Any = None

    def apply(self, pipeline: "sigma.processing.pipeline.Proces", rule: "sigma.rule.SigmaRule") -> None:
        super().apply(pipeline, rule)
        pipeline.state['query_table'] = pipeline.state.get('query_table', []) + [self.val]
