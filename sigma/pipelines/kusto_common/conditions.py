from dataclasses import dataclass
from typing import Union

from sigma.correlations import SigmaCorrelationRule
from sigma.processing.conditions import RuleProcessingCondition
from sigma.rule import SigmaRule


@dataclass
class QueryTableSetCondition(RuleProcessingCondition):
    def match(
        self,
        rule: Union[SigmaRule, SigmaCorrelationRule],
    ) -> bool:
        """Match condition on Sigma rule."""
        return self._pipeline.state.get("query_table", None) is not None
