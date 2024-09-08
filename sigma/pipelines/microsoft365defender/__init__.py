from .microsoft365defender import microsoft_365_defender_pipeline
from .sentinelasim import sentinelasim_pipeline

pipelines = {
    "microsoft_365_defender_pipeline": microsoft_365_defender_pipeline,   # TODO: adapt identifier to something approproiate
    "sentinelasim_pipeline": sentinelasim_pipeline,
}