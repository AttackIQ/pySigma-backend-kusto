from .microsoft365defender import microsoft_365_defender_pipeline, microsoft_xdr_pipeline

pipelines = {
    "microsoft_365_defender_pipeline": microsoft_365_defender_pipeline,
    "microsoft_xdr_pipeline": microsoft_xdr_pipeline,
}
