from ..kusto_common.transformations import BaseHashesValuesTransformation


class SecurityEventHashesValuesTransformation(BaseHashesValuesTransformation):
    """
    Transforms the FileHash (originally Hashes) field in SecurityEvent table to get rid of the hash algorithm prefix in each value.
    """

    def __init__(self):
        super().__init__(valid_hash_algos=["MD5", "SHA1", "SHA256"], field_prefix="FileHash", drop_algo_prefix=True)


class DefaultHashesValuesTransformation(BaseHashesValuesTransformation):
    """
    Transforms the Hashes field in XDR Tables to create fields for each hash algorithm.
    """

    def __init__(self):
        super().__init__(valid_hash_algos=["MD5", "SHA1", "SHA256"], field_prefix="")
