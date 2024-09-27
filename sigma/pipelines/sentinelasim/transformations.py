from ..kusto_common.transformations import BaseHashesValuesTransformation


class ProcessCreateHashesValuesTransformation(BaseHashesValuesTransformation):
    """
    Transforms the Hashes field in imProcessCreate table to get rid of the hash algorithm prefix in each value.
    """

    def __init__(self):
        super().__init__(valid_hash_algos=["MD5", "SHA1", "SHA256", "SHA512", "IMPHASH"], field_prefix="TargetProcess")


class FileEventHashesValuesTransformation(BaseHashesValuesTransformation):
    """
    Transforms the Hashes field in imFileEvent table to get rid of the hash algorithm prefix in each value.
    """

    def __init__(self):
        super().__init__(valid_hash_algos=["MD5", "SHA1", "SHA256", "SHA512"], field_prefix="TargetFile")


class WebSessionHashesValuesTransformation(BaseHashesValuesTransformation):
    """
    Transforms the Hashes field in imWebSession table to get rid of the hash algorithm prefix in each value.
    """

    def __init__(self):
        super().__init__(valid_hash_algos=["MD5", "SHA1", "SHA256", "SHA512"], field_prefix="File")
