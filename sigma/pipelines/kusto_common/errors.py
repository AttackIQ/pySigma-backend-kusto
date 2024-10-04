from sigma.processing.transformations import (
    DetectionItemFailureTransformation,
    SigmaTransformationError,
)
from sigma.rule import SigmaDetectionItem


class InvalidFieldTransformation(DetectionItemFailureTransformation):
    """
    Overrides the apply_detection_item() method from DetectionItemFailureTransformation to also include the field name
    in the error message
    """

    def apply_detection_item(self, detection_item: SigmaDetectionItem) -> None:
        field_name = detection_item.field
        if field_name:  # If no field name is set, don't raise an error because its a keyword
            self.message = f"Invalid SigmaDetectionItem field name encountered: {field_name}. " + self.message
            raise SigmaTransformationError(self.message)


class InvalidHashAlgorithmError(Exception):
    pass
