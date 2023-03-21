![Tests](https://github.com/slincoln-aiq/pySigma-backend-microsoft365defender/actions/workflows/test.yml/badge.svg)
![Coverage Badge](https://img.shields.io/endpoint?url=https://gist.githubusercontent.com/slincoln-aiq/9c0879725c7f94387801390bbb0ac8d6/raw/slincoln-aiq-pySigma-backend-microsoft365defender.json)
![Status](https://img.shields.io/badge/Status-pre--release-orange)

# pySigma Microsoft 365 Defender Backend

## Overview

This is
the [Microsoft 365 Defender](https://learn.microsoft.com/en-us/microsoft-365/security/defender/?view=o365-worldwide)
backend for [pySigma](https://github.com/SigmaHQ/pySigma), previously known as the mdatp backend for sigmac. This
backend allows the transformation & conversion of Sigma Rules
into [Microsoft Advanced Hunting Queries](https://learn.microsoft.com/en-us/microsoft-365/security/defender/advanced-hunting-query-language?view=o365-worldwide)
in [Kusto Query
Language (KQL)](https://learn.microsoft.com/en-us/azure/data-explorer/kusto/query/). It
provides
the package `sigma.backends.microsoft365defender` with the `Microsoft365DefenderBackend` class.
Further, it contains the `microsoft_365_defender_pipeline` processing pipeline for field renames and error handling.
This pipeline is automatically applied to `SigmaRule` and `SigmaCollection` objects passed to
the `Microsoft365DefenderBackend` class.

It supports the following output formats:

* default: Query string for Advanced Hunting Queries in Kusto Query Language (KQL)

This backend is currently maintained by:

* [Stephen Lincoln](https://github.com/slincoln-aiq) via [AttackIQ](https://github.com/AttackIQ)

## Rule Support

The following `category` types are currently supported for only `product=windows`:

* process_creation
* image_load
* network_connection
* file_access, file_change, file_delete, file_event, file_rename
* registry_add, registry_delete, registry_event, registry_set

## Processing Pipeline

Along with field mappings and error handling, the `microsoft_365_defender_pipeline` contains the following
custom `ProcessingPipeline` classes to help ensure correct fields and values and are automatically applied as part of
the pipeline in the backend:

* `SplitDomainUserTransformation`: Custom DetectionItemTransformation transformation to split a User field into separate
  domain and user fields,
  if applicable. This is to handle the case where the Sysmon `User` field may contain a domain AND username, and
  Advanced Hunting queries separate out the domain and username into separate fields.
  If a matching field_name_condition field uses the schema DOMAIN\\USER, a new SigmaDetectionItem
  will be made for the Domain and put inside a SigmaDetection with the original User SigmaDetectionItem (minus the
  domain) for the
  matching SigmaDetectionItem.

  You should use this with a field_name_condition for `IncludeFieldName(['field', 'names', 'for', 'username']`)
* `HashesValuesTransformation`: Custom DetectionItemTransformation to take a list of values in the 'Hashes' field, which
  are expected to be
  'algo:hash_value', and create new SigmaDetectionItems for each hash type, where the values is a list of
  SigmaString hashes. If the hash type is not part of the value, it will be inferred based on length.

  Use with field_name_condition for Hashes field
* `RegistryActionTypeValueTransformation`: Custom ValueTransformation transformation. The Microsoft DeviceRegistryEvents
  table expect the ActionType to
  be a slightly different set of values than what Sysmon specified, so this will change them to the correct value.

## Limitations and Constraints

The pipeline/backend will only work for `product=windows` and the rule categories listed above (for now).

Fields that are not specified in each field mappings dictionary in the `microsoft_365_defender_pipeline` will not throw
an exception, but will also not be mapped to anything.
We are working on removing unsupported fields from queries and adding them as a comment in the query so the user will be
aware of unsupported fields, but still be able to transform/convert rules without error.

