# This file is auto-generated. Do not edit manually.
# Last updated: 2024-09-12 19:59:53 UTC

MICROSOFT_XDR_TABLES = {
    "AADSignInEventsBeta": {
        "Timestamp": {"data_type": "datetime", "description": "Date and time when the record was generated"},
        "Application": {"data_type": "string", "description": "Application that performed the recorded action"},
        "ApplicationId": {"data_type": "string", "description": "Unique identifier for the application"},
        "LogonType": {
            "data_type": "string",
            "description": "Type of logon session, specifically interactive, remote interactive (RDP), network, batch, and service",
        },
        "ErrorCode": {
            "data_type": "int",
            "description": "Contains the error code if a sign-in error occurs. To find a description of a specific error code, visit <https://aka.ms/AADsigninsErrorCodes>.",
        },
        "CorrelationId": {"data_type": "string", "description": "Unique identifier of the sign-in event"},
        "SessionId": {
            "data_type": "string",
            "description": "Unique number assigned to a user by a website's server for the duration of the visit or session",
        },
        "AccountDisplayName": {
            "data_type": "string",
            "description": "Name displayed in the address book entry for the account user. This is usually a combination of the given name, middle initial, and surname of the user.",
        },
        "AccountObjectId": {
            "data_type": "string",
            "description": "Unique identifier for the account in Microsoft Entra ID",
        },
        "AccountUpn": {"data_type": "string", "description": "User principal name (UPN) of the account"},
        "IsExternalUser": {
            "data_type": "int",
            "description": "Indicates if the user that signed in is external. Possible values: -1 (not set), 0 (not external), 1 (external).",
        },
        "IsGuestUser": {
            "data_type": "boolean",
            "description": "Indicates whether the user that signed in is a guest in the tenant",
        },
        "AlternateSignInName": {
            "data_type": "string",
            "description": "On-premises user principal name (UPN) of the user signing in to Microsoft Entra ID",
        },
        "LastPasswordChangeTimestamp": {
            "data_type": "datetime",
            "description": "Date and time when the user that signed in last changed their password",
        },
        "ResourceDisplayName": {
            "data_type": "string",
            "description": "Display name of the resource accessed. The display name can contain any character.",
        },
        "ResourceId": {"data_type": "string", "description": "Unique identifier of the resource accessed"},
        "ResourceTenantId": {
            "data_type": "string",
            "description": "Unique identifier of the tenant of the resource accessed",
        },
        "DeviceName": {"data_type": "string", "description": "Fully qualified domain name (FQDN) of the device"},
        "AadDeviceId": {"data_type": "string", "description": "Unique identifier for the device in Microsoft Entra ID"},
        "OSPlatform": {
            "data_type": "string",
            "description": "Platform of the operating system running on the device. Indicates specific operating systems, including variations within the same family, such as Windows 11, Windows 10, and Windows 7.",
        },
        "DeviceTrustType": {
            "data_type": "string",
            "description": "Indicates the trust type of the device that signed in. For managed device scenarios only. Possible values are Workplace, AzureAd, and ServerAd.",
        },
        "IsManaged": {
            "data_type": "int",
            "description": "Indicates whether the device that initiated the sign-in is a managed device (1) or not a managed device (0)",
        },
        "IsCompliant": {
            "data_type": "int",
            "description": "Indicates whether the device that initiated the sign-in is compliant (1) or non-compliant (0)",
        },
        "AuthenticationProcessingDetails": {
            "data_type": "string",
            "description": "Details about the authentication processor",
        },
        "AuthenticationRequirement": {
            "data_type": "string",
            "description": "Type of authentication required for the sign-in. Possible values: multiFactorAuthentication (MFA was required) and singleFactorAuthentication (no MFA was required).",
        },
        "TokenIssuerType": {
            "data_type": "int",
            "description": "Indicates if the token issuer is Microsoft Entra ID (0) or Active Directory Federation Services (1)",
        },
        "RiskLevelAggregated": {
            "data_type": "int",
            "description": "Aggregated risk level during sign-in. Possible values: 0 (aggregated risk level not set), 1 (none), 10 (low), 50 (medium), or 100 (high).",
        },
        "RiskDetails": {"data_type": "int", "description": "Details about the risky state of the user that signed in"},
        "RiskState": {
            "data_type": "int",
            "description": "Indicates risky user state. Possible values: 0 (none), 1 (confirmed safe), 2 (remediated), 3 (dismissed), 4 (at risk), or 5 (confirmed compromised).",
        },
        "UserAgent": {
            "data_type": "string",
            "description": "User agent information from the web browser or other client application",
        },
        "ClientAppUsed": {"data_type": "string", "description": "Indicates the client app used"},
        "Browser": {"data_type": "string", "description": "Details about the version of the browser used to sign in"},
        "ConditionalAccessPolicies": {
            "data_type": "string",
            "description": "Details of the conditional access policies applied to the sign-in event",
        },
        "ConditionalAccessStatus": {
            "data_type": "int",
            "description": "Status of the conditional access policies applied to the sign-in. Possible values are 0 (policies applied), 1 (attempt to apply policies failed), or 2 (policies not applied).",
        },
        "IPAddress": {"data_type": "string", "description": "IP address assigned to the device during communication"},
        "Country": {
            "data_type": "string",
            "description": "Two-letter code indicating the country/region where the client IP address is geolocated",
        },
        "State": {"data_type": "string", "description": "State where the sign-in occurred, if available"},
        "City": {"data_type": "string", "description": "City where the account user is located"},
        "Latitude": {"data_type": "string", "description": "The north to south coordinates of the sign-in location"},
        "Longitude": {"data_type": "string", "description": "The east to west coordinates of the sign-in location"},
        "NetworkLocationDetails": {
            "data_type": "string",
            "description": "Network location details of the authentication processor of the sign-in event",
        },
        "RequestId": {"data_type": "string", "description": "Unique identifier of the request"},
        "ReportId": {"data_type": "string", "description": "Unique identifier for the event"},
    },
    "AADSpnSignInEventsBeta": {
        "Timestamp": {"data_type": "datetime", "description": "Date and time when the record was generated"},
        "Application": {"data_type": "string", "description": "Application that performed the recorded action"},
        "ApplicationId": {"data_type": "string", "description": "Unique identifier for the application"},
        "IsManagedIdentity": {
            "data_type": "boolean",
            "description": "Indicates whether the sign-in was initiated by a managed identity",
        },
        "ErrorCode": {
            "data_type": "int",
            "description": "Contains the error code if a sign-in error occurs. To find a description of a specific error code, visit <https://aka.ms/AADsigninsErrorCodes>.",
        },
        "CorrelationId": {"data_type": "string", "description": "Unique identifier of the sign-in event"},
        "ServicePrincipalName": {
            "data_type": "string",
            "description": "Name of the service principal that initiated the sign-in",
        },
        "ServicePrincipalId": {
            "data_type": "string",
            "description": "Unique identifier of the service principal that initiated the sign-in",
        },
        "ResourceDisplayName": {
            "data_type": "string",
            "description": "Display name of the resource accessed. The display name can contain any character.",
        },
        "ResourceId": {"data_type": "string", "description": "Unique identifier of the resource accessed"},
        "ResourceTenantId": {
            "data_type": "string",
            "description": "Unique identifier of the tenant of the resource accessed",
        },
        "IPAddress": {
            "data_type": "string",
            "description": "IP address assigned to the endpoint and used during related network communications",
        },
        "Country": {
            "data_type": "string",
            "description": "Two-letter code indicating the country where the client IP address is geolocated",
        },
        "State": {"data_type": "string", "description": "State where the sign-in occurred, if available"},
        "City": {"data_type": "string", "description": "City where the account user is located"},
        "Latitude": {"data_type": "string", "description": "The north to south coordinates of the sign-in location"},
        "Longitude": {"data_type": "string", "description": "The east to west coordinates of the sign-in location"},
        "RequestId": {"data_type": "string", "description": "Unique identifier of the request"},
        "ReportId": {"data_type": "string", "description": "Unique identifier for the event"},
    },
    "AlertEvidence": {
        "Timestamp": {"data_type": "datetime", "description": "Date and time when the event was recorded"},
        "AlertId": {"data_type": "string", "description": "Unique identifier for the alert"},
        "Title": {"data_type": "string", "description": "Title of the alert"},
        "Categories": {
            "data_type": "string",
            "description": "List of categories that the information belongs to, in JSON array format",
        },
        "AttackTechniques": {
            "data_type": "string",
            "description": "MITRE ATT&CK techniques associated with the activity that triggered the alert",
        },
        "ServiceSource": {
            "data_type": "string",
            "description": "Product or service that provided the alert information",
        },
        "DetectionSource": {
            "data_type": "string",
            "description": "Detection technology or sensor that identified the notable component or activity",
        },
        "EntityType": {
            "data_type": "string",
            "description": "Type of object, such as a file, a process, a device, or a user",
        },
        "EvidenceRole": {
            "data_type": "string",
            "description": "How the entity is involved in an alert, indicating whether it is impacted or is merely related",
        },
        "EvidenceDirection": {
            "data_type": "string",
            "description": "Indicates whether the entity is the source or the destination of a network connection",
        },
        "FileName": {"data_type": "string", "description": "Name of the file that the recorded action was applied to"},
        "FolderPath": {
            "data_type": "string",
            "description": "Folder containing the file that the recorded action was applied to",
        },
        "SHA1": {"data_type": "string", "description": "SHA-1 of the file that the recorded action was applied to"},
        "SHA256": {
            "data_type": "string",
            "description": "SHA-256 of the file that the recorded action was applied to. This field is usually not populated—use the SHA1 column when available.",
        },
        "FileSize": {"data_type": "long", "description": "Size of the file in bytes"},
        "ThreatFamily": {
            "data_type": "string",
            "description": "Malware family that the suspicious or malicious file or process has been classified under",
        },
        "RemoteIP": {"data_type": "string", "description": "IP address that was being connected to"},
        "RemoteUrl": {
            "data_type": "string",
            "description": "URL or fully qualified domain name (FQDN) that was being connected to",
        },
        "AccountName": {"data_type": "string", "description": "User name of the account"},
        "AccountDomain": {"data_type": "string", "description": "Domain of the account"},
        "AccountSid": {"data_type": "string", "description": "Security Identifier (SID) of the account"},
        "AccountObjectId": {
            "data_type": "string",
            "description": "Unique identifier for the account in Microsoft Entra ID",
        },
        "AccountUpn": {"data_type": "string", "description": "User principal name (UPN) of the account"},
        "DeviceId": {"data_type": "string", "description": "Unique identifier for the device in the service"},
        "DeviceName": {"data_type": "string", "description": "Fully qualified domain name (FQDN) of the device"},
        "LocalIP": {
            "data_type": "string",
            "description": "IP address assigned to the local device used during communication",
        },
        "NetworkMessageId": {
            "data_type": "string",
            "description": "Unique identifier for the email, generated by Office 365",
        },
        "EmailSubject": {"data_type": "string", "description": "Subject of the email"},
        "Application": {"data_type": "string", "description": "Application that performed the recorded action"},
        "ApplicationId": {"data_type": "int", "description": "Unique identifier for the application"},
        "OAuthApplicationId": {
            "data_type": "string",
            "description": "Unique identifier of the third-party OAuth application",
        },
        "ProcessCommandLine": {"data_type": "string", "description": "Command line used to create the new process"},
        "RegistryKey": {"data_type": "string", "description": "Registry key that the recorded action was applied to"},
        "RegistryValueName": {
            "data_type": "string",
            "description": "Name of the registry value that the recorded action was applied to",
        },
        "RegistryValueData": {
            "data_type": "string",
            "description": "Data of the registry value that the recorded action was applied to",
        },
        "AdditionalFields": {"data_type": "string", "description": "Additional information about the entity or event"},
        "Severity": {
            "data_type": "string",
            "description": "Indicates the potential impact (high, medium, or low) of the threat indicator or breach activity identified by the alert",
        },
        "CloudResource": {"data_type": "string", "description": "Cloud resource name"},
        "CloudPlatform": {
            "data_type": "string",
            "description": "The cloud platform that the resource belongs to, can be Azure, Amazon Web Services, or Google Cloud Platform",
        },
        "ResourceType": {"data_type": "string", "description": "Type of cloud resource"},
        "ResourceID": {"data_type": "string", "description": "Unique identifier of the cloud resource accessed"},
        "SubscriptionId": {"data_type": "string", "description": "Unique identifier of the cloud service subscription"},
    },
    "AlertInfo": {
        "Timestamp": {"data_type": "datetime", "description": "Date and time when the record was generated"},
        "AlertId": {"data_type": "string", "description": "Unique identifier for the alert"},
        "Title": {"data_type": "string", "description": "Title of the alert"},
        "Category": {
            "data_type": "string",
            "description": "Type of threat indicator or breach activity identified by the alert",
        },
        "Severity": {
            "data_type": "string",
            "description": "Indicates the potential impact (high, medium, or low) of the threat indicator or breach activity identified by the alert",
        },
        "ServiceSource": {
            "data_type": "string",
            "description": "Product or service that provided the alert information",
        },
        "DetectionSource": {
            "data_type": "string",
            "description": "Detection technology or sensor that identified the notable component or activity",
        },
        "AttackTechniques": {
            "data_type": "string",
            "description": "MITRE ATT&CK techniques associated with the activity that triggered the alert",
        },
    },
    "BehaviorEntities": {
        "Timestamp": {"data_type": "datetime", "description": "Date and time when the record was generated"},
        "BehaviorId": {"data_type": "string", "description": "Unique identifier for the behavior"},
        "ActionType": {"data_type": "string", "description": "Type of behavior"},
        "Categories": {
            "data_type": "string",
            "description": "Type of threat indicator or  breach activity identified by the behavior",
        },
        "ServiceSource": {"data_type": "string", "description": "Product or service that identified the behavior"},
        "DetectionSource": {
            "data_type": "string",
            "description": "Detection technology or sensor that identified the notable component or activity",
        },
        "DataSources": {
            "data_type": "string",
            "description": "Products or services that provided information for the behavior",
        },
        "EntityType": {
            "data_type": "string",
            "description": "Type of object, such as a file, a process, a device, or a user",
        },
        "EntityRole": {
            "data_type": "string",
            "description": "Indicates whether the entity is impacted or merely related",
        },
        "DetailedEntityRole": {"data_type": "string", "description": "The roles of the entity in the behavior"},
        "FileName": {"data_type": "string", "description": "Name of the file that the behavior applies to"},
        "FolderPath": {"data_type": "string", "description": "Folder containing the file that the behavior applies to"},
        "SHA1": {"data_type": "string", "description": "SHA-1 of the file that the behavior applies to"},
        "SHA256": {"data_type": "string", "description": "SHA-256 of the file that the behavior applies to"},
        "FileSize": {"data_type": "long", "description": "Size, in bytes, of the file that the behavior applies to"},
        "ThreatFamily": {
            "data_type": "string",
            "description": "Malware family that the suspicious or malicious file or process has been classified under",
        },
        "RemoteIP": {"data_type": "string", "description": "IP address that was being connected to"},
        "RemoteUrl": {
            "data_type": "string",
            "description": "URL or fully qualified domain name (FQDN) that was being connected to",
        },
        "AccountName": {"data_type": "string", "description": "User name of the account"},
        "AccountDomain": {"data_type": "string", "description": "Domain of the account"},
        "AccountSid": {"data_type": "string", "description": "Security Identifier (SID) of the account"},
        "AccountObjectId": {
            "data_type": "string",
            "description": "Unique identifier for the account in Microsoft Entra ID",
        },
        "AccountUpn": {"data_type": "string", "description": "User principal name (UPN) of the account"},
        "DeviceId": {"data_type": "string", "description": "Unique identifier for the device in the service"},
        "DeviceName": {"data_type": "string", "description": "Fully qualified domain name (FQDN) of the device"},
        "LocalIP": {
            "data_type": "string",
            "description": "IP address assigned to the local device used during communication",
        },
        "NetworkMessageId": {
            "data_type": "string",
            "description": "Unique identifier for the email, generated by Office 365",
        },
        "EmailSubject": {"data_type": "string", "description": "Subject of the email"},
        "EmailClusterId": {
            "data_type": "string",
            "description": "Identifier for the group of similar emails clustered based on heuristic analysis of their contents",
        },
        "Application": {"data_type": "string", "description": "Application that performed the recorded action"},
        "ApplicationId": {"data_type": "int", "description": "Unique identifier for the application"},
        "OAuthApplicationId": {
            "data_type": "string",
            "description": "Unique identifier of the third-party OAuth application",
        },
        "ProcessCommandLine": {"data_type": "string", "description": "Command line used to create the new process"},
        "RegistryKey": {"data_type": "string", "description": "Registry key that the recorded action was applied to"},
        "RegistryValueName": {
            "data_type": "string",
            "description": "Name of the registry value that the recorded action was applied to",
        },
        "RegistryValueData": {
            "data_type": "string",
            "description": "Data of the registry value that the recorded action was applied to",
        },
        "AdditionalFields": {"data_type": "string", "description": "Additional information about the behavior"},
    },
    "BehaviorInfo": {
        "Timestamp": {"data_type": "datetime", "description": "Date and time when the record was generated"},
        "BehaviorId": {"data_type": "string", "description": "Unique identifier for the behavior"},
        "ActionType": {"data_type": "string", "description": "Type of behavior"},
        "Description": {"data_type": "string", "description": "Description of the behavior"},
        "Categories": {
            "data_type": "string",
            "description": "Type of threat indicator or  breach activity identified by the behavior",
        },
        "AttackTechniques": {
            "data_type": "string",
            "description": "MITRE ATT&CK techniques associated with the activity that triggered the behavior",
        },
        "ServiceSource": {"data_type": "string", "description": "Product or service that identified the behavior"},
        "DetectionSource": {
            "data_type": "string",
            "description": "Detection technology or sensor that identified the notable component or activity",
        },
        "DataSources": {
            "data_type": "string",
            "description": "Products or services that provided information for the behavior",
        },
        "DeviceId": {"data_type": "string", "description": "Unique identifier for the device in the service"},
        "AccountUpn": {"data_type": "string", "description": "User principal name (UPN) of the account"},
        "AccountObjectId": {
            "data_type": "string",
            "description": "Unique identifier for the account in Microsoft Entra ID",
        },
        "StartTime": {
            "data_type": "datetime",
            "description": "Date and time of the first activity related to the behavior",
        },
        "EndTime": {
            "data_type": "datetime",
            "description": "Date and time of the last activity related to the behavior",
        },
        "AdditionalFields": {"data_type": "string", "description": "Additional information about the behavior"},
    },
    "CloudAppEvents": {
        "Timestamp": {"data_type": "datetime", "description": "Date and time when the event was recorded"},
        "ActionType": {"data_type": "string", "description": "Type of activity that triggered the event"},
        "Application": {"data_type": "string", "description": "Application that performed the recorded action"},
        "ApplicationId": {"data_type": "int", "description": "Unique identifier for the application"},
        "AccountObjectId": {
            "data_type": "string",
            "description": "Unique identifier for the account in Microsoft Entra ID",
        },
        "AccountId": {
            "data_type": "string",
            "description": "An identifier for the account as found by Microsoft Defender for Cloud Apps. Could be Microsoft Entra ID, user principal name, or other identifiers.",
        },
        "AccountDisplayName": {
            "data_type": "string",
            "description": "Name displayed in the address book entry for the account user. This is usually a combination of the given name, middle initial, and surname of the user.",
        },
        "IsAdminOperation": {
            "data_type": "bool",
            "description": "Indicates whether the activity was performed by an administrator",
        },
        "DeviceType": {
            "data_type": "string",
            "description": "Type of device based on purpose and functionality, such as network device, workstation, server, mobile, gaming console, or printer",
        },
        "OSPlatform": {
            "data_type": "string",
            "description": "Platform of the operating system running on the device. This column indicates specific operating systems, including variations within the same family, such as Windows 11, Windows 10 and Windows 7.",
        },
        "IPAddress": {"data_type": "string", "description": "IP address assigned to the device during communication"},
        "IsAnonymousProxy": {
            "data_type": "boolean",
            "description": "Indicates whether the IP address belongs to a known anonymous proxy",
        },
        "CountryCode": {
            "data_type": "string",
            "description": "Two-letter code indicating the country where the client IP address is geolocated",
        },
        "City": {"data_type": "string", "description": "City where the client IP address is geolocated"},
        "Isp": {"data_type": "string", "description": "Internet service provider associated with the IP address"},
        "UserAgent": {
            "data_type": "string",
            "description": "User agent information from the web browser or other client application",
        },
        "ActivityType": {"data_type": "string", "description": "Type of activity that triggered the event"},
        "ActivityObjects": {
            "data_type": "dynamic",
            "description": "List of objects, such as files or folders, that were involved in the recorded activity",
        },
        "ObjectName": {
            "data_type": "string",
            "description": "Name of the object that the recorded action was applied to",
        },
        "ObjectType": {
            "data_type": "string",
            "description": "Type of object, such as a file or a folder, that the recorded action was applied to",
        },
        "ObjectId": {
            "data_type": "string",
            "description": "Unique identifier of the object that the recorded action was applied to",
        },
        "ReportId": {"data_type": "string", "description": "Unique identifier for the event"},
        "AccountType": {
            "data_type": "string",
            "description": "Type of user account, indicating its general role and access levels, such as Regular, System, Admin, Application",
        },
        "IsExternalUser": {
            "data_type": "boolean",
            "description": "Indicates whether a user inside the network doesn't belong to the organization's domain",
        },
        "IsImpersonated": {
            "data_type": "boolean",
            "description": "Indicates whether the activity was performed by one user for another (impersonated) user",
        },
        "IPTags": {
            "data_type": "dynamic",
            "description": "Customer-defined information applied to specific IP addresses and IP address ranges",
        },
        "IPCategory": {"data_type": "string", "description": "Additional information about the IP address"},
        "UserAgentTags": {
            "data_type": "dynamic",
            "description": "More information provided by Microsoft Defender for Cloud Apps in a tag in the user agent field. Can have any of the following values: Native client, Outdated browser, Outdated operating system, Robot",
        },
        "RawEventData": {
            "data_type": "dynamic",
            "description": "Raw event information from the source application or service in JSON format",
        },
        "AdditionalFields": {"data_type": "dynamic", "description": "Additional information about the entity or event"},
        "LastSeenForUser": {
            "data_type": "string",
            "description": "Shows how many days back the attribute was recently in use by the user in days (i.e. ISP, ActionType etc.)",
        },
        "UncommonForUser": {
            "data_type": "string",
            "description": "Lists the attributes in the event that are uncommon for the user, using this data to help rule out false positives and find out anomalies",
        },
        "AuditSource": {
            "data_type": "string",
            "description": "Audit data source, including one of the following: <br>- Defender for Cloud Apps access control <br>- Defender for Cloud Apps session control <br>- Defender for Cloud Apps app connector",
        },
        "SessionData": {
            "data_type": "dynamic",
            "description": 'The Defender for Cloud Apps session ID for access or session control. For example: `{InLineSessionId:"232342"}`',
        },
        "OAuthAppId": {
            "data_type": "string",
            "description": "A unique identifier that's assigned to an application when it’s registered to Entra with OAuth 2.0",
        },
    },
    "CloudAuditEvents": {
        "Timestamp": {"data_type": "datetime", "description": "Date and time when the event was recorded"},
        "ReportId": {"data_type": "string", "description": "Unique identifier for the event"},
        "DataSource": {
            "data_type": "string",
            "description": "Data source for the cloud audit events, can be GCP (for Google Cloud Platform), AWS (for Amazon Web Services), Azure (for Azure Resource Manager), Kubernetes Audit (for Kubernetes), or other cloud platforms",
        },
        "ActionType": {
            "data_type": "string",
            "description": "Type of activity that triggered the event, can be: Unknown, Create, Read, Update, Delete, Other",
        },
        "OperationName": {
            "data_type": "string",
            "description": "Audit event operation name as it appears in the record, usually includes both resource type and operation",
        },
        "ResourceId": {"data_type": "string", "description": "Unique identifier of the cloud resource accessed"},
        "IPAddress": {
            "data_type": "string",
            "description": "The client IP address used to access the cloud resource or control plane",
        },
        "IsAnonymousProxy": {
            "data_type": "boolean",
            "description": "Indicates whether the IP address belongs to a known anonymous proxy (1) or no (0)",
        },
        "CountryCode": {
            "data_type": "string",
            "description": "Two-letter code indicating the country where the client IP address is geolocated",
        },
        "City": {"data_type": "string", "description": "City where the client IP address is geolocated"},
        "Isp": {"data_type": "string", "description": "Internet service provider (ISP) associated with the IP address"},
        "UserAgent": {
            "data_type": "string",
            "description": "User agent information from the web browser or other client application",
        },
        "RawEventData": {
            "data_type": "dynamic",
            "description": "Full raw event information from the data source in JSON format",
        },
        "AdditionalFields": {"data_type": "dynamic", "description": "Additional information about the audit event"},
    },
    "DeviceEvents": {
        "Timestamp": {"data_type": "datetime", "description": "Date and time when the event was recorded"},
        "DeviceId": {"data_type": "string", "description": "Unique identifier for the device in the service"},
        "DeviceName": {"data_type": "string", "description": "Fully qualified domain name (FQDN) of the device"},
        "ActionType": {
            "data_type": "string",
            "description": "Type of activity that triggered the event. See the [in-portal schema reference](advanced-hunting-schema-tables.md?#get-schema-information-in-the-security-center) for details.",
        },
        "FileName": {"data_type": "string", "description": "Name of the file that the recorded action was applied to"},
        "FolderPath": {
            "data_type": "string",
            "description": "Folder containing the file that the recorded action was applied to",
        },
        "SHA1": {"data_type": "string", "description": "SHA-1 of the file that the recorded action was applied to"},
        "SHA256": {
            "data_type": "string",
            "description": "SHA-256 of the file that the recorded action was applied to. This field is usually not populated — use the SHA1 column when available.",
        },
        "MD5": {"data_type": "string", "description": "MD5 hash of the file that the recorded action was applied to"},
        "FileSize": {"data_type": "long", "description": "Size of the file in bytes"},
        "AccountDomain": {"data_type": "string", "description": "Domain of the account"},
        "AccountName": {
            "data_type": "string",
            "description": "User name of the account; if the device is registered in Microsoft Entra ID, the Entra ID user name of the account might be shown instead",
        },
        "AccountSid": {"data_type": "string", "description": "Security Identifier (SID) of the account"},
        "RemoteUrl": {
            "data_type": "string",
            "description": "URL or fully qualified domain name (FQDN) that was being connected to",
        },
        "RemoteDeviceName": {
            "data_type": "string",
            "description": "Name of the device that performed a remote operation on the affected device. Depending on the event being reported, this name could be a fully-qualified domain name (FQDN), a NetBIOS name, or a host name without domain information.",
        },
        "ProcessId": {"data_type": "long", "description": "Process ID (PID) of the newly created process"},
        "ProcessCommandLine": {"data_type": "string", "description": "Command line used to create the new process"},
        "ProcessCreationTime": {"data_type": "datetime", "description": "Date and time the process was created"},
        "ProcessTokenElevation": {
            "data_type": "string",
            "description": "Indicates the type of token elevation applied to the newly created process. Possible values: TokenElevationTypeLimited (restricted), TokenElevationTypeDefault (standard), and TokenElevationTypeFull (elevated)",
        },
        "LogonId": {
            "data_type": "long",
            "description": "Identifier for a logon session. This identifier is unique on the same device only between restarts.",
        },
        "RegistryKey": {"data_type": "string", "description": "Registry key that the recorded action was applied to"},
        "RegistryValueName": {
            "data_type": "string",
            "description": "Name of the registry value that the recorded action was applied to",
        },
        "RegistryValueData": {
            "data_type": "string",
            "description": "Data of the registry value that the recorded action was applied to",
        },
        "RemoteIP": {"data_type": "string", "description": "IP address that was being connected to"},
        "RemotePort": {"data_type": "int", "description": "TCP port on the remote device that was being connected to"},
        "LocalIP": {
            "data_type": "string",
            "description": "IP address assigned to the local device used during communication",
        },
        "LocalPort": {"data_type": "int", "description": "TCP port on the local device used during communication"},
        "FileOriginUrl": {"data_type": "string", "description": "URL where the file was downloaded from"},
        "FileOriginIP": {"data_type": "string", "description": "IP address where the file was downloaded from"},
        "InitiatingProcessSHA1": {
            "data_type": "string",
            "description": "SHA-1 of the process (image file) that initiated the event",
        },
        "InitiatingProcessSHA256": {
            "data_type": "string",
            "description": "SHA-256 of the process (image file) that initiated the event. This field is usually not populated — use the SHA1 column when available.",
        },
        "InitiatingProcessMD5": {
            "data_type": "string",
            "description": "MD5 hash of the process (image file) that initiated the event",
        },
        "InitiatingProcessFileName": {
            "data_type": "string",
            "description": "Name of the process that initiated the event",
        },
        "InitiatingProcessFileSize": {
            "data_type": "long",
            "description": "Size of the file that ran the process responsible for the event",
        },
        "InitiatingProcessFolderPath": {
            "data_type": "string",
            "description": "Folder containing the process (image file) that initiated the event",
        },
        "InitiatingProcessId": {
            "data_type": "long",
            "description": "Process ID (PID) of the process that initiated the event",
        },
        "InitiatingProcessCommandLine": {
            "data_type": "string",
            "description": "Command line used to run the process that initiated the event",
        },
        "InitiatingProcessCreationTime": {
            "data_type": "datetime",
            "description": "Date and time when the process that initiated the event was started",
        },
        "InitiatingProcessAccountDomain": {
            "data_type": "string",
            "description": "Domain of the account that ran the process responsible for the event",
        },
        "InitiatingProcessAccountName": {
            "data_type": "string",
            "description": "User name of the account that ran the process responsible for the event; if the device is registered in Microsoft Entra ID, the Entra ID user name of the account that ran the process responsible for the event might be shown instead",
        },
        "InitiatingProcessAccountSid": {
            "data_type": "string",
            "description": "Security Identifier (SID) of the account that ran the process responsible for the event",
        },
        "InitiatingProcessAccountUpn": {
            "data_type": "string",
            "description": "User principal name (UPN) of the account that ran the process responsible for the event; if the device is registered in Microsoft Entra ID, the Entra ID UPN of the account that ran the process responsible for the event might be shown instead",
        },
        "InitiatingProcessAccountObjectId": {
            "data_type": "string",
            "description": "Microsoft Entra object ID of the user account that ran the process responsible for the event",
        },
        "InitiatingProcessVersionInfoCompanyName": {
            "data_type": "string",
            "description": "Company name from the version information of the process (image file) responsible for the event",
        },
        "InitiatingProcessVersionInfoProductName": {
            "data_type": "string",
            "description": "Product name from the version information of the process (image file) responsible for the event",
        },
        "InitiatingProcessVersionInfoProductVersion": {
            "data_type": "string",
            "description": "Product version from the version information of the process (image file) responsible for the event",
        },
        " InitiatingProcessVersionInfoInternalFileName": {
            "data_type": "string",
            "description": "Internal file name from the version information of the process (image file) responsible for the event",
        },
        "InitiatingProcessVersionInfoOriginalFileName": {
            "data_type": "string",
            "description": "Original file name from the version information of the process (image file) responsible for the event",
        },
        "InitiatingProcessVersionInfoFileDescription": {
            "data_type": "string",
            "description": "Description from the version information of the process (image file) responsible for the event",
        },
        "InitiatingProcessParentId": {
            "data_type": "long",
            "description": "Process ID (PID) of the parent process that spawned the process responsible for the event",
        },
        "InitiatingProcessParentFileName": {
            "data_type": "string",
            "description": "Name or full path of the parent process that spawned the process responsible for the event",
        },
        "InitiatingProcessParentCreationTime": {
            "data_type": "datetime",
            "description": "Date and time when the parent of the process responsible for the event was started",
        },
        "InitiatingProcessLogonId": {
            "data_type": "long",
            "description": "Identifier for a logon session of the process that initiated the event. This identifier is unique on the same device only between restarts.",
        },
        "ReportId": {
            "data_type": "long",
            "description": "Event identifier based on a repeating counter. To identify unique events, this column must be used in conjunction with the DeviceName and Timestamp columns.",
        },
        "AppGuardContainerId": {
            "data_type": "string",
            "description": "Identifier for the virtualized container used by Application Guard to isolate browser activity",
        },
        "AdditionalFields": {
            "data_type": "string",
            "description": "Additional information about the event in JSON array format",
        },
        "InitiatingProcessSessionId": {
            "data_type": "long",
            "description": "Windows session ID of the initiating process",
        },
        "IsInitiatingProcessRemoteSession": {
            "data_type": "bool",
            "description": "Indicates whether the initiating process was run under a remote desktop protocol (RDP) session (true) or locally (false)",
        },
        "InitiatingProcessRemoteSessionDeviceName": {
            "data_type": "string",
            "description": "Device name of the remote device from which the initiating process’s RDP session was initiated",
        },
        "InitiatingProcessRemoteSessionIP": {
            "data_type": "string",
            "description": "IP address of the remote device from which the initiating process’s RDP session was initiated",
        },
        "CreatedProcessSessionId": {"data_type": "long", "description": "Windows session ID of the created process"},
        "IsProcessRemoteSession": {
            "data_type": "bool",
            "description": "Indicates whether the created process was run under a remote desktop protocol (RDP) session (true) or locally (false)",
        },
        "ProcessRemoteSessionDeviceName": {
            "data_type": "string",
            "description": "Device name of the remote device from which the created process’s RDP session was initiated",
        },
        "ProcessRemoteSessionIP": {
            "data_type": "string",
            "description": "IP address of the remote device from which the created process’s RDP session was initiated",
        },
    },
    "DeviceFileCertificateInfo": {
        "Timestamp": {"data_type": "datetime", "description": "Date and time when the record was generated"},
        "DeviceId": {"data_type": "string", "description": "Unique identifier for the device in the service"},
        "DeviceName": {"data_type": "string", "description": "Fully qualified domain name (FQDN) of the device"},
        "SHA1": {"data_type": "string", "description": "SHA-1 of the file that the recorded action was applied to"},
        "IsSigned": {"data_type": "bool", "description": "Indicates whether the file is signed"},
        "SignatureType": {
            "data_type": "string",
            "description": "Indicates whether signature information was read as embedded content in the file itself or read from an external catalog file",
        },
        "Signer": {"data_type": "string", "description": "Information about the signer of the file"},
        "SignerHash": {"data_type": "string", "description": "Unique hash value identifying the signer"},
        "Issuer": {"data_type": "string", "description": "Information about the issuing certificate authority (CA)"},
        "IssuerHash": {
            "data_type": "string",
            "description": "Unique hash value identifying issuing certificate authority (CA)",
        },
        "CertificateSerialNumber": {
            "data_type": "string",
            "description": "Identifier for the certificate that is unique to the issuing certificate authority (CA)",
        },
        "CrlDistributionPointUrls": {
            "data_type": "string",
            "description": "JSON array listing the URLs of network shares that contain certificates and certificate revocation lists (CRLs)",
        },
        "CertificateCreationTime": {
            "data_type": "datetime",
            "description": "Date and time the certificate was created",
        },
        "CertificateExpirationTime": {
            "data_type": "datetime",
            "description": "Date and time the certificate is set to expire",
        },
        "CertificateCountersignatureTime": {
            "data_type": "datetime",
            "description": "Date and time the certificate was countersigned",
        },
        "IsTrusted": {
            "data_type": "bool",
            "description": "Indicates whether the file is trusted based on the results of the WinVerifyTrust function, which checks for unknown root certificate information, invalid signatures, revoked certificates, and other questionable attributes",
        },
        "IsRootSignerMicrosoft": {
            "data_type": "boolean",
            "description": "Indicates whether the signer of the root certificate is Microsoft and if the file is included in Windows operating system",
        },
        "ReportId": {
            "data_type": "long",
            "description": "Event identifier based on a repeating counter. To identify unique events, this column must be used in conjunction with the DeviceName and Timestamp columns.",
        },
    },
    "DeviceFileEvents": {
        "Timestamp": {"data_type": "datetime", "description": "Date and time when the event was recorded"},
        "DeviceId": {"data_type": "string", "description": "Unique identifier for the device in the service"},
        "DeviceName": {"data_type": "string", "description": "Fully qualified domain name (FQDN) of the device"},
        "ActionType": {
            "data_type": "string",
            "description": "Type of activity that triggered the event. See the [in-portal schema reference](advanced-hunting-schema-tables.md?#get-schema-information-in-the-security-center) for details.",
        },
        "FileName": {"data_type": "string", "description": "Name of the file that the recorded action was applied to"},
        "FolderPath": {
            "data_type": "string",
            "description": "Folder containing the file that the recorded action was applied to",
        },
        "SHA1": {"data_type": "string", "description": "SHA-1 of the file that the recorded action was applied to"},
        "SHA256": {
            "data_type": "string",
            "description": "SHA-256 of the file that the recorded action was applied to. This field is usually not populated — use the SHA1 column when available.",
        },
        "MD5": {"data_type": "string", "description": "MD5 hash of the file that the recorded action was applied to"},
        "FileOriginUrl": {"data_type": "string", "description": "URL where the file was downloaded from"},
        "FileOriginReferrerUrl": {
            "data_type": "string",
            "description": "URL of the web page that links to the downloaded file",
        },
        "FileOriginIP": {"data_type": "string", "description": "IP address where the file was downloaded from"},
        "PreviousFolderPath": {
            "data_type": "string",
            "description": "Original folder containing the file before the recorded action was applied",
        },
        "PreviousFileName": {
            "data_type": "string",
            "description": "Original name of the file that was renamed as a result of the action",
        },
        "FileSize": {"data_type": "long", "description": "Size of the file in bytes"},
        "InitiatingProcessAccountDomain": {
            "data_type": "string",
            "description": "Domain of the account that ran the process responsible for the event",
        },
        "InitiatingProcessAccountName": {
            "data_type": "string",
            "description": "User name of the account that ran the process responsible for the event; if the device is registered in Microsoft Entra ID, the Entra ID user name of the account that ran the process responsible for the event might be shown instead",
        },
        "InitiatingProcessAccountSid": {
            "data_type": "string",
            "description": "Security Identifier (SID) of the account that ran the process responsible for the event",
        },
        "InitiatingProcessAccountUpn": {
            "data_type": "string",
            "description": "User principal name (UPN) of the account that ran the process responsible for the event; if the device is registered in Microsoft Entra ID, the Entra ID UPN of the account that ran the process responsible for the event might be shown instead",
        },
        "InitiatingProcessAccountObjectId": {
            "data_type": "string",
            "description": "Microsoft Entra object ID of the user account that ran the process responsible for the event",
        },
        "InitiatingProcessMD5": {
            "data_type": "string",
            "description": "MD5 hash of the process (image file) that initiated the event",
        },
        "InitiatingProcessSHA1": {
            "data_type": "string",
            "description": "SHA-1 of the process (image file) that initiated the event",
        },
        "InitiatingProcessSHA256": {
            "data_type": "string",
            "description": "SHA-256 of the process (image file) that initiated the event. This field is usually not populated — use the SHA1 column when available.",
        },
        "InitiatingProcessFolderPath": {
            "data_type": "string",
            "description": "Folder containing the process (image file) that initiated the event",
        },
        "InitiatingProcessFileName": {
            "data_type": "string",
            "description": "Name of the process that initiated the event",
        },
        "InitiatingProcessFileSize": {
            "data_type": "long",
            "description": "Size of the process (image file) that initiated the event",
        },
        "InitiatingProcessVersionInfoCompanyName": {
            "data_type": "string",
            "description": "Company name from the version information of the process (image file) responsible for the event",
        },
        "InitiatingProcessVersionInfoProductName": {
            "data_type": "string",
            "description": "Product name from the version information of the process (image file) responsible for the event",
        },
        "InitiatingProcessVersionInfoProductVersion": {
            "data_type": "string",
            "description": "Product version from the version information of the process (image file) responsible for the event",
        },
        "InitiatingProcessVersionInfoInternalFileName": {
            "data_type": "string",
            "description": "Internal file name from the version information of the process (image file) responsible for the event",
        },
        "InitiatingProcessVersionInfoOriginalFileName": {
            "data_type": "string",
            "description": "Original file name from the version information of the process (image file) responsible for the event",
        },
        "InitiatingProcessVersionInfoFileDescription": {
            "data_type": "string",
            "description": "Description from the version information of the process (image file) responsible for the event",
        },
        "InitiatingProcessId": {
            "data_type": "long",
            "description": "Process ID (PID) of the process that initiated the event",
        },
        "InitiatingProcessCommandLine": {
            "data_type": "string",
            "description": "Command line used to run the process that initiated the event",
        },
        "InitiatingProcessCreationTime": {
            "data_type": "datetime",
            "description": "Date and time when the process that initiated the event was started",
        },
        "InitiatingProcessIntegrityLevel": {
            "data_type": "string",
            "description": "Integrity level of the process that initiated the event. Windows assigns integrity levels to processes based on certain characteristics, such as if they were launched from an internet download. These integrity levels influence permissions to resources.",
        },
        "InitiatingProcessTokenElevation": {
            "data_type": "string",
            "description": "Token type indicating the presence or absence of User Access Control (UAC) privilege elevation applied to the process that initiated the event",
        },
        "InitiatingProcessParentId": {
            "data_type": "long",
            "description": "Process ID (PID) of the parent process that spawned the process responsible for the event",
        },
        "InitiatingProcessParentFileName": {
            "data_type": "string",
            "description": "Name of the parent process that spawned the process responsible for the event",
        },
        "InitiatingProcessParentCreationTime": {
            "data_type": "datetime",
            "description": "Date and time when the parent of the process responsible for the event was started",
        },
        "RequestProtocol": {
            "data_type": "string",
            "description": "Network protocol, if applicable, used to initiate the activity: Unknown, Local, SMB, or NFS",
        },
        "RequestSourceIP": {
            "data_type": "string",
            "description": "IPv4 or IPv6 address of the remote device that initiated the activity",
        },
        "RequestSourcePort": {
            "data_type": "int",
            "description": "Source port on the remote device that initiated the activity",
        },
        "RequestAccountName": {
            "data_type": "string",
            "description": "User name of account used to remotely initiate the activity",
        },
        "RequestAccountDomain": {
            "data_type": "string",
            "description": "Domain of the account used to remotely initiate the activity",
        },
        "RequestAccountSid": {
            "data_type": "string",
            "description": "Security Identifier (SID) of the account used to remotely initiate the activity",
        },
        "ShareName": {"data_type": "string", "description": "Name of shared folder containing the file"},
        "SensitivityLabel": {
            "data_type": "string",
            "description": "Label applied to an email, file, or other content to classify it for information protection",
        },
        "SensitivitySubLabel": {
            "data_type": "string",
            "description": "Sublabel applied to an email, file, or other content to classify it for information protection; sensitivity sublabels are grouped under sensitivity labels but are treated independently",
        },
        "IsAzureInfoProtectionApplied": {
            "data_type": "boolean",
            "description": "Indicates whether the file is encrypted by Azure Information Protection",
        },
        "ReportId": {
            "data_type": "long",
            "description": "Event identifier based on a repeating counter. To identify unique events, this column must be used in conjunction with the DeviceName and Timestamp columns.",
        },
        "AppGuardContainerId": {
            "data_type": "string",
            "description": "Identifier for the virtualized container used by Application Guard to isolate browser activity",
        },
        "AdditionalFields": {"data_type": "string", "description": "Additional information about the entity or event"},
        "InitiatingProcessSessionId": {
            "data_type": "long",
            "description": "Windows session ID of the initiating process",
        },
        "IsInitiatingProcessRemoteSession": {
            "data_type": "bool",
            "description": "Indicates whether the initiating process was run under a remote desktop protocol (RDP) session (true) or locally (false)",
        },
        "InitiatingProcessRemoteSessionDeviceName": {
            "data_type": "string",
            "description": "Device name of the remote device from which the initiating process’s RDP session was initiated",
        },
        "InitiatingProcessRemoteSessionIP": {
            "data_type": "string",
            "description": "IP address of the remote device from which the initiating process’s RDP session was initiated",
        },
    },
    "DeviceImageLoadEvents": {
        "Timestamp": {"data_type": "datetime", "description": "Date and time when the event was recorded"},
        "DeviceId": {"data_type": "string", "description": "Unique identifier for the device in the service"},
        "DeviceName": {"data_type": "string", "description": "Fully qualified domain name (FQDN) of the device"},
        "ActionType": {
            "data_type": "string",
            "description": "Type of activity that triggered the event. See the [in-portal schema reference](advanced-hunting-schema-tables.md?#get-schema-information-in-the-security-center) for details.",
        },
        "FileName": {"data_type": "string", "description": "Name of the file that the recorded action was applied to"},
        "FolderPath": {
            "data_type": "string",
            "description": "Folder containing the file that the recorded action was applied to",
        },
        "SHA1": {"data_type": "string", "description": "SHA-1 of the file that the recorded action was applied to"},
        "SHA256": {
            "data_type": "string",
            "description": "SHA-256 of the file that the recorded action was applied to. This field is usually not populated — use the SHA1 column when available.",
        },
        "MD5": {"data_type": "string", "description": "MD5 hash of the file that the recorded action was applied to"},
        "FileSize": {"data_type": "long", "description": "Size of the file in bytes"},
        "InitiatingProcessAccountDomain": {
            "data_type": "string",
            "description": "Domain of the account that ran the process responsible for the event",
        },
        "InitiatingProcessAccountName": {
            "data_type": "string",
            "description": "User name of the account that ran the process responsible for the event; if the device is registered in Microsoft Entra ID, the Entra ID user name of the account that ran the process responsible for the event might be shown instead",
        },
        "InitiatingProcessAccountSid": {
            "data_type": "string",
            "description": "Security Identifier (SID) of the account that ran the process responsible for the event",
        },
        "InitiatingProcessAccountUpn": {
            "data_type": "string",
            "description": "User principal name (UPN) of the account that ran the process responsible for the event; if the device is registered in Microsoft Entra ID, the Entra ID UPN of the account that ran the process responsible for the event might be shown instead",
        },
        "InitiatingProcessAccountObjectId": {
            "data_type": "string",
            "description": "Microsoft Entra object ID of the user account that ran the process responsible for the event",
        },
        "InitiatingProcessIntegrityLevel": {
            "data_type": "string",
            "description": "Integrity level of the process that initiated the event. Windows assigns integrity levels to processes based on certain characteristics, such as if they were launched from an internet download. These integrity levels influence permissions to resources.",
        },
        "InitiatingProcessTokenElevation": {
            "data_type": "string",
            "description": "Token type indicating the presence or absence of User Access Control (UAC) privilege elevation applied to the process that initiated the event",
        },
        "InitiatingProcessSHA1": {
            "data_type": "string",
            "description": "SHA-1 of the process (image file) that initiated the event",
        },
        "InitiatingProcessSHA256": {
            "data_type": "string",
            "description": "SHA-256 of the process (image file) that initiated the event. This field is usually not populated — use the SHA1 column when available.",
        },
        "InitiatingProcessMD5": {
            "data_type": "string",
            "description": "MD5 hash of the process (image file) that initiated the event",
        },
        "InitiatingProcessFileName": {
            "data_type": "string",
            "description": "Name of the process that initiated the event",
        },
        "InitiatingProcessFileSize": {
            "data_type": "long",
            "description": "Size of the file that ran the process responsible for the event",
        },
        "InitiatingProcessVersionInfoCompanyName": {
            "data_type": "string",
            "description": "Company name from the version information of the process (image file) responsible for the event",
        },
        "InitiatingProcessVersionInfoProductName": {
            "data_type": "string",
            "description": "Product name from the version information of the process (image file) responsible for the event",
        },
        "InitiatingProcessVersionInfoProductVersion": {
            "data_type": "string",
            "description": "Product version from the version information of the process (image file) responsible for the event",
        },
        "InitiatingProcessVersionInfoInternalFileName": {
            "data_type": "string",
            "description": "Internal file name from the version information of the process (image file) responsible for the event",
        },
        "InitiatingProcessVersionInfoOriginalFileName": {
            "data_type": "string",
            "description": "Original file name from the version information of the process (image file) responsible for the event",
        },
        "InitiatingProcessVersionInfoFileDescription": {
            "data_type": "string",
            "description": "Description from the version information of the process (image file) responsible for the event",
        },
        "InitiatingProcessId": {
            "data_type": "long",
            "description": "Process ID (PID) of the process that initiated the event",
        },
        "InitiatingProcessCommandLine": {
            "data_type": "string",
            "description": "Command line used to run the process that initiated the event",
        },
        "InitiatingProcessCreationTime": {
            "data_type": "datetime",
            "description": "Date and time when the process that initiated the event was started",
        },
        "InitiatingProcessFolderPath": {
            "data_type": "string",
            "description": "Folder containing the process (image file) that initiated the event",
        },
        "InitiatingProcessParentId": {
            "data_type": "long",
            "description": "Process ID (PID) of the parent process that spawned the process responsible for the event",
        },
        "InitiatingProcessParentFileName": {
            "data_type": "string",
            "description": "Name of the parent process that spawned the process responsible for the event",
        },
        "InitiatingProcessParentCreationTime": {
            "data_type": "datetime",
            "description": "Date and time when the parent of the process responsible for the event was started",
        },
        "ReportId": {
            "data_type": "long",
            "description": "Event identifier based on a repeating counter. To identify unique events, this column must be used in conjunction with the DeviceName and Timestamp columns.",
        },
        "AppGuardContainerId": {
            "data_type": "string",
            "description": "Identifier for the virtualized container used by Application Guard to isolate browser activity",
        },
        "InitiatingProcessSessionId": {
            "data_type": "long",
            "description": "Windows session ID of the initiating process",
        },
        "IsInitiatingProcessRemoteSession": {
            "data_type": "bool",
            "description": "Indicates whether the initiating process was run under a remote desktop protocol (RDP) session (true) or locally (false)",
        },
        "InitiatingProcessRemoteSessionDeviceName": {
            "data_type": "string",
            "description": "Device name of the remote device from which the initiating process’s RDP session was initiated",
        },
        "InitiatingProcessRemoteSessionIP": {
            "data_type": "string",
            "description": "IP address of the remote device from which the initiating process’s RDP session was initiated",
        },
    },
    "DeviceInfo": {
        "Timestamp": {"data_type": "datetime", "description": "Date and time when the event was recorded"},
        "DeviceId": {"data_type": "string", "description": "Unique identifier for the device in the service"},
        "DeviceName": {"data_type": "string", "description": "Fully qualified domain name (FQDN) of the device"},
        "ClientVersion": {
            "data_type": "string",
            "description": "Version of the endpoint agent or sensor running on the device",
        },
        "PublicIP": {
            "data_type": "string",
            "description": "Public IP address used by the onboarded device to connect to the Microsoft  Defender for Endpoint service. This could be the IP address of the device itself, a NAT device, or a proxy.",
        },
        "OSArchitecture": {
            "data_type": "string",
            "description": "Architecture of the operating system running on the device",
        },
        "OSPlatform": {
            "data_type": "string",
            "description": "Platform of the operating system running on the device. This indicates specific operating systems, including variations within the same family, such as Windows 11, Windows 10 and Windows 7.",
        },
        "OSBuild": {"data_type": "long", "description": "Build version of the operating system running on the device"},
        "IsAzureADJoined": {
            "data_type": "boolean",
            "description": "Boolean indicator of whether device is joined to the Microsoft Entra ID",
        },
        "JoinType": {"data_type": "string", "description": "The device's Microsoft Entra ID join type"},
        "AadDeviceId": {"data_type": "string", "description": "Unique identifier for the device in Microsoft Entra ID"},
        "LoggedOnUsers": {
            "data_type": "string",
            "description": "List of all users that are logged on the device at the time of the event in JSON array format",
        },
        "RegistryDeviceTag": {"data_type": "string", "description": "Device tag added through the registry"},
        "OSVersion": {"data_type": "string", "description": "Version of the operating system running on the device"},
        "MachineGroup": {
            "data_type": "string",
            "description": "Machine group of the device. This group is used by role-based access control to determine access to the device.",
        },
        "ReportId": {
            "data_type": "long",
            "description": "Event identifier based on a repeating counter. To identify unique events, this column must be used in conjunction with the DeviceName and Timestamp columns.",
        },
        "OnboardingStatus": {
            "data_type": "string",
            "description": "Indicates whether the device is currently onboarded or not to  Microsoft Defender For Endpoint or if the device is not supported",
        },
        "AdditionalFields": {
            "data_type": "string",
            "description": "Additional information about the event in JSON array format",
        },
        "DeviceCategory": {
            "data_type": "string",
            "description": "Broader classification that groups certain device types under the following categories: Endpoint, Network device, IoT, Unknown",
        },
        "DeviceType": {
            "data_type": "string",
            "description": "Type of device based on purpose and functionality, such as network device, workstation, server, mobile, gaming console, or printer",
        },
        "DeviceSubtype": {
            "data_type": "string",
            "description": "Additional modifier for certain types of devices, for example, a mobile device can be a tablet or a smartphone; only available if device discovery finds enough information about this attribute",
        },
        "Model": {
            "data_type": "string",
            "description": "Model name or number of the product from the vendor or manufacturer, only available if device discovery finds enough information about this attribute",
        },
        "Vendor": {
            "data_type": "string",
            "description": "Name of the product vendor or manufacturer, only available if device discovery finds enough information about this attribute",
        },
        "OSDistribution": {
            "data_type": "string",
            "description": "Distribution of the OS platform, such as Ubuntu or RedHat for Linux platforms",
        },
        "OSVersionInfo": {
            "data_type": "string",
            "description": "Additional information about the OS version, such as the popular name, code name, or version number",
        },
        "MergedDeviceIds": {
            "data_type": "string",
            "description": "Previous device IDs that have been assigned to the same device",
        },
        "MergedToDeviceId": {"data_type": "string", "description": "The most recent device ID assigned to a device"},
        "IsInternetFacing": {"data_type": "boolean", "description": "Indicates whether the device is internet-facing"},
        "SensorHealthState": {
            "data_type": "string",
            "description": "Indicates health of the device's EDR sensor, if onboarded to Microsoft Defender For Endpoint",
        },
        "IsExcluded": {
            "data_type": "bool",
            "description": "Determines if the device is currently excluded from Microsoft Defender for Vulnerability Management experiences",
        },
        "ExclusionReason": {"data_type": "string", "description": "Indicates the reason for device exclusion"},
        "ExposureLevel": {
            "data_type": "string",
            "description": "The device's level of vulnerability to exploitation based on its exposure score; can be: Low, Medium, High",
        },
        "AssetValue": {
            "data_type": "string",
            "description": "Priority or value assigned to the device in relation to its importance in computing the organization's exposure score; can be: Low, Normal (Default), High",
        },
        "DeviceManualTags": {
            "data_type": "string",
            "description": "Device tags created manually using the portal UI or public API",
        },
        "DeviceDynamicTags": {
            "data_type": "string",
            "description": "Device tags added and removed dynamically based on dynamic rules",
        },
        "ConnectivityType": {"data_type": "string", "description": "Type of connectivity from the device to the cloud"},
        "HostDeviceId": {
            "data_type": "string",
            "description": "Device ID of the device running Windows Subsystem for Linux",
        },
        "AzureResourceId": {
            "data_type": "string",
            "description": "Unique identifier of the Azure resource associated with the device",
        },
        "AwsResourceName": {
            "data_type": "string",
            "description": "Unique identifier specific to Amazon Web Services devices, containing the Amazon resource name",
        },
        "GcpFullResourceName": {
            "data_type": "string",
            "description": "Unique identifier specific to Google Cloud Platform devices, containing a combination of zone and ID for GCP",
        },
    },
    "DeviceLogonEvents": {
        "Timestamp": {"data_type": "datetime", "description": "Date and time when the event was recorded"},
        "DeviceId": {"data_type": "string", "description": "Unique identifier for the device in the service"},
        "DeviceName": {"data_type": "string", "description": "Fully qualified domain name (FQDN) of the device"},
        "ActionType": {"data_type": "string", "description": "Type of activity that triggered the event"},
        "LogonType": {
            "data_type": "string",
            "description": "Type of logon session, specifically:<br><br> - **Interactive** - User physically interacts with the device using the local keyboard and screen<br><br> - **Remote interactive (RDP) logons** - User interacts with the device remotely using Remote Desktop, Terminal Services, Remote Assistance, or other RDP clients<br><br> - **Network** - Session initiated when the device is accessed using PsExec or when shared resources on the device, such as printers and shared folders, are accessed<br><br> - **Batch** - Session initiated by scheduled tasks<br><br> - **Service** - Session initiated by services as they start<br>",
        },
        "AccountDomain": {"data_type": "string", "description": "Domain of the account"},
        "AccountName": {"data_type": "string", "description": "User name of the account"},
        "AccountSid": {"data_type": "string", "description": "Security Identifier (SID) of the account"},
        "Protocol": {"data_type": "string", "description": "Protocol used during the communication"},
        "FailureReason": {
            "data_type": "string",
            "description": "Information explaining why the recorded action failed",
        },
        "IsLocalAdmin": {
            "data_type": "boolean",
            "description": "Boolean indicator of whether the user is a local administrator on the device",
        },
        "LogonId": {
            "data_type": "long",
            "description": "Identifier for a logon session. This identifier is unique on the same device only between restarts.",
        },
        "RemoteDeviceName": {
            "data_type": "string",
            "description": "Name of the device that performed a remote operation on the affected device. Depending on the event being reported, this name could be a fully-qualified domain name (FQDN), a NetBIOS name  or a host name without domain information.",
        },
        "RemoteIP": {
            "data_type": "string",
            "description": "IP address of the device from which the logon attempt was performed",
        },
        "RemoteIPType": {
            "data_type": "string",
            "description": "Type of IP address, for example Public, Private, Reserved, Loopback, Teredo, FourToSixMapping, and Broadcast",
        },
        "RemotePort": {"data_type": "int", "description": "TCP port on the remote device that was being connected to"},
        "InitiatingProcessAccountDomain": {
            "data_type": "string",
            "description": "Domain of the account that ran the process responsible for the event",
        },
        "InitiatingProcessAccountName": {
            "data_type": "string",
            "description": "User name of the account that ran the process responsible for the event",
        },
        "InitiatingProcessAccountSid": {
            "data_type": "string",
            "description": "Security Identifier (SID) of the account that ran the process responsible for the event",
        },
        "InitiatingProcessAccountUpn": {
            "data_type": "string",
            "description": "User principal name (UPN) of the account that ran the process responsible for the event",
        },
        "InitiatingProcessAccountObjectId": {
            "data_type": "string",
            "description": "Microsoft Entra object ID of the user account that ran the process responsible for the event",
        },
        "InitiatingProcessIntegrityLevel": {
            "data_type": "string",
            "description": "Integrity level of the process that initiated the event. Windows assigns integrity levels to processes based on certain characteristics, such as if they were launched from an internet download. These integrity levels influence permissions to resources.",
        },
        "InitiatingProcessTokenElevation": {
            "data_type": "string",
            "description": "Token type indicating the presence or absence of User Access Control (UAC) privilege elevation applied to the process that initiated the event",
        },
        "InitiatingProcessSHA1": {
            "data_type": "string",
            "description": "SHA-1 hash of the process (image file) that initiated the event",
        },
        "InitiatingProcessSHA256": {
            "data_type": "string",
            "description": "SHA-256 hash of the process (image file) that initiated the event. This field is usually not populated - use the SHA1 column when available.",
        },
        "InitiatingProcessMD5": {
            "data_type": "string",
            "description": "MD5 hash of the process (image file) that initiated the event",
        },
        "InitiatingProcessFileName": {
            "data_type": "string",
            "description": "Name of the process that initiated the event",
        },
        "InitiatingProcessFileSize": {
            "data_type": "long",
            "description": "Size of the file that ran the process responsible for the event",
        },
        "InitiatingProcessVersionInfoCompanyName": {
            "data_type": "string",
            "description": "Company name from the version information of the process (image file) responsible for the event",
        },
        "InitiatingProcessVersionInfoProductName": {
            "data_type": "string",
            "description": "Product name from the version information of the process (image file) responsible for the event",
        },
        "InitiatingProcessVersionInfoProductVersion": {
            "data_type": "string",
            "description": "Product version from the version information of the process (image file) responsible for the event",
        },
        "InitiatingProcessVersionInfoInternalFileName": {
            "data_type": "string",
            "description": "Internal file name from the version information of the process (image file) responsible for the event",
        },
        "InitiatingProcessVersionInfoOriginalFileName": {
            "data_type": "string",
            "description": "Original file name from the version information of the process (image file) responsible for the event",
        },
        "InitiatingProcessVersionInfoFileDescription": {
            "data_type": "string",
            "description": "Description from the version information of the process (image file) responsible for the event",
        },
        "InitiatingProcessId": {
            "data_type": "long",
            "description": "Process ID (PID) of the process that initiated the event",
        },
        "InitiatingProcessCommandLine": {
            "data_type": "string",
            "description": "Command line used to run the process that initiated the event",
        },
        "InitiatingProcessCreationTime": {
            "data_type": "datetime",
            "description": "Date and time when the process that initiated the event was started",
        },
        "InitiatingProcessFolderPath": {
            "data_type": "string",
            "description": "Folder containing the process (image file) that initiated the event",
        },
        "InitiatingProcessParentId": {
            "data_type": "long",
            "description": "Process ID (PID) of the parent process that spawned the process responsible for the event",
        },
        "InitiatingProcessParentFileName": {
            "data_type": "string",
            "description": "Name or full path of the parent process that spawned the process responsible for the event",
        },
        "InitiatingProcessParentCreationTime": {
            "data_type": "datetime",
            "description": "Date and time when the parent of the process responsible for the event was started",
        },
        "ReportId": {
            "data_type": "long",
            "description": "Event identifier based on a repeating counter. To identify unique events, this column must be used in conjunction with the DeviceName and Timestamp columns.",
        },
        "AppGuardContainerId": {
            "data_type": "string",
            "description": "Identifier for the virtualized container used by Application Guard to isolate browser activity",
        },
        "AdditionalFields": {
            "data_type": "string",
            "description": "Additional information about the event in JSON array format",
        },
        "InitiatingProcessSessionId": {
            "data_type": "long",
            "description": "Windows session ID of the initiating process",
        },
        "IsInitiatingProcessRemoteSession": {
            "data_type": "bool",
            "description": "Indicates whether the initiating process was run under a remote desktop protocol (RDP) session (true) or locally (false)",
        },
        "InitiatingProcessRemoteSessionDeviceName": {
            "data_type": "string",
            "description": "Device name of the remote device from which the initiating process’s RDP session was initiated",
        },
        "InitiatingProcessRemoteSessionIP": {
            "data_type": "string",
            "description": "IP address of the remote device from which the initiating process’s RDP session was initiated",
        },
    },
    "DeviceNetworkEvents": {
        "Timestamp": {"data_type": "datetime", "description": "Date and time when the event was recorded"},
        "DeviceId": {"data_type": "string", "description": "Unique identifier for the device in the service"},
        "DeviceName": {"data_type": "string", "description": "Fully qualified domain name (FQDN) of the device"},
        "ActionType": {
            "data_type": "string",
            "description": "Type of activity that triggered the event. See the [in-portal schema reference](advanced-hunting-schema-tables.md?#get-schema-information-in-the-security-center) for details.",
        },
        "RemoteIP": {"data_type": "string", "description": "IP address that was being connected to"},
        "RemotePort": {"data_type": "int", "description": "TCP port on the remote device that was being connected to"},
        "RemoteUrl": {
            "data_type": "string",
            "description": "URL or fully qualified domain name (FQDN) that was being connected to",
        },
        "LocalIP": {
            "data_type": "string",
            "description": "Source IP, or the IP address where the communication came from",
        },
        "LocalPort": {"data_type": "int", "description": "TCP port on the local device used during communication"},
        "Protocol": {"data_type": "string", "description": "Protocol used during the communication"},
        "LocalIPType": {
            "data_type": "string",
            "description": "Type of IP address, for example Public, Private, Reserved, Loopback, Teredo, FourToSixMapping, and Broadcast",
        },
        "RemoteIPType": {
            "data_type": "string",
            "description": "Type of IP address, for example Public, Private, Reserved, Loopback, Teredo, FourToSixMapping, and Broadcast",
        },
        "InitiatingProcessSHA1": {
            "data_type": "string",
            "description": "SHA-1 of the process (image file) that initiated the event",
        },
        "InitiatingProcessSHA256": {
            "data_type": "string",
            "description": "SHA-256 of the process (image file) that initiated the event. This field is usually not populated — use the SHA1 column when available.",
        },
        "InitiatingProcessMD5": {
            "data_type": "string",
            "description": "MD5 hash of the process (image file) that initiated the event",
        },
        "InitiatingProcessFileName": {
            "data_type": "string",
            "description": "Name of the process that initiated the event",
        },
        "InitiatingProcessFileSize": {
            "data_type": "long",
            "description": "Size of the file that ran the process responsible for the event",
        },
        "InitiatingProcessVersionInfoCompanyName": {
            "data_type": "string",
            "description": "Company name from the version information of the process (image file) responsible for the event",
        },
        "InitiatingProcessVersionInfoProductName": {
            "data_type": "string",
            "description": "Product name from the version information of the process (image file) responsible for the event",
        },
        "InitiatingProcessVersionInfoProductVersion": {
            "data_type": "string",
            "description": "Product version from the version information of the process (image file) responsible for the event",
        },
        "InitiatingProcessVersionInfoInternalFileName": {
            "data_type": "string",
            "description": "Internal file name from the version information of the process (image file) responsible for the event",
        },
        "InitiatingProcessVersionInfoOriginalFileName": {
            "data_type": "string",
            "description": "Original file name from the version information of the process (image file) responsible for the event",
        },
        "InitiatingProcessVersionInfoFileDescription": {
            "data_type": "string",
            "description": "Description from the version information of the process (image file) responsible for the event",
        },
        "InitiatingProcessId": {
            "data_type": "long",
            "description": "Process ID (PID) of the process that initiated the event",
        },
        "InitiatingProcessCommandLine": {
            "data_type": "string",
            "description": "Command line used to run the process that initiated the event",
        },
        "InitiatingProcessCreationTime": {
            "data_type": "datetime",
            "description": "Date and time when the process that initiated the event was started",
        },
        "InitiatingProcessFolderPath": {
            "data_type": "string",
            "description": "Folder containing the process (image file) that initiated the event",
        },
        "InitiatingProcessParentFileName": {
            "data_type": "string",
            "description": "Name of the parent process that spawned the process responsible for the event",
        },
        "InitiatingProcessParentId": {
            "data_type": "long",
            "description": "Process ID (PID) of the parent process that spawned the process responsible for the event",
        },
        "InitiatingProcessParentCreationTime": {
            "data_type": "datetime",
            "description": "Date and time when the parent of the process responsible for the event was started",
        },
        "InitiatingProcessAccountDomain": {
            "data_type": "string",
            "description": "Domain of the account that ran the process responsible for the event",
        },
        "InitiatingProcessAccountName": {
            "data_type": "string",
            "description": "User name of the account that ran the process responsible for the event; if the device is registered in Microsoft Entra ID, the Entra ID user name of the account that ran the process responsible for the event might be shown instead",
        },
        "InitiatingProcessAccountSid": {
            "data_type": "string",
            "description": "Security Identifier (SID) of the account that ran the process responsible for the event",
        },
        "InitiatingProcessAccountUpn": {
            "data_type": "string",
            "description": "User principal name (UPN) of the account that ran the process responsible for the event; if the device is registered in Microsoft Entra ID, the Entra ID UPN of the account that ran the process responsible for the event might be shown instead",
        },
        "InitiatingProcessAccountObjectId": {
            "data_type": "string",
            "description": "Microsoft Entra object ID of the user account that ran the process responsible for the event",
        },
        "InitiatingProcessIntegrityLevel": {
            "data_type": "string",
            "description": "Integrity level of the process that initiated the event. Windows assigns integrity levels to processes based on certain characteristics, such as if they were launched from an internet download. These integrity levels influence permissions to resources.",
        },
        "InitiatingProcessTokenElevation": {
            "data_type": "string",
            "description": "Token type indicating the presence or absence of User Access Control (UAC) privilege elevation applied to the process that initiated the event",
        },
        "ReportId": {
            "data_type": "long",
            "description": "Event identifier based on a repeating counter. To identify unique events, this column must be used in conjunction with the DeviceName and Timestamp columns.",
        },
        "AppGuardContainerId": {
            "data_type": "string",
            "description": "Identifier for the virtualized container used by Application Guard to isolate browser activity",
        },
        "AdditionalFields": {
            "data_type": "string",
            "description": "Additional information about the event in JSON array format",
        },
        "InitiatingProcessSessionId": {
            "data_type": "long",
            "description": "Windows session ID of the initiating process",
        },
        "IsInitiatingProcessRemoteSession": {
            "data_type": "bool",
            "description": "Indicates whether the initiating process was run under a remote desktop protocol (RDP) session (true) or locally (false)",
        },
        "InitiatingProcessRemoteSessionDeviceName": {
            "data_type": "string",
            "description": "Device name of the remote device from which the initiating process’s RDP session was initiated",
        },
        "InitiatingProcessRemoteSessionIP": {
            "data_type": "string",
            "description": "IP address of the remote device from which the initiating process’s RDP session was initiated",
        },
    },
    "DeviceNetworkInfo": {
        "Timestamp": {"data_type": "datetime", "description": "Date and time when the event was recorded"},
        "DeviceId": {"data_type": "string", "description": "Unique identifier for the device in the service"},
        "DeviceName": {"data_type": "string", "description": "Fully qualified domain name (FQDN) of the device"},
        "NetworkAdapterName": {"data_type": "string", "description": "Name of the network adapter"},
        "MacAddress": {"data_type": "string", "description": "MAC address of the network adapter"},
        "NetworkAdapterType": {
            "data_type": "string",
            "description": "Network adapter type. For the possible values, refer to [this enumeration](/dotnet/api/system.net.networkinformation.networkinterfacetype).",
        },
        "NetworkAdapterStatus": {
            "data_type": "string",
            "description": "Operational status of the network adapter. For the possible values, refer to [this enumeration](/dotnet/api/system.net.networkinformation.operationalstatus).",
        },
        "TunnelType": {
            "data_type": "string",
            "description": "Tunneling protocol, if the interface is used for this purpose, for example 6to4, Teredo, ISATAP, PPTP, SSTP, and SSH",
        },
        "ConnectedNetworks": {
            "data_type": "string",
            "description": "Networks that the adapter is connected to. Each JSON element in the array contains the network name, category (public, private or domain), a description, and a flag indicating if it's connected publicly to the internet.",
        },
        "DnsAddresses": {"data_type": "string", "description": "DNS server addresses in JSON array format"},
        "IPv4Dhcp": {"data_type": "string", "description": "IPv4 address of DHCP server"},
        "IPv6Dhcp": {"data_type": "string", "description": "IPv6 address of DHCP server"},
        "DefaultGateways": {"data_type": "string", "description": "Default gateway addresses in JSON array format"},
        "IPAddresses": {
            "data_type": "string",
            "description": "JSON array containing all the IP addresses assigned to the adapter, along with their respective subnet prefix and IP address space, such as public, private, or link-local",
        },
        "ReportId": {
            "data_type": "long",
            "description": "Event identifier based on a repeating counter. To identify unique events, this column must be used in conjunction with the DeviceName and Timestamp columns.",
        },
        "NetworkAdapterVendor": {
            "data_type": "string",
            "description": "Name of the manufacturer or vendor of the network adapter",
        },
    },
    "DeviceProcessEvents": {
        "Timestamp": {"data_type": "datetime", "description": "Date and time when the event was recorded"},
        "DeviceId": {"data_type": "string", "description": "Unique identifier for the device in the service"},
        "DeviceName": {"data_type": "string", "description": "Fully qualified domain name (FQDN) of the device"},
        "ActionType": {
            "data_type": "string",
            "description": "Type of activity that triggered the event. See the [in-portal schema reference](advanced-hunting-schema-tables.md?#get-schema-information-in-the-security-center) for details.",
        },
        "FileName": {"data_type": "string", "description": "Name of the file that the recorded action was applied to"},
        "FolderPath": {
            "data_type": "string",
            "description": "Folder containing the file that the recorded action was applied to",
        },
        "SHA1": {"data_type": "string", "description": "SHA-1 of the file that the recorded action was applied to"},
        "SHA256": {
            "data_type": "string",
            "description": "SHA-256 of the file that the recorded action was applied to. This field is usually not populated — use the SHA1 column when available.",
        },
        "MD5": {"data_type": "string", "description": "MD5 hash of the file that the recorded action was applied to"},
        "FileSize": {"data_type": "long", "description": "Size of the file in bytes"},
        "ProcessVersionInfoCompanyName": {
            "data_type": "string",
            "description": "Company name from the version information of the newly created process",
        },
        "ProcessVersionInfoProductName": {
            "data_type": "string",
            "description": "Product name from the version information of the newly created process",
        },
        "ProcessVersionInfoProductVersion": {
            "data_type": "string",
            "description": "Product version from the version information of the newly created process",
        },
        "ProcessVersionInfoInternalFileName": {
            "data_type": "string",
            "description": "Internal file name from the version information of the newly created process",
        },
        "ProcessVersionInfoOriginalFileName": {
            "data_type": "string",
            "description": "Original file name from the version information of the newly created process",
        },
        "ProcessVersionInfoFileDescription": {
            "data_type": "string",
            "description": "Description from the version information of the newly created process",
        },
        "ProcessId": {"data_type": "long", "description": "Process ID (PID) of the newly created process"},
        "ProcessCommandLine": {"data_type": "string", "description": "Command line used to create the new process"},
        "ProcessIntegrityLevel": {
            "data_type": "string",
            "description": "Integrity level of the newly created process. Windows assigns integrity levels to processes based on certain characteristics, such as if they were launched from an internet downloaded. These integrity levels influence permissions to resources.",
        },
        "ProcessTokenElevation": {
            "data_type": "string",
            "description": "Indicates the type of token elevation applied to the newly created process. Possible values: TokenElevationTypeLimited (restricted), TokenElevationTypeDefault (standard), and TokenElevationTypeFull (elevated)",
        },
        "ProcessCreationTime": {"data_type": "datetime", "description": "Date and time the process was created"},
        "AccountDomain": {"data_type": "string", "description": "Domain of the account"},
        "AccountName": {
            "data_type": "string",
            "description": "User name of the account; if the device is registered in Microsoft Entra ID, the Entra ID user name of the account might be shown instead",
        },
        "AccountSid": {"data_type": "string", "description": "Security Identifier (SID) of the account"},
        "AccountUpn": {
            "data_type": "string",
            "description": "User principal name (UPN) of the account; if the device is registered in Microsoft Entra ID, the Entra ID UPN of the account might be shown instead",
        },
        "AccountObjectId": {
            "data_type": "string",
            "description": "Unique identifier for the account in Microsoft Entra ID",
        },
        "LogonId": {
            "data_type": "long",
            "description": "Identifier for a logon session. This identifier is unique on the same device only between restarts.",
        },
        "InitiatingProcessAccountDomain": {
            "data_type": "string",
            "description": "Domain of the account that ran the process responsible for the event",
        },
        "InitiatingProcessAccountName": {
            "data_type": "string",
            "description": "User name of the account that ran the process responsible for the event; if the device is registered in Microsoft Entra ID, the Entra ID user name of the account that ran the process responsible for the event might be shown instead",
        },
        "InitiatingProcessAccountSid": {
            "data_type": "string",
            "description": "Security Identifier (SID) of the account that ran the process responsible for the event",
        },
        "InitiatingProcessAccountUpn": {
            "data_type": "string",
            "description": "User principal name (UPN) of the account that ran the process responsible for the event; if the device is registered in Microsoft Entra ID, the Entra ID UPN of the account that ran the process responsible for the event might be shown instead",
        },
        "InitiatingProcessAccountObjectId": {
            "data_type": "string",
            "description": "Microsoft Entra object ID of the user account that ran the process responsible for the event",
        },
        "InitiatingProcessLogonId": {
            "data_type": "long",
            "description": "Identifier for a logon session of the process that initiated the event. This identifier is unique on the same device only between restarts.",
        },
        "InitiatingProcessIntegrityLevel": {
            "data_type": "string",
            "description": "Integrity level of the process that initiated the event. Windows assigns integrity levels to processes based on certain characteristics, such as if they were launched from an internet download. These integrity levels influence permissions to resources.",
        },
        "InitiatingProcessTokenElevation": {
            "data_type": "string",
            "description": "Token type indicating the presence or absence of User Access Control (UAC) privilege elevation applied to the process that initiated the event",
        },
        "InitiatingProcessSHA1": {
            "data_type": "string",
            "description": "SHA-1 hash of the process (image file) that initiated the event",
        },
        "InitiatingProcessSHA256": {
            "data_type": "string",
            "description": "SHA-256 of the process (image file) that initiated the event. This field is usually not populated — use the SHA1 column when available.",
        },
        "InitiatingProcessMD5": {
            "data_type": "string",
            "description": "MD5 hash of the process (image file) that initiated the event",
        },
        "InitiatingProcessFileName": {
            "data_type": "string",
            "description": "Name of the process that initiated the event",
        },
        "InitiatingProcessFileSize": {
            "data_type": "long",
            "description": "Size of the file that ran the process responsible for the event",
        },
        "InitiatingProcessVersionInfoCompanyName": {
            "data_type": "string",
            "description": "Company name from the version information of the process (image file) responsible for the event",
        },
        "InitiatingProcessVersionInfoProductName": {
            "data_type": "string",
            "description": "Product name from the version information of the process (image file) responsible for the event",
        },
        "InitiatingProcessVersionInfoProductVersion": {
            "data_type": "string",
            "description": "Product version from the version information of the process (image file) responsible for the event",
        },
        "InitiatingProcessVersionInfoInternalFileName": {
            "data_type": "string",
            "description": "Internal file name from the version information of the process (image file) responsible for the event",
        },
        "InitiatingProcessVersionInfoOriginalFileName": {
            "data_type": "string",
            "description": "Original file name from the version information of the process (image file) responsible for the event",
        },
        "InitiatingProcessVersionInfoFileDescription": {
            "data_type": "string",
            "description": "Description from the version information of the process (image file) responsible for the event",
        },
        "InitiatingProcessId": {
            "data_type": "long",
            "description": "Process ID (PID) of the process that initiated the event",
        },
        "InitiatingProcessCommandLine": {
            "data_type": "string",
            "description": "Command line used to run the process that initiated the event",
        },
        "InitiatingProcessCreationTime": {
            "data_type": "datetime",
            "description": "Date and time when the process that initiated the event was started",
        },
        "InitiatingProcessFolderPath": {
            "data_type": "string",
            "description": "Folder containing the process (image file) that initiated the event",
        },
        "InitiatingProcessParentId": {
            "data_type": "long",
            "description": "Process ID (PID) of the parent process that spawned the process responsible for the event",
        },
        "InitiatingProcessParentFileName": {
            "data_type": "string",
            "description": "Name of the parent process that spawned the process responsible for the event",
        },
        "InitiatingProcessParentCreationTime": {
            "data_type": "datetime",
            "description": "Date and time when the parent of the process responsible for the event was started",
        },
        "InitiatingProcessSignerType": {
            "data_type": "string",
            "description": "Type of file signer of the process (image file) that initiated the event",
        },
        "InitiatingProcessSignatureStatus": {
            "data_type": "string",
            "description": "Information about the signature status of the process (image file) that initiated the event",
        },
        "ReportId": {
            "data_type": "long",
            "description": "Event identifier based on a repeating counter. To identify unique events, this column must be used in conjunction with the DeviceName and Timestamp columns.",
        },
        "AppGuardContainerId": {
            "data_type": "string",
            "description": "Identifier for the virtualized container used by Application Guard to isolate browser activity",
        },
        "AdditionalFields": {
            "data_type": "string",
            "description": "Additional information about the event in JSON array format",
        },
        "InitiatingProcessSessionId": {
            "data_type": "long",
            "description": "Windows session ID of the initiating process",
        },
        "IsInitiatingProcessRemoteSession": {
            "data_type": "bool",
            "description": "Indicates whether the initiating process was run under a remote desktop protocol (RDP) session (true) or locally (false)",
        },
        "InitiatingProcessRemoteSessionDeviceName": {
            "data_type": "string",
            "description": "Device name of the remote device from which the initiating process’s RDP session was initiated",
        },
        "InitiatingProcessRemoteSessionIP": {
            "data_type": "string",
            "description": "IP address of the remote device from which the initiating process’s RDP session was initiated",
        },
        "CreatedProcessSessionId": {"data_type": "long", "description": "Windows session ID of the created process"},
        "IsProcessRemoteSession": {
            "data_type": "bool",
            "description": "Indicates whether the created process was run under a remote desktop protocol (RDP) session (true) or locally (false)",
        },
        "ProcessRemoteSessionDeviceName": {
            "data_type": "string",
            "description": "Device name of the remote device from which the created process’s RDP session was initiated",
        },
        "ProcessRemoteSessionIP": {
            "data_type": "string",
            "description": "IP address of the remote device from which the created process’s RDP session was initiated",
        },
    },
    "DeviceRegistryEvents": {
        "Timestamp": {"data_type": "datetime", "description": "Date and time when the event was recorded"},
        "DeviceId": {"data_type": "string", "description": "Unique identifier for the device in the service"},
        "DeviceName": {"data_type": "string", "description": "Fully qualified domain name (FQDN) of the device"},
        "ActionType": {
            "data_type": "string",
            "description": "Type of activity that triggered the event. See the [in-portal schema reference](advanced-hunting-schema-tables.md?#get-schema-information-in-the-security-center) for details.",
        },
        "RegistryKey": {"data_type": "string", "description": "Registry key that the recorded action was applied to"},
        "RegistryValueType": {
            "data_type": "string",
            "description": "Data type, such as binary or string, of the registry value that the recorded action was applied to",
        },
        "RegistryValueName": {
            "data_type": "string",
            "description": "Name of the registry value that the recorded action was applied to",
        },
        "RegistryValueData": {
            "data_type": "string",
            "description": "Data of the registry value that the recorded action was applied to",
        },
        "PreviousRegistryKey": {
            "data_type": "string",
            "description": "Original registry key of the registry value before it was modified",
        },
        "PreviousRegistryValueName": {
            "data_type": "string",
            "description": "Original name of the registry value before it was modified",
        },
        "PreviousRegistryValueData": {
            "data_type": "string",
            "description": "Original data of the registry value before it was modified",
        },
        "InitiatingProcessAccountDomain": {
            "data_type": "string",
            "description": "Domain of the account that ran the process responsible for the event",
        },
        "InitiatingProcessAccountName": {
            "data_type": "string",
            "description": "User name of the account that ran the process responsible for the event; if the device is registered in Microsoft Entra ID, the Entra ID user name of the account that ran the process responsible for the event might be shown instead",
        },
        "InitiatingProcessAccountSid": {
            "data_type": "string",
            "description": "Security Identifier (SID) of the account that ran the process responsible for the event",
        },
        "InitiatingProcessAccountUpn": {
            "data_type": "string",
            "description": "User principal name (UPN) of the account that ran the process responsible for the event; if the device is registered in Microsoft Entra ID, the Entra ID UPN of the account that ran the process responsible for the event might be shown instead",
        },
        "InitiatingProcessAccountObjectId": {
            "data_type": "string",
            "description": "Microsoft Entra object ID of the user account that ran the process responsible for the event",
        },
        "InitiatingProcessSHA1": {
            "data_type": "string",
            "description": "SHA-1 of the process (image file) that initiated the event",
        },
        "InitiatingProcessSHA256": {
            "data_type": "string",
            "description": "SHA-256 of the process (image file) that initiated the event. This field is usually not populated — use the SHA1 column when available.",
        },
        "InitiatingProcessMD5": {
            "data_type": "string",
            "description": "MD5 hash of the process (image file) that initiated the event",
        },
        "InitiatingProcessFileName": {
            "data_type": "string",
            "description": "Name of the process that initiated the event",
        },
        "InitiatingProcessFileSize": {
            "data_type": "long",
            "description": "Size of the file that ran the process responsible for the event",
        },
        "InitiatingProcessVersionInfoCompanyName": {
            "data_type": "string",
            "description": "Company name from the version information of the process (image file) responsible for the event",
        },
        "InitiatingProcessVersionInfoProductName": {
            "data_type": "string",
            "description": "Product name from the version information of the process (image file) responsible for the event",
        },
        "InitiatingProcessVersionInfoProductVersion": {
            "data_type": "string",
            "description": "Product version from the version information of the process (image file) responsible for the event",
        },
        "InitiatingProcessVersionInfoInternalFileName": {
            "data_type": "string",
            "description": "Internal file name from the version information of the process (image file) responsible for the event",
        },
        "InitiatingProcessVersionInfoOriginalFileName": {
            "data_type": "string",
            "description": "Original file name from the version information of the process (image file) responsible for the event",
        },
        "InitiatingProcessVersionInfoFileDescription": {
            "data_type": "string",
            "description": "Description from the version information of the process (image file) responsible for the event",
        },
        "InitiatingProcessId": {
            "data_type": "long",
            "description": "Process ID (PID) of the process that initiated the event",
        },
        "InitiatingProcessCommandLine": {
            "data_type": "string",
            "description": "Command line used to run the process that initiated the event",
        },
        "InitiatingProcessCreationTime": {
            "data_type": "datetime",
            "description": "Date and time when the process that initiated the event was started",
        },
        "InitiatingProcessFolderPath": {
            "data_type": "string",
            "description": "Folder containing the process (image file) that initiated the event",
        },
        "InitiatingProcessParentId": {
            "data_type": "long",
            "description": "Process ID (PID) of the parent process that spawned the process responsible for the event",
        },
        "InitiatingProcessParentFileName": {
            "data_type": "string",
            "description": "Name of the parent process that spawned the process responsible for the event",
        },
        "InitiatingProcessParentCreationTime": {
            "data_type": "datetime",
            "description": "Date and time when the parent of the process responsible for the event was started",
        },
        "InitiatingProcessIntegrityLevel": {
            "data_type": "string",
            "description": "Integrity level of the process that initiated the event. Windows assigns integrity levels to processes based on certain characteristics, such as if they were launched from an internet download. These integrity levels influence permissions to resources.",
        },
        "InitiatingProcessTokenElevation": {
            "data_type": "string",
            "description": "Token type indicating the presence or absence of User Access Control (UAC) privilege elevation applied to the process that initiated the event",
        },
        "ReportId": {
            "data_type": "long",
            "description": "Event identifier based on a repeating counter. To identify unique events, this column must be used in conjunction with the DeviceName and Timestamp columns.",
        },
        "AppGuardContainerId": {
            "data_type": "string",
            "description": "Identifier for the virtualized container used by Application Guard to isolate browser activity",
        },
        "InitiatingProcessSessionId": {
            "data_type": "long",
            "description": "Windows session ID of the initiating process",
        },
        "IsInitiatingProcessRemoteSession": {
            "data_type": "bool",
            "description": "Indicates whether the initiating process was run under a remote desktop protocol (RDP) session (true) or locally (false)",
        },
        "InitiatingProcessRemoteSessionDeviceName": {
            "data_type": "string",
            "description": "Device name of the remote device from which the initiating process’s RDP session was initiated",
        },
        "InitiatingProcessRemoteSessionIP": {
            "data_type": "string",
            "description": "IP address of the remote device from which the initiating process’s RDP session was initiated",
        },
    },
    "DeviceTvmHardwareFirmware": {
        "DeviceId": {"data_type": "string", "description": "Unique identifier for the device in the service"},
        "DeviceName": {"data_type": "string", "description": "Fully qualified domain name (FQDN) of the device"},
        "ComponentType": {"data_type": "string", "description": "Type of hardware or firmware component"},
        "Manufacturer": {"data_type": "string", "description": "Manufacturer of hardware or firmware component"},
        "ComponentName": {"data_type": "string", "description": "Name of hardware or firmware component"},
        "ComponentFamily": {
            "data_type": "string",
            "description": "Component family or class, a grouping of components that have similar features or characteristics as determined by the manufacturer",
        },
        "ComponentVersion": {"data_type": "string", "description": "Component version (for example, BIOS version)"},
        "AdditionalFields": {
            "data_type": "dynamic",
            "description": "Additional information about the components in JSON array format",
        },
    },
    "DeviceTvmInfoGathering": {
        "Timestamp": {"data_type": "datetime", "description": "Date and time when the record was generated"},
        "LastSeenTime": {"data_type": "datetime", "description": "Date and time when the service last saw the device"},
        "DeviceId": {"data_type": "string", "description": "Unique identifier for the device in the service"},
        "DeviceName": {"data_type": "string", "description": "Fully qualified domain name (FQDN) of the device"},
        "OSPlatform": {
            "data_type": "string",
            "description": "Platform of the operating system running on the device. This indicates specific operating systems, including variations within the same family, such as Windows 10 and Windows 7.",
        },
        "AdditionalFields": {"data_type": "dynamic", "description": "Additional information about the entity or event"},
    },
    "DeviceTvmInfoGatheringKB": {
        "IgId": {"data_type": "string", "description": "Unique identifier for the piece of information gathered"},
        "FieldName": {
            "data_type": "string",
            "description": "Name of the field where this information appears in the AdditionalFields column of the DeviceTvmInfoGathering table",
        },
        "Description": {"data_type": "string", "description": "Description of the information gathered"},
        "Categories": {
            "data_type": "dynamic",
            "description": "List of categories that the information belongs to, in JSON array format",
        },
        "DataStructure": {"data_type": "string", "description": "The data structure of the information gathered"},
    },
    "DeviceTvmSecureConfigurationAssessment": {
        "DeviceId": {"data_type": "string", "description": "Unique identifier for the device in the service"},
        "DeviceName": {"data_type": "string", "description": "Fully qualified domain name (FQDN) of the device"},
        "OSPlatform": {
            "data_type": "string",
            "description": "Platform of the operating system running on the device. Indicates specific operating systems, including variations within the same family, such as Windows 11, Windows 10, and Windows 7.",
        },
        "Timestamp": {"data_type": "datetime", "description": "Date and time when the record was generated"},
        "ConfigurationId": {"data_type": "string", "description": "Unique identifier for a specific configuration"},
        "ConfigurationCategory": {
            "data_type": "string",
            "description": "Category or grouping to which the configuration belongs: Application, OS, Network, Accounts, Security controls",
        },
        "ConfigurationSubcategory": {
            "data_type": "string",
            "description": "Subcategory or subgrouping to which the configuration belongs. In many cases,  string describes specific capabilities or features.",
        },
        "ConfigurationImpact": {
            "data_type": "real",
            "description": "Rated impact of the configuration to the overall configuration score (1-10)",
        },
        "IsCompliant": {
            "data_type": "boolean",
            "description": "Indicates whether the configuration or policy is properly configured",
        },
        "IsApplicable": {
            "data_type": "boolean",
            "description": "Indicates whether the configuration or policy applies to the device",
        },
        "Context": {
            "data_type": "dynamic",
            "description": "Additional contextual information about the configuration or policy",
        },
        "IsExpectedUserImpact": {
            "data_type": "boolean",
            "description": "Indicates whether there will be user impact if the configuration or policy is applied",
        },
    },
    "DeviceTvmSecureConfigurationAssessmentKB": {
        "ConfigurationId": {"data_type": "string", "description": "Unique identifier for a specific configuration"},
        "ConfigurationImpact": {
            "data_type": "real",
            "description": "Rated impact of the configuration to the overall configuration score (1-10)",
        },
        "ConfigurationName": {"data_type": "string", "description": "Display name of the configuration"},
        "ConfigurationDescription": {"data_type": "string", "description": "Description of the configuration"},
        "RiskDescription": {"data_type": "string", "description": "Description of the associated risk"},
        "ConfigurationCategory": {
            "data_type": "string",
            "description": "Category or grouping to which the configuration belongs: Application, OS, Network, Accounts, Security controls",
        },
        "ConfigurationSubcategory": {
            "data_type": "string",
            "description": "Subcategory or subgrouping to which the configuration belongs. In many cases, this describes specific capabilities or features.",
        },
        "ConfigurationBenchmarks": {
            "data_type": "dynamic",
            "description": "List of industry benchmarks recommending the same or similar configuration",
        },
        "Tags": {
            "data_type": "dynamic",
            "description": "Labels representing various attributes used to identify or categorize a security configuration",
        },
        "RemediationOptions": {
            "data_type": "string",
            "description": "Recommended actions to reduce or address any associated risks",
        },
    },
    "DeviceTvmSoftwareEvidenceBeta": {
        "DeviceId": {"data_type": "string", "description": "Unique identifier for the device in the service"},
        "SoftwareVendor": {"data_type": "string", "description": "Name of the software publisher"},
        "SoftwareName": {"data_type": "string", "description": "Name of the software product"},
        "SoftwareVersion": {"data_type": "string", "description": "Version number of the software product"},
        "RegistryPaths": {
            "data_type": "dynamic",
            "description": "Registry paths where evidence indicating the existence of the software on a device was detected",
        },
        "DiskPaths": {
            "data_type": "dynamic",
            "description": "Disk paths where file-level evidence indicating the existence of the software on a device was detected",
        },
        "LastSeenTime": {
            "data_type": "string",
            "description": "Date and time when the device was last seen by this service",
        },
    },
    "DeviceTvmSoftwareInventory": {
        "DeviceId": {"data_type": "string", "description": "Unique identifier for the device in the service"},
        "DeviceName": {"data_type": "string", "description": "Fully qualified domain name (FQDN) of the device"},
        "OSPlatform": {
            "data_type": "string",
            "description": "Platform of the operating system running on the device. This indicates specific operating systems, including variations within the same family, such as Windows 11, Windows 10 and Windows 7.",
        },
        "OSVersion": {"data_type": "string", "description": "Version of the operating system running on the device"},
        "OSArchitecture": {
            "data_type": "string",
            "description": "Architecture of the operating system running on the device",
        },
        "SoftwareVendor": {"data_type": "string", "description": "Name of the software vendor"},
        "SoftwareName": {"data_type": "string", "description": "Name of the software product"},
        "SoftwareVersion": {"data_type": "string", "description": "Version number of the software product"},
        "EndOfSupportStatus": {
            "data_type": "string",
            "description": "Indicates the lifecycle stage of the software product relative to its specified end-of-support (EOS) or end-of-life (EOL) date",
        },
        "EndOfSupportDate": {
            "data_type": "datetime",
            "description": "End-of-support (EOS) or end-of-life (EOL) date of the software product",
        },
        "ProductCodeCpe": {
            "data_type": "string",
            "description": "The standard Common Platform Enumeration (CPE) name of the software product version or 'not available' where there's no CPE",
        },
    },
    "DeviceTvmSoftwareVulnerabilities": {
        "DeviceId": {"data_type": "string", "description": "Unique identifier for the device in the service"},
        "DeviceName": {"data_type": "string", "description": "Fully qualified domain name (FQDN) of the device"},
        "OSPlatform": {
            "data_type": "string",
            "description": "Platform of the operating system running on the device. Indicates specific operating systems, including variations within the same family, such as Windows 11, Windows 10, and Windows 7.",
        },
        "OSVersion": {"data_type": "string", "description": "Version of the operating system running on the device"},
        "OSArchitecture": {
            "data_type": "string",
            "description": "Architecture of the operating system running on the device",
        },
        "SoftwareVendor": {"data_type": "string", "description": "Name of the software publisher"},
        "SoftwareName": {"data_type": "string", "description": "Name of the software product"},
        "SoftwareVersion": {"data_type": "string", "description": "Version number of the software product"},
        "CveId": {
            "data_type": "string",
            "description": "Unique identifier assigned to the security vulnerability under the Common Vulnerabilities and Exposures (CVE) system",
        },
        "VulnerabilitySeverityLevel": {
            "data_type": "string",
            "description": "Severity level assigned to the security vulnerability based on the CVSS score and dynamic factors influenced by the threat landscape",
        },
        "RecommendedSecurityUpdate": {
            "data_type": "string",
            "description": "Name or description of the security update provided by the software publisher to address the vulnerability",
        },
        "RecommendedSecurityUpdateId": {
            "data_type": "string",
            "description": "Identifier of the applicable security updates or identifier for the corresponding guidance or knowledge base (KB) articles",
        },
        "CveTags": {
            "data_type": "dynamic",
            "description": "Array of tags relevant to the CVE; example: ZeroDay, NoSecurityUpdate",
        },
    },
    "DeviceTvmSoftwareVulnerabilitiesKB": {
        "CveId": {
            "data_type": "string",
            "description": "Unique identifier assigned to the security vulnerability under the Common Vulnerabilities and Exposures (CVE) system",
        },
        "CvssScore": {
            "data_type": "string",
            "description": "Severity score assigned to the security vulnerability under the Common Vulnerability Scoring System (CVSS)",
        },
        "IsExploitAvailable": {
            "data_type": "boolean",
            "description": "Indicates whether exploit code for the vulnerability is publicly available",
        },
        "VulnerabilitySeverityLevel": {
            "data_type": "string",
            "description": "Severity level assigned to the security vulnerability based on the CVSS score and dynamic factors influenced by the threat landscape",
        },
        "LastModifiedTime": {
            "data_type": "datetime",
            "description": "Date and time the item or related metadata was last modified",
        },
        "PublishedDate": {"data_type": "datetime", "description": "Date vulnerability was disclosed to the public"},
        "VulnerabilityDescription": {
            "data_type": "string",
            "description": "Description of the vulnerability and associated risks",
        },
        "AffectedSoftware": {
            "data_type": "dynamic",
            "description": "List of all software products affected by the vulnerability",
        },
    },
    "EmailAttachmentInfo": {
        "Timestamp": {"data_type": "datetime", "description": "Date and time when the event was recorded"},
        "NetworkMessageId": {
            "data_type": "string",
            "description": "Unique identifier for the email, generated by Microsoft 365",
        },
        "SenderFromAddress": {
            "data_type": "string",
            "description": "Sender email address in the FROM header, which is visible to email recipients on their email clients",
        },
        "SenderDisplayName": {
            "data_type": "string",
            "description": "Name of the sender displayed in the address book, typically a combination of a given or first name, a middle initial, and a last name or surname",
        },
        "SenderObjectId": {
            "data_type": "string",
            "description": "Unique identifier for the sender's account in Microsoft Entra ID",
        },
        "RecipientEmailAddress": {
            "data_type": "string",
            "description": "Email address of the recipient, or email address of the recipient after distribution list expansion",
        },
        "RecipientObjectId": {
            "data_type": "string",
            "description": "Unique identifier for the email recipient in Microsoft Entra ID",
        },
        "FileName": {"data_type": "string", "description": "Name of the file that the recorded action was applied to"},
        "FileType": {"data_type": "string", "description": "File extension type"},
        "SHA256": {
            "data_type": "string",
            "description": "SHA-256 of the file that the recorded action was applied to. This field is usually not populated — use the SHA1 column when available.",
        },
        "FileSize": {"data_type": "long", "description": "Size of the file in bytes"},
        "ThreatTypes": {
            "data_type": "string",
            "description": "Verdict from the email filtering stack on whether the email contains malware, phishing, or other threats",
        },
        "ThreatNames": {"data_type": "string", "description": "Detection name for malware or other threats found"},
        "DetectionMethods": {
            "data_type": "string",
            "description": "Methods used to detect malware, phishing, or other threats found in the email",
        },
        "ReportId": {
            "data_type": "string",
            "description": "Event identifier based on a repeating counter. To identify unique events, this column must be used in conjunction with the DeviceName and Timestamp columns.",
        },
    },
    "EmailEvents": {
        "Timestamp": {"data_type": "datetime", "description": "Date and time when the event was recorded"},
        "NetworkMessageId": {
            "data_type": "string",
            "description": "Unique identifier for the email, generated by Microsoft 365",
        },
        "InternetMessageId": {
            "data_type": "string",
            "description": "Public-facing identifier for the email that is set by the sending email system",
        },
        "SenderMailFromAddress": {
            "data_type": "string",
            "description": "Sender email address in the MAIL FROM header, also known as the envelope sender or the Return-Path address",
        },
        "SenderFromAddress": {
            "data_type": "string",
            "description": "Sender email address in the FROM header, which is visible to email recipients on their email clients",
        },
        "SenderDisplayName": {
            "data_type": "string",
            "description": "Name of the sender displayed in the address book, typically a combination of a given or first name, a middle initial, and a last name or surname",
        },
        "SenderObjectId": {
            "data_type": "string",
            "description": "Unique identifier for the sender's account in Microsoft Entra ID",
        },
        "SenderMailFromDomain": {
            "data_type": "string",
            "description": "Sender domain in the MAIL FROM header, also known as the envelope sender or the Return-Path address",
        },
        "SenderFromDomain": {
            "data_type": "string",
            "description": "Sender domain in the FROM header, which is visible to email recipients on their email clients",
        },
        "SenderIPv4": {
            "data_type": "string",
            "description": "IPv4 address of the last detected mail server that relayed the message",
        },
        "SenderIPv6": {
            "data_type": "string",
            "description": "IPv6 address of the last detected mail server that relayed the message",
        },
        "RecipientEmailAddress": {
            "data_type": "string",
            "description": "Email address of the recipient, or email address of the recipient after distribution list expansion",
        },
        "RecipientObjectId": {
            "data_type": "string",
            "description": "Unique identifier for the email recipient in Microsoft Entra ID",
        },
        "Subject": {"data_type": "string", "description": "Subject of the email"},
        "EmailClusterId": {
            "data_type": "long",
            "description": "Identifier for the group of similar emails clustered based on heuristic analysis of their contents",
        },
        "EmailDirection": {
            "data_type": "string",
            "description": "Direction of the email relative to your network:  Inbound, Outbound, Intra-org",
        },
        "DeliveryAction": {
            "data_type": "string",
            "description": "Delivery action of the email: Delivered, Junked, Blocked, or Replaced",
        },
        "DeliveryLocation": {
            "data_type": "string",
            "description": "Location where the email was delivered: Inbox/Folder, On-premises/External, Junk, Quarantine, Failed, Dropped, Deleted items",
        },
        "ThreatTypes": {
            "data_type": "string",
            "description": "Verdict from the email filtering stack on whether the email contains malware, phishing, or other threats",
        },
        "ThreatNames": {"data_type": "string", "description": "Detection name for malware or other threats found"},
        "DetectionMethods": {
            "data_type": "string",
            "description": "Methods used to detect malware, phishing, or other threats found in the email",
        },
        "ConfidenceLevel": {
            "data_type": "string",
            "description": 'List of confidence levels of any spam or phishing verdicts. For spam, this column shows the spam confidence level (SCL), indicating if the email was skipped (-1), found to be not spam (0,1), found to be spam with moderate confidence (5,6), or found to be spam with high confidence (9). For phishing, this column displays whether the confidence level is "High" or "Low".',
        },
        "BulkComplaintLevel": {
            "data_type": "int",
            "description": "Threshold assigned to email from bulk mailers, a high bulk complaint level (BCL) means the email is more likely to generate complaints, and thus more likely to be spam",
        },
        "EmailAction": {
            "data_type": "string",
            "description": "Final action taken on the email based on filter verdict, policies, and user actions:  Move message to junk mail folder, Add X-header, Modify subject, Redirect message, Delete message, send to quarantine, No action taken, Bcc message",
        },
        "EmailActionPolicy": {
            "data_type": "string",
            "description": "Action policy that took effect: Antispam high-confidence, Antispam, Antispam bulk mail, Antispam phishing, Anti-phishing domain impersonation, Anti-phishing user impersonation, Anti-phishing spoof, Anti-phishing graph impersonation, Antimalware, Safe Attachments, Enterprise Transport Rules (ETR)",
        },
        "EmailActionPolicyGuid": {
            "data_type": "string",
            "description": "Unique identifier for the policy that determined the final mail action",
        },
        "AuthenticationDetails": {
            "data_type": "string",
            "description": "List of pass or fail verdicts by email authentication protocols like DMARC, DKIM, SPF or a combination of multiple authentication types (CompAuth)",
        },
        "AttachmentCount": {"data_type": "int", "description": "Number of attachments in the email"},
        "UrlCount": {"data_type": "int", "description": "Number of embedded URLs in the email"},
        "EmailLanguage": {"data_type": "string", "description": "Detected language of the email content"},
        "Connectors": {
            "data_type": "string",
            "description": "Custom instructions that define organizational mail flow and how the email was routed",
        },
        "OrgLevelAction": {
            "data_type": "string",
            "description": "Action taken on the email in response to matches to a policy defined at the organizational level",
        },
        "OrgLevelPolicy": {
            "data_type": "string",
            "description": "Organizational policy that triggered the action taken on the email",
        },
        "UserLevelAction": {
            "data_type": "string",
            "description": "Action taken on the email in response to matches to a mailbox policy defined by the recipient",
        },
        "UserLevelPolicy": {
            "data_type": "string",
            "description": "End-user mailbox policy that triggered the action taken on the email",
        },
        "ReportId": {
            "data_type": "string",
            "description": "Event identifier based on a repeating counter. To identify unique events, this column must be used in conjunction with the DeviceName and Timestamp columns.",
        },
        "AdditionalFields": {"data_type": "string", "description": "Additional information about the entity or event"},
        "LatestDeliveryLocation`*": {"data_type": "string", "description": "Last known location of the email"},
        "LatestDeliveryAction`*": {
            "data_type": "string",
            "description": "Last known action attempted on an email by the service or by an admin through manual remediation",
        },
    },
    "EmailPostDeliveryEvents": {
        "Timestamp": {"data_type": "datetime", "description": "Date and time when the event was recorded"},
        "NetworkMessageId": {
            "data_type": "string",
            "description": "Unique identifier for the email, generated by Microsoft 365",
        },
        "InternetMessageId": {
            "data_type": "string",
            "description": "Public-facing identifier for the email that is set by the sending email system",
        },
        "Action": {"data_type": "string", "description": "Action taken on the entity"},
        "ActionType": {
            "data_type": "string",
            "description": "Type of activity that triggered the event: Manual remediation, Phish ZAP, Malware ZAP",
        },
        "ActionTrigger": {
            "data_type": "string",
            "description": "Indicates whether an action was triggered by an administrator (manually or through approval of a pending automated action), or by some special mechanism, such as a ZAP or Dynamic Delivery",
        },
        "ActionResult": {"data_type": "string", "description": "Result of the action"},
        "RecipientEmailAddress": {
            "data_type": "string",
            "description": "Email address of the recipient, or email address of the recipient after distribution list expansion",
        },
        "DeliveryLocation": {
            "data_type": "string",
            "description": "Location where the email was delivered: Inbox/Folder, On-premises/External, Junk, Quarantine, Failed, Dropped, Deleted items",
        },
        "ThreatTypes": {
            "data_type": "string",
            "description": "Verdict from the email filtering stack on whether the email contains malware, phishing, or other threats",
        },
        "DetectionMethods": {
            "data_type": "string",
            "description": "Methods used to detect malware, phishing, or other threats found in the email",
        },
        "ReportId": {
            "data_type": "string",
            "description": "Event identifier based on a repeating counter. To identify unique events, this column must be used in conjunction with the DeviceName and Timestamp columns.",
        },
    },
    "EmailUrlInfo": {
        "Timestamp": {"data_type": "datetime", "description": "Date and time when the event was recorded"},
        "NetworkMessageId": {
            "data_type": "string",
            "description": "Unique identifier for the email, generated by Microsoft 365",
        },
        "Url": {"data_type": "string", "description": "Full URL in the email subject, body, or attachment"},
        "UrlDomain": {"data_type": "string", "description": "Domain name or host name of the URL"},
        "UrlLocation": {"data_type": "string", "description": "Indicates which part of the email the URL is located"},
        "ReportId": {
            "data_type": "string",
            "description": "Event identifier based on a repeating counter. To identify unique events, this column must be used in conjunction with the DeviceName and Timestamp columns",
        },
    },
    "ExposureGraphEdges": {
        "EdgeId": {"data_type": "string", "description": "Unique identifier for the relationship/edge"},
        "EdgeLabel": {"data_type": "string", "description": 'The edge label like "routes traffic to"'},
        "SourceNodeId": {"data_type": "string", "description": "Node ID of the edge's source"},
        "SourceNodeName": {"data_type": "string", "description": "Source node display name"},
        "SourceNodeLabel": {"data_type": "string", "description": "Source node label"},
        "SourceNodeCategories": {
            "data_type": "dynamic",
            "description": "Categories list of the source node in JSON format",
        },
        "TargetNodeId": {"data_type": "string", "description": "Node ID of the edge's target"},
        "TargetNodeName": {"data_type": "string", "description": "Display name of the target node"},
        "TargetNodeLabel": {"data_type": "string", "description": "Target node label"},
        "TargetNodeCategories": {
            "data_type": "dynamic",
            "description": "The categories list of the target node in JSON format",
        },
        "EdgeProperties": {
            "data_type": "dynamic",
            "description": "Optional data relevant for the relationship between the nodes in JSON format",
        },
    },
    "ExposureGraphNodes": {
        "NodeId": {"data_type": "string", "description": "Unique node identifier"},
        "NodeLabel": {"data_type": "string", "description": "Node label"},
        "NodeName": {"data_type": "string", "description": "Node display name"},
        "Categories": {"data_type": "dynamic", "description": "Categories of the node in JSON format"},
        "NodeProperties": {
            "data_type": "dynamic",
            "description": "Properties of the node, including insights related to the resource, such as whether the resource is exposed to the internet, or vulnerable to remote code execution. Values are JSON formatted raw data (unstructured).",
        },
        "EntityIds": {"data_type": "dynamic", "description": "All known node identifiers in JSON format"},
    },
    "IdentityDirectoryEvents": {
        "Timestamp": {"data_type": "datetime", "description": "Date and time when the event was recorded"},
        "ActionType": {
            "data_type": "string",
            "description": "Type of activity that triggered the event. See the [in-portal schema reference](advanced-hunting-schema-tables.md?#get-schema-information-in-the-security-center) for details",
        },
        "Application": {"data_type": "string", "description": "Application that performed the recorded action"},
        "TargetAccountUpn": {
            "data_type": "string",
            "description": "User principal name (UPN) of the account that the recorded action was applied to",
        },
        "TargetAccountDisplayName": {
            "data_type": "string",
            "description": "Display name of the account that the recorded action was applied to",
        },
        "TargetDeviceName": {
            "data_type": "string",
            "description": "Fully qualified domain name (FQDN) of the device that the recorded action was applied to",
        },
        "DestinationDeviceName": {
            "data_type": "string",
            "description": "Name of the device running the server application that processed the recorded action",
        },
        "DestinationIPAddress": {
            "data_type": "string",
            "description": "IP address of the device running the server application that processed the recorded action",
        },
        "DestinationPort": {"data_type": "int", "description": "Destination port of the activity"},
        "Protocol": {"data_type": "string", "description": "Protocol used during the communication"},
        "AccountName": {"data_type": "string", "description": "User name of the account"},
        "AccountDomain": {"data_type": "string", "description": "Domain of the account"},
        "AccountUpn": {"data_type": "string", "description": "User principal name (UPN) of the account"},
        "AccountSid": {"data_type": "string", "description": "Security Identifier (SID) of the account"},
        "AccountObjectId": {
            "data_type": "string",
            "description": "Unique identifier for the account in Microsoft Entra ID",
        },
        "AccountDisplayName": {
            "data_type": "string",
            "description": "Name of the account user displayed in the address book. Typically a combination of a given or first name, a middle initial, and a last name or surname.",
        },
        "DeviceName": {"data_type": "string", "description": "Fully qualified domain name (FQDN) of the device"},
        "IPAddress": {"data_type": "string", "description": "IP address assigned to the device during communication"},
        "Port": {"data_type": "int", "description": "TCP port used during communication"},
        "Location": {
            "data_type": "string",
            "description": "City, country/region, or other geographic location associated with the event",
        },
        "ISP": {"data_type": "string", "description": "Internet service provider associated with the IP address"},
        "ReportId": {"data_type": "string", "description": "Unique identifier for the event"},
        "AdditionalFields": {"data_type": "dynamic", "description": "Additional information about the entity or event"},
    },
    "IdentityInfo": {
        "Timestamp` [*](#mdi-only)": {
            "data_type": "datetime",
            "description": "The date and time that the line was written to the database. <br><br>This is used when there are multiple lines for each identity, such as when a change is detected, or if 24 hours have passed since the last database line was added.",
        },
        "ReportId` [*](#mdi-only)": {"data_type": "string", "description": "Unique identifier for the event"},
        "AccountObjectId": {
            "data_type": "string",
            "description": "Unique identifier for the account in Microsoft Entra ID",
        },
        "AccountUpn": {"data_type": "string", "description": "User principal name (UPN) of the account"},
        "OnPremSid": {"data_type": "string", "description": "On-premises security identifier (SID) of the account"},
        "AccountDisplayName": {
            "data_type": "string",
            "description": "Name of the account user displayed in the address book. Typically a combination of a given or first name, a middle initial, and a last name or surname.",
        },
        "AccountName": {"data_type": "string", "description": "User name of the account"},
        "AccountDomain` [*](#mdi-only)": {"data_type": "string", "description": "Domain of the account"},
        "Type` [*](#mdi-only)": {"data_type": "string", "description": "Type of record"},
        "DistinguishedName` [*](#mdi-only)": {
            "data_type": "string",
            "description": "The user's [distinguished name](/previous-versions/windows/desktop/ldap/distinguished-names)",
        },
        "CloudSid": {"data_type": "string", "description": "Cloud security identifier of the account"},
        "GivenName": {"data_type": "string", "description": "Given name or first name of the account user"},
        "Surname": {"data_type": "string", "description": "Surname, family name, or last name of the account user"},
        "Department": {"data_type": "string", "description": "Name of the department that the account user belongs to"},
        "JobTitle": {"data_type": "string", "description": "Job title of the account user"},
        "EmailAddress": {"data_type": "string", "description": "SMTP address of the account"},
        "SipProxyAddress": {
            "data_type": "string",
            "description": "Voice over IP (VOIP) session initiation protocol (SIP) address of the account",
        },
        "Address": {"data_type": "string", "description": "Address of the account user"},
        "City": {"data_type": "string", "description": "City where the account user is located"},
        "Country": {"data_type": "string", "description": "Country/Region where the account user is located"},
        "IsAccountEnabled": {"data_type": "boolean", "description": "Indicates whether the account is enabled or not"},
        "Manager` [*](#mdi-only)": {"data_type": "string", "description": "The listed manager of the account user"},
        "Phone` [*](#mdi-only)": {"data_type": "string", "description": "The listed phone number of the account user"},
        "CreatedDateTime` [*](#mdi-only)": {
            "data_type": "datetime",
            "description": "Date and time when the account user was created",
        },
        "SourceProvider` [*](#mdi-only)": {
            "data_type": "string",
            "description": "The identity's source, such as Microsoft Entra ID, Active Directory, or a [hybrid identity](/azure/active-directory/hybrid/what-is-provisioning) synchronized from Active Directory to Azure Active Directory",
        },
        "ChangeSource` [*](#mdi-only)": {
            "data_type": "string",
            "description": "Identifies which identity provider or process triggered the addition of the new row. For example, the `System-UserPersistence` value is used for any rows added by an automated process.",
        },
        "Tags` [*](#mdi-only)": {
            "data_type": "dynamic",
            "description": "Tags assigned to the account user by Defender for Identity",
        },
        "AssignedRoles` [*](#mdi-only)": {
            "data_type": "dynamic",
            "description": "For identities from Microsoft Entra-only, the roles assigned to the account user",
        },
        "TenantId": {
            "data_type": "string",
            "description": "Unique identifier representing your organization's instance of Microsoft Entra ID",
        },
        "SourceSystem` [*](#mdi-only)": {"data_type": "string", "description": "The source system for the record"},
    },
    "IdentityLogonEvents": {
        "Timestamp": {"data_type": "datetime", "description": "Date and time when the event was recorded"},
        "ActionType": {
            "data_type": "string",
            "description": "Type of activity that triggered the event. See the [in-portal schema reference](advanced-hunting-schema-tables.md?#get-schema-information-in-the-security-center) for details",
        },
        "Application": {"data_type": "string", "description": "Application that performed the recorded action"},
        "LogonType": {
            "data_type": "string",
            "description": "Type of logon session. For more information, see [Supported logon types](#supported-logon-types).",
        },
        "Protocol": {"data_type": "string", "description": "Network protocol used"},
        "FailureReason": {
            "data_type": "string",
            "description": "Information explaining why the recorded action failed",
        },
        "AccountName": {"data_type": "string", "description": "User name of the account"},
        "AccountDomain": {"data_type": "string", "description": "Domain of the account"},
        "AccountUpn": {"data_type": "string", "description": "User principal name (UPN) of the account"},
        "AccountSid": {"data_type": "string", "description": "Security Identifier (SID) of the account"},
        "AccountObjectId": {
            "data_type": "string",
            "description": "Unique identifier for the account in Microsoft Entra ID",
        },
        "AccountDisplayName": {
            "data_type": "string",
            "description": "Name of the account user displayed in the address book. Typically a combination of a given or first name, a middle initial, and a last name or surname.",
        },
        "DeviceName": {"data_type": "string", "description": "Fully qualified domain name (FQDN) of the device"},
        "DeviceType": {
            "data_type": "string",
            "description": "Type of device based on purpose and functionality, such as network device, workstation, server, mobile, gaming console, or printer",
        },
        "OSPlatform": {
            "data_type": "string",
            "description": "Platform of the operating system running on the device. This indicates specific operating systems, including variations within the same family, such as Windows 11, Windows 10 and Windows 7.",
        },
        "IPAddress": {
            "data_type": "string",
            "description": "IP address assigned to the endpoint and used during related network communications",
        },
        "Port": {"data_type": "int", "description": "TCP port used during communication"},
        "DestinationDeviceName": {
            "data_type": "string",
            "description": "Name of the device running the server application that processed the recorded action",
        },
        "DestinationIPAddress": {
            "data_type": "string",
            "description": "IP address of the device running the server application that processed the recorded action",
        },
        "DestinationPort": {"data_type": "int", "description": "Destination port of related network communications"},
        "TargetDeviceName": {
            "data_type": "string",
            "description": "Fully qualified domain name (FQDN) of the device that the recorded action was applied to",
        },
        "TargetAccountDisplayName": {
            "data_type": "string",
            "description": "Display name of the account that the recorded action was applied to",
        },
        "Location": {
            "data_type": "string",
            "description": "City, country/region, or other geographic location associated with the event",
        },
        "Isp": {
            "data_type": "string",
            "description": "Internet service provider (ISP) associated with the endpoint IP address",
        },
        "ReportId": {"data_type": "string", "description": "Unique identifier for the event"},
        "AdditionalFields": {"data_type": "dynamic", "description": "Additional information about the entity or event"},
    },
    "IdentityQueryEvents": {
        "Timestamp": {"data_type": "datetime", "description": "Date and time when the event was recorded"},
        "ActionType": {
            "data_type": "string",
            "description": "Type of activity that triggered the event. See the [in-portal schema reference](advanced-hunting-schema-tables.md?#get-schema-information-in-the-security-center) for details",
        },
        "Application": {"data_type": "string", "description": "Application that performed the recorded action"},
        "QueryType": {
            "data_type": "string",
            "description": "Type of query, such as QueryGroup, QueryUser, or EnumerateUsers",
        },
        "QueryTarget": {
            "data_type": "string",
            "description": "Name of user, group, device, domain, or any other entity type being queried",
        },
        "Query": {"data_type": "string", "description": "String used to run the query"},
        "Protocol": {"data_type": "string", "description": "Protocol used during the communication"},
        "AccountName": {"data_type": "string", "description": "User name of the account"},
        "AccountDomain": {"data_type": "string", "description": "Domain of the account"},
        "AccountUpn": {"data_type": "string", "description": "User principal name (UPN) of the account"},
        "AccountSid": {"data_type": "string", "description": "Security Identifier (SID) of the account"},
        "AccountObjectId": {
            "data_type": "string",
            "description": "Unique identifier for the account in Microsoft Entra ID",
        },
        "AccountDisplayName": {
            "data_type": "string",
            "description": "Name of the account user displayed in the address book. Typically a combination of a given or first name, a middle initial, and a last name or surname.",
        },
        "DeviceName": {"data_type": "string", "description": "Fully qualified domain name (FQDN) of the device"},
        "IPAddress": {
            "data_type": "string",
            "description": "IP address assigned to the endpoint and used during related network communications",
        },
        "Port": {"data_type": "int", "description": "TCP port used during communication"},
        "DestinationDeviceName": {
            "data_type": "string",
            "description": "Name of the device running the server application that processed the recorded action",
        },
        "DestinationIPAddress": {
            "data_type": "string",
            "description": "IP address of the device running the server application that processed the recorded action",
        },
        "DestinationPort": {"data_type": "int", "description": "Destination port of related network communications"},
        "TargetDeviceName": {
            "data_type": "string",
            "description": "Fully qualified domain name (FQDN) of the device that the recorded action was applied to",
        },
        "TargetAccountUpn": {
            "data_type": "string",
            "description": "User principal name (UPN) of the account that the recorded action was applied to",
        },
        "TargetAccountDisplayName": {
            "data_type": "string",
            "description": "Display name of the account that the recorded action was applied to",
        },
        "Location": {
            "data_type": "string",
            "description": "City, country/region, or other geographic location associated with the event",
        },
        "ReportId": {"data_type": "string", "description": "Unique identifier for the event"},
        "AdditionalFields": {"data_type": "dynamic", "description": "Additional information about the entity or event"},
    },
    "UrlClickEvents": {
        "Timestamp": {"data_type": "datetime", "description": "The date and time when the user clicked on the link"},
        "Url": {"data_type": "string", "description": "The full URL that was clicked on by the user"},
        "ActionType": {
            "data_type": "string",
            "description": "Indicates whether the click was allowed or blocked by Safe Links or blocked due to a tenant policy, for instance, from Tenant Allow Block list",
        },
        "AccountUpn": {
            "data_type": "string",
            "description": "User Principal Name of the account that clicked on the link",
        },
        "Workload": {
            "data_type": "string",
            "description": "The application from which the user clicked on the link, with the values being Email, Office, and Teams",
        },
        "NetworkMessageId": {
            "data_type": "string",
            "description": "The unique identifier for the email that contains the clicked link, generated by Microsoft 365",
        },
        "ThreatTypes": {
            "data_type": "string",
            "description": "Verdict at the time of click, which tells whether the URL led to malware, phish or other threats",
        },
        "DetectionMethods": {
            "data_type": "string",
            "description": "Detection technology that was used to identify the threat at the time of click",
        },
        "IPAddress": {
            "data_type": "string",
            "description": "Public IP address of the device from which the user clicked on the link",
        },
        "IsClickedThrough": {
            "data_type": "bool",
            "description": "Indicates whether the user was able to click through to the original URL (1) or not (0)",
        },
        "UrlChain": {
            "data_type": "string",
            "description": "For scenarios involving redirections, it includes URLs present in the redirection chain",
        },
        "ReportId": {
            "data_type": "string",
            "description": "The unique identifier for a click event. For clickthrough scenarios, report ID would have same value, and therefore it should be used to correlate a click event.",
        },
    },
}
