package org.opensearch.securityanalytics.helpers;

import java.util.Locale;

public class DocsHelper {

    public static String randomDoc() {
        return "{\n" +
                "\"@timestamp\":\"2020-02-04T14:59:39.343541+00:00\",\n" +
                "\"EventTime\":\"2020-02-04T14:59:39.343541+00:00\",\n" +
                "\"HostName\":\"EC2AMAZ-EPO7HKA\",\n" +
                "\"Keywords\":\"9223372036854775808\",\n" +
                "\"SeverityValue\":2,\n" +
                "\"Severity\":\"INFO\",\n" +
                "\"EventID\":22,\n" +
                "\"SourceName\":\"Microsoft-Windows-Sysmon\",\n" +
                "\"SourceIp\":\"1.2.3.4\",\n" +
                "\"ProviderGuid\":\"{5770385F-C22A-43E0-BF4C-06F5698FFBD9}\",\n" +
                "\"Version\":5,\n" +
                "\"TaskValue\":22,\n" +
                "\"OpcodeValue\":0,\n" +
                "\"RecordNumber\":9532,\n" +
                "\"ExecutionProcessID\":1996,\n" +
                "\"ExecutionThreadID\":2616,\n" +
                "\"Channel\":\"Microsoft-Windows-Sysmon/Operational\",\n" +
                "\"Domain\":\"NTAUTHORITY\",\n" +
                "\"AccountName\":\"SYSTEM\",\n" +
                "\"UserID\":\"S-1-5-18\",\n" +
                "\"AccountType\":\"User\",\n" +
                "\"Message\":\"Dns query:\\r\\nRuleName: \\r\\nUtcTime: 2020-02-04 14:59:38.349\\r\\nProcessGuid: {b3c285a4-3cda-5dc0-0000-001077270b00}\\r\\nProcessId: 1904\\r\\nQueryName: EC2AMAZ-EPO7HKA\\r\\nQueryStatus: 0\\r\\nQueryResults: 172.31.46.38;\\r\\nImage: C:\\\\Program Files\\\\nxlog\\\\nxlog.exe\",\n" +
                "\"Category\":\"Dns query (rule: DnsQuery)\",\n" +
                "\"Opcode\":\"Info\",\n" +
                "\"UtcTime\":\"2020-02-04 14:59:38.349\",\n" +
                "\"ProcessGuid\":\"{b3c285a4-3cda-5dc0-0000-001077270b00}\",\n" +
                "\"ProcessId\":\"1904\",\"QueryName\":\"EC2AMAZ-EPO7HKA\",\"QueryStatus\":\"0\",\n" +
                "\"QueryResults\":\"172.31.46.38;\",\n" +
                "\"Image\":\"C:\\\\Program Files\\\\nxlog\\\\regsvr32.exe\",\n" +
                "\"EventReceivedTime\":\"2020-02-04T14:59:40.780905+00:00\",\n" +
                "\"SourceModuleName\":\"in\",\n" +
                "\"SourceModuleType\":\"im_msvistalog\",\n" +
                "\"CommandLine\": \"eachtest\",\n" +
                "\"Initiated\": \"true\"\n" +
                "}";
    }

    public static String randomDoc(int severity, int version, String opCode) {
        String doc = "{\n" +
                "\"EventTime\":\"2020-02-04T14:59:39.343541+00:00\",\n" +
                "\"HostName\":\"EC2AMAZ-EPO7HKA\",\n" +
                "\"Keywords\":\"9223372036854775808\",\n" +
                "\"SeverityValue\":%s,\n" +
                "\"Severity\":\"INFO\",\n" +
                "\"EventID\":22,\n" +
                "\"SourceName\":\"Microsoft-Windows-Sysmon\",\n" +
                "\"ProviderGuid\":\"{5770385F-C22A-43E0-BF4C-06F5698FFBD9}\",\n" +
                "\"Version\":%s,\n" +
                "\"TaskValue\":22,\n" +
                "\"OpcodeValue\":0,\n" +
                "\"RecordNumber\":9532,\n" +
                "\"ExecutionProcessID\":1996,\n" +
                "\"ExecutionThreadID\":2616,\n" +
                "\"Channel\":\"Microsoft-Windows-Sysmon/Operational\",\n" +
                "\"Domain\":\"NT AUTHORITY\",\n" +
                "\"AccountName\":\"SYSTEM\",\n" +
                "\"UserID\":\"S-1-5-18\",\n" +
                "\"AccountType\":\"User\",\n" +
                "\"Message\":\"Dns query:\\r\\nRuleName: \\r\\nUtcTime: 2020-02-04 14:59:38.349\\r\\nProcessGuid: {b3c285a4-3cda-5dc0-0000-001077270b00}\\r\\nProcessId: 1904\\r\\nQueryName: EC2AMAZ-EPO7HKA\\r\\nQueryStatus: 0\\r\\nQueryResults: 172.31.46.38;\\r\\nImage: C:\\\\Program Files\\\\nxlog\\\\nxlog.exe\",\n" +
                "\"Category\":\"Dns query (rule: DnsQuery)\",\n" +
                "\"Opcode\":\"%s\",\n" +
                "\"UtcTime\":\"2020-02-04 14:59:38.349\",\n" +
                "\"ProcessGuid\":\"{b3c285a4-3cda-5dc0-0000-001077270b00}\",\n" +
                "\"ProcessId\":\"1904\",\"QueryName\":\"EC2AMAZ-EPO7HKA\",\"QueryStatus\":\"0\",\n" +
                "\"QueryResults\":\"172.31.46.38;\",\n" +
                "\"Image\":\"C:\\\\Program Files\\\\nxlog\\\\regsvr32.exe\",\n" +
                "\"EventReceivedTime\":\"2020-02-04T14:59:40.780905+00:00\",\n" +
                "\"SourceModuleName\":\"in\",\n" +
                "\"SourceModuleType\":\"im_msvistalog\",\n" +
                "\"CommandLine\": \"eachtest\",\n" +
                "\"Initiated\": \"true\"\n" +
                "}";
        return String.format(Locale.ROOT, doc, severity, version, opCode);

    }

    // TODO: not used, can we remove?
    public static String randomNetFlowDoc() {
        return "{" +
                "  \"netflow.event_data.SourceAddress\":\"10.50.221.10\"," +
                "  \"netflow.event_data.DestinationPort\":1234," +
                "  \"netflow.event_data.DestAddress\":\"10.53.111.14\"," +
                "  \"netflow.event_data.SourcePort\":4444" +
                "}";
    }

    public static String randomDocForNotCondition(int severity, int version, String opCode) {
        String doc = "{\n" +
                "\"EventTime\":\"2020-02-04T14:59:39.343541+00:00\",\n" +
                "\"HostName\":\"EC2AMAZ-EPO7HKA\",\n" +
                "\"Keywords\":\"9223372036854775808\",\n" +
                "\"SeverityValue\":%s,\n" +
                "\"Severity\":\"INFO\",\n" +
                "\"EventID\":22,\n" +
                "\"SourceName\":\"Microsoft-Windows-Sysmon\",\n" +
                "\"ProviderGuid\":\"{5770385F-C22A-43E0-BF4C-06F5698FFBD9}\",\n" +
                "\"Version\":%s,\n" +
                "\"TaskValue\":22,\n" +
                "\"OpcodeValue\":0,\n" +
                "\"RecordNumber\":9532,\n" +
                "\"ExecutionProcessID\":1996,\n" +
                "\"ExecutionThreadID\":2616,\n" +
                "\"Channel\":\"Microsoft-Windows-Sysmon/Operational\",\n" +
                "\"Domain\":\"NT AUTHORITY\",\n" +
                "\"UserID\":\"S-1-5-18\",\n" +
                "\"AccountType\":\"User\",\n" +
                "\"Message\":\"Dns query:\\r\\nRuleName: \\r\\nUtcTime: 2020-02-04 14:59:38.349\\r\\nProcessGuid: {b3c285a4-3cda-5dc0-0000-001077270b00}\\r\\nProcessId: 1904\\r\\nQueryName: EC2AMAZ-EPO7HKA\\r\\nQueryStatus: 0\\r\\nQueryResults: 172.31.46.38;\\r\\nImage: C:\\\\Program Files\\\\nxlog\\\\nxlog.exe\",\n" +
                "\"Category\":\"Dns query (rule: DnsQuery)\",\n" +
                "\"Opcode\":\"%s\",\n" +
                "\"UtcTime\":\"2020-02-04 14:59:38.349\",\n" +
                "\"ProcessGuid\":\"{b3c285a4-3cda-5dc0-0000-001077270b00}\",\n" +
                "\"ProcessId\":\"1904\",\"QueryName\":\"EC2AMAZ-EPO7HKA\",\"QueryStatus\":\"0\",\n" +
                "\"QueryResults\":\"172.31.46.38;\",\n" +
                "\"Image\":\"C:\\\\Program Files\\\\nxlog\\\\regsvr32.exe\",\n" +
                "\"EventReceivedTime\":\"2020-02-04T14:59:40.780905+00:00\",\n" +
                "\"SourceModuleName\":\"in\",\n" +
                "\"SourceModuleType\":\"im_msvistalog\",\n" +
                "\"CommandLine\": \"eachtest\",\n" +
                "\"Initiated\": \"true\"\n" +
                "}";
        return String.format(Locale.ROOT, doc, severity, version, opCode);

    }

    public static String randomDocOnlyNumericAndDate(int severity, int version, String opCode) {
        String doc = "{\n" +
                "\"EventTime\":\"2020-02-04T14:59:39.343541+00:00\",\n" +
                "\"ExecutionProcessID\":2001,\n" +
                "\"ExecutionThreadID\":2616,\n" +
                "\"EventID\": 1234,\n" +
                "\"TaskValue\":22\n" +
                "}";
        return String.format(Locale.ROOT, doc, severity, version, opCode);
    }

    public static String randomDocOnlyNumericAndText(int severity, int version, String opCode) {
        String doc = "{\n" +
                "\"TaskName\":\"SYSTEM\",\n" +
                "\"ExecutionProcessID\":2001,\n" +
                "\"ExecutionThreadID\":2616,\n" +
                "\"EventID\": 1234,\n" +
                "\"TaskValue\":22\n" +
                "}";
        return String.format(Locale.ROOT, doc, severity, version, opCode);
    }

    //Add IPs in HostName field.
    public static String randomDocWithIpIoc(int severity, int version, String ioc) {
        String doc = "{\n" +
                "\"EventTime\":\"2020-02-04T14:59:39.343541+00:00\",\n" +
                "\"HostName\":\"%s\",\n" +
                "\"Keywords\":\"9223372036854775808\",\n" +
                "\"SeverityValue\":%s,\n" +
                "\"Severity\":\"INFO\",\n" +
                "\"EventID\":22,\n" +
                "\"SourceName\":\"Microsoft-Windows-Sysmon\",\n" +
                "\"ProviderGuid\":\"{5770385F-C22A-43E0-BF4C-06F5698FFBD9}\",\n" +
                "\"Version\":%s,\n" +
                "\"TaskValue\":22,\n" +
                "\"OpcodeValue\":0,\n" +
                "\"RecordNumber\":9532,\n" +
                "\"ExecutionProcessID\":1996,\n" +
                "\"ExecutionThreadID\":2616,\n" +
                "\"Channel\":\"Microsoft-Windows-Sysmon/Operational\",\n" +
                "\"Domain\":\"NT AUTHORITY\",\n" +
                "\"AccountName\":\"SYSTEM\",\n" +
                "\"UserID\":\"S-1-5-18\",\n" +
                "\"AccountType\":\"User\",\n" +
                "\"Message\":\"Dns query:\\r\\nRuleName: \\r\\nUtcTime: 2020-02-04 14:59:38.349\\r\\nProcessGuid: {b3c285a4-3cda-5dc0-0000-001077270b00}\\r\\nProcessId: 1904\\r\\nQueryName: EC2AMAZ-EPO7HKA\\r\\nQueryStatus: 0\\r\\nQueryResults: 172.31.46.38;\\r\\nImage: C:\\\\Program Files\\\\nxlog\\\\nxlog.exe\",\n" +
                "\"Category\":\"Dns query (rule: DnsQuery)\",\n" +
                "\"Opcode\":\"blahblah\",\n" +
                "\"UtcTime\":\"2020-02-04 14:59:38.349\",\n" +
                "\"ProcessGuid\":\"{b3c285a4-3cda-5dc0-0000-001077270b00}\",\n" +
                "\"ProcessId\":\"1904\",\"QueryName\":\"EC2AMAZ-EPO7HKA\",\"QueryStatus\":\"0\",\n" +
                "\"QueryResults\":\"172.31.46.38;\",\n" +
                "\"Image\":\"C:\\\\Program Files\\\\nxlog\\\\regsvr32.exe\",\n" +
                "\"EventReceivedTime\":\"2020-02-04T14:59:40.780905+00:00\",\n" +
                "\"SourceModuleName\":\"in\",\n" +
                "\"SourceModuleType\":\"im_msvistalog\",\n" +
                "\"CommandLine\": \"eachtest\",\n" +
                "\"Initiated\": \"true\"\n" +
                "}";
        return String.format(Locale.ROOT, doc, ioc, severity, version);

    }

    public static String randomDocWithNullField() {
        return "{\n" +
                "\"@timestamp\":\"2020-02-04T14:59:39.343541+00:00\",\n" +
                "\"EventTime\":\"2020-02-04T14:59:39.343541+00:00\",\n" +
                "\"HostName\":\"EC2AMAZ-EPO7HKA\",\n" +
                "\"Keywords\":\"9223372036854775808\",\n" +
                "\"SeverityValue\":2,\n" +
                "\"Severity\":\"INFO\",\n" +
                "\"EventID\":22,\n" +
                "\"SourceName\":\"Microsoft-Windows-Sysmon\",\n" +
                "\"ProviderGuid\":\"{5770385F-C22A-43E0-BF4C-06F5698FFBD9}\",\n" +
                "\"Version\":5,\n" +
                "\"TaskValue\":22,\n" +
                "\"OpcodeValue\":0,\n" +
                "\"RecordNumber\":null,\n" +
                "\"ExecutionProcessID\":1996,\n" +
                "\"ExecutionThreadID\":2616,\n" +
                "\"Channel\":\"Microsoft-Windows-Sysmon/Operational\",\n" +
                "\"Domain\":\"NTAUTHORITY\",\n" +
                "\"AccountName\":\"SYSTEM\",\n" +
                "\"UserID\":\"S-1-5-18\",\n" +
                "\"AccountType\":\"User\",\n" +
                "\"Message\":\"Dns query:\\r\\nRuleName: \\r\\nUtcTime: 2020-02-04 14:59:38.349\\r\\nProcessGuid: {b3c285a4-3cda-5dc0-0000-001077270b00}\\r\\nProcessId: 1904\\r\\nQueryName: EC2AMAZ-EPO7HKA\\r\\nQueryStatus: 0\\r\\nQueryResults: 172.31.46.38;\\r\\nImage: C:\\\\Program Files\\\\nxlog\\\\nxlog.exe\",\n" +
                "\"Category\":\"Dns query (rule: DnsQuery)\",\n" +
                "\"Opcode\":\"Info\",\n" +
                "\"UtcTime\":\"2020-02-04 14:59:38.349\",\n" +
                "\"ProcessGuid\":\"{b3c285a4-3cda-5dc0-0000-001077270b00}\",\n" +
                "\"ProcessId\":\"1904\",\"QueryName\":\"EC2AMAZ-EPO7HKA\",\"QueryStatus\":\"0\",\n" +
                "\"QueryResults\":\"172.31.46.38;\",\n" +
                "\"Image\":\"C:\\\\Program Files\\\\nxlog\\\\regsvr32.exe\",\n" +
                "\"EventReceivedTime\":\"2020-02-04T14:59:40.780905+00:00\",\n" +
                "\"SourceModuleName\":\"in\",\n" +
                "\"SourceModuleType\":\"im_msvistalog\",\n" +
                "\"CommandLine\": \"eachtest\",\n" +
                "\"Initiated\": \"true\"\n" +
                "}";
    }

    public static String randomNetworkDoc() {
        return "{\n" +
                "\"@timestamp\":\"2020-02-04T14:59:39.343541+00:00\",\n" +
                "\"EventTime\":\"2020-02-04T14:59:39.343541+00:00\",\n" +
                "\"HostName\":\"EC2AMAZ-EPO7HKA\",\n" +
                "\"Keywords\":\"9223372036854775808\",\n" +
                "\"SeverityValue\":2,\n" +
                "\"Severity\":\"INFO\",\n" +
                "\"EventID\":22,\n" +
                "\"SourceName\":\"Microsoft-Windows-Sysmon\",\n" +
                "\"SourceIp\":\"1.2.3.4\",\n" +
                "\"ProviderGuid\":\"{5770385F-C22A-43E0-BF4C-06F5698FFBD9}\",\n" +
                "\"Version\":5,\n" +
                "\"TaskValue\":22,\n" +
                "\"OpcodeValue\":0,\n" +
                "\"RecordNumber\":9532,\n" +
                "\"ExecutionProcessID\":1996,\n" +
                "\"ExecutionThreadID\":2616,\n" +
                "\"Channel\":\"Microsoft-Windows-Sysmon/Operational\",\n" +
                "\"Domain\":\"NTAUTHORITY\",\n" +
                "\"AccountName\":\"SYSTEM\",\n" +
                "\"UserID\":\"S-1-5-18\",\n" +
                "\"AccountType\":\"User\",\n" +
                "\"Message\":\"Dns query:\\r\\nRuleName: \\r\\nUtcTime: 2020-02-04 14:59:38.349\\r\\nProcessGuid: {b3c285a4-3cda-5dc0-0000-001077270b00}\\r\\nProcessId: 1904\\r\\nQueryName: EC2AMAZ-EPO7HKA\\r\\nQueryStatus: 0\\r\\nQueryResults: 172.31.46.38;\\r\\nImage: C:\\\\Program Files\\\\nxlog\\\\nxlog.exe\",\n" +
                "\"Category\":\"Dns query (rule: DnsQuery)\",\n" +
                "\"Opcode\":\"Info\",\n" +
                "\"UtcTime\":\"2020-02-04 14:59:38.349\",\n" +
                "\"ProcessGuid\":\"{b3c285a4-3cda-5dc0-0000-001077270b00}\",\n" +
                "\"ProcessId\":\"1904\",\"QueryName\":\"EC2AMAZ-EPO7HKA\",\"QueryStatus\":\"0\",\n" +
                "\"QueryResults\":\"172.31.46.38;\",\n" +
                "\"Image\":\"C:\\\\Program Files\\\\nxlog\\\\regsvr32.exe\",\n" +
                "\"EventReceivedTime\":\"2020-02-04T14:59:40.780905+00:00\",\n" +
                "\"SourceModuleName\":\"in\",\n" +
                "\"SourceModuleType\":\"im_msvistalog\",\n" +
                "\"CommandLine\": \"eachtest\",\n" +
                "\"id.orig_h\": \"123.12.123.12\",\n" +
                "\"Initiated\": \"true\"\n" +
                "}";
    }

    // TODO: not used, can we remove?
    public static String randomCloudtrailAggrDoc(String eventType, String accountId) {
        return "{\n" +
                "  \"AccountName\": \"" + accountId + "\",\n" +
                "  \"EventType\": \"" + eventType + "\"\n" +
                "}";
    }

    public static String randomVpcFlowDoc() {
        return "{\n" +
                "  \"version\": 1,\n" +
                "  \"account-id\": \"A12345\",\n" +
                "  \"interface-id\": \"I12345\",\n" +
                "  \"srcaddr\": \"1.2.3.4\",\n" +
                "  \"dstaddr\": \"4.5.6.7\",\n" +
                "  \"srcport\": 9000,\n" +
                "  \"dstport\": 8000,\n" +
                "  \"severity_id\": \"-1\",\n" +
                "  \"id.orig_h\": \"1.2.3.4\",\n" +
                "  \"class_name\": \"Network Activity\"\n" +
                "}";
    }

    public static String randomAdLdapDoc() {
        return "{\n" +
                "  \"azure.platformlogs.result_type\": 50126,\n" +
                "  \"azure.signinlogs.result_description\": \"Invalid username or password or Invalid on-premises username or password.\",\n" +
                "  \"azure.signinlogs.props.user_id\": \"DEYSUBHO\"\n" +
                "}";
    }

    public static String randomCloudtrailOcsfDoc() {
        return "{\n" +
                "  \"activity_id\": 8,\n" +
                "  \"activity_name\": \"Detach Policy\",\n" +
                "  \"actor\": {\n" +
                "    \"idp\": {\n" +
                "      \"name\": null\n" +
                "    },\n" +
                "    \"invoked_by\": null,\n" +
                "    \"session\": {\n" +
                "      \"created_time\": 1702510696000,\n" +
                "      \"issuer\": \"arn\",\n" +
                "      \"mfa\": false\n" +
                "    },\n" +
                "    \"user\": {\n" +
                "      \"account_uid\": \"\",\n" +
                "      \"credential_uid\": \"\",\n" +
                "      \"name\": null,\n" +
                "      \"type\": \"AssumedRole\",\n" +
                "      \"uid\": \"\",\n" +
                "      \"uuid\": \"\"\n" +
                "    }\n" +
                "  },\n" +
                "  \"api\": {\n" +
                "    \"operation\": \"CreateFunction\",\n" +
                "    \"request\": {\n" +
                "      \"uid\": \"0966237c-6279-43f4-a9d7-1eb416fca17d\"\n" +
                "    },\n" +
                "    \"response\": {\n" +
                "      \"error\": null,\n" +
                "      \"message\": null\n" +
                "    },\n" +
                "    \"service\": {\n" +
                "      \"name\": \"lambda.amazonaws.com\"\n" +
                "    },\n" +
                "    \"version\": null\n" +
                "  },\n" +
                "  \"category_name\": \"Audit Activity\",\n" +
                "  \"category_uid\": 3,\n" +
                "  \"class_name\": \"account_change\",\n" +
                "  \"class_uid\": 3001,\n" +
                "  \"cloud\": {\n" +
                "    \"provider\": \"AWS\",\n" +
                "    \"region\": \"us-east-1\"\n" +
                "  },\n" +
                "  \"dst_endpoint\": null,\n" +
                "  \"http_request\": {\n" +
                "    \"user_agent\": \"Boto3/1.26.90 Python/3.7.17 Linux/test.amzn2.x86_64 exec-env/AWS_Lambda_python3.7 Botocore/1.29.90\"\n" +
                "  },\n" +
                "  \"metadata\": {\n" +
                "    \"product\": {\n" +
                "      \"feature\": {\n" +
                "        \"name\": \"Management\"\n" +
                "      },\n" +
                "      \"name\": \"cloudtrail\",\n" +
                "      \"vendor_name\": \"AWS\",\n" +
                "      \"version\": \"1.08\"\n" +
                "    },\n" +
                "    \"profiles\": [\n" +
                "      \"cloud\"\n" +
                "    ],\n" +
                "    \"uid\": \"\",\n" +
                "    \"version\": \"1.0.0-rc.2\"\n" +
                "  },\n" +
                "  \"mfa\": null,\n" +
                "  \"resources\": null,\n" +
                "  \"severity\": \"Informational\",\n" +
                "  \"severity_id\": 1,\n" +
                "  \"src_endpoint\": {\n" +
                "    \"domain\": null,\n" +
                "    \"ip\": \"\",\n" +
                "    \"uid\": null\n" +
                "  },\n" +
                "  \"status\": \"Success\",\n" +
                "  \"status_id\": 1,\n" +
                "  \"time\": " + System.currentTimeMillis() + ",\n" +
                "  \"type_name\": \"Account Change: Detach Policy\",\n" +
                "  \"type_uid\": 300108,\n" +
                "  \"unmapped\": {\n" +
                "    \"eventType\": \"AwsApiCall\",\n" +
                "    \"managementEvent\": \"true\",\n" +
                "    \"readOnly\": \"false\",\n" +
                "    \"recipientAccountId\": \"\",\n" +
                "    \"requestParameters.instanceProfileName\": \"\",\n" +
                "    \"tlsDetails.cipherSuite\": \"\",\n" +
                "    \"tlsDetails.clientProvidedHostHeader\": \"iam.amazonaws.com\",\n" +
                "    \"tlsDetails.tlsVersion\": \"TLSv1.2\",\n" +
                "    \"userIdentity.sessionContext.sessionIssuer.accountId\": \"\",\n" +
                "    \"userIdentity.sessionContext.sessionIssuer.principalId\": \"\",\n" +
                "    \"userIdentity.sessionContext.sessionIssuer.type\": \"Role\",\n" +
                "    \"userIdentity.sessionContext.sessionIssuer.userName\": \"\"\n" +
                "  },\n" +
                "  \"user\": {\n" +
                "    \"name\": \"\",\n" +
                "    \"uid\": null,\n" +
                "    \"uuid\": null\n" +
                "  }\n" +
                "}";
    }

    public static String randomCloudtrailDoc(String user, String event) {
        return "{\n" +
                "    \"eventVersion\": \"1.08\",\n" +
                "    \"userIdentity\": {\n" +
                "        \"type\": \"IAMUser\",\n" +
                "        \"principalId\": \"AIDA6ON6E4XEGITEXAMPLE\",\n" +
                "        \"arn\": \"arn:aws:iam::888888888888:user/Mary\",\n" +
                "        \"accountId\": \"888888888888\",\n" +
                "        \"accessKeyId\": \"AKIAIOSFODNN7EXAMPLE\",\n" +
                "        \"userName\": \"Mary\",\n" +
                "        \"sessionContext\": {\n" +
                "            \"sessionIssuer\": {},\n" +
                "            \"webIdFederationData\": {},\n" +
                "            \"attributes\": {\n" +
                "                \"creationDate\": \"2023-07-19T21:11:57Z\",\n" +
                "                \"mfaAuthenticated\": \"false\"\n" +
                "            }\n" +
                "        }\n" +
                "    },\n" +
                "    \"eventTime\": \"2023-07-19T21:25:09Z\",\n" +
                "    \"eventSource\": \"iam.amazonaws.com\",\n" +
                "    \"EventName\": \"" + event + "\",\n" +
                "    \"awsRegion\": \"us-east-1\",\n" +
                "    \"sourceIPAddress\": \"192.0.2.0\",\n" +
                "    \"AccountName\": \"" + user + "\",\n" +
                "    \"userAgent\": \"aws-cli/2.13.5 Python/3.11.4 Linux/4.14.255-314-253.539.amzn2.x86_64 exec-env/CloudShell exe/x86_64.amzn.2 prompt/off command/iam.create-user\",\n" +
                "    \"requestParameters\": {\n" +
                "        \"userName\": \"" + user + "\"\n" +
                "    },\n" +
                "    \"responseElements\": {\n" +
                "        \"user\": {\n" +
                "            \"path\": \"/\",\n" +
                "            \"arn\": \"arn:aws:iam::888888888888:user/Richard\",\n" +
                "            \"userId\": \"AIDA6ON6E4XEP7EXAMPLE\",\n" +
                "            \"createDate\": \"Jul 19, 2023 9:25:09 PM\",\n" +
                "            \"userName\": \"Richard\"\n" +
                "        }\n" +
                "    },\n" +
                "    \"requestID\": \"2d528c76-329e-410b-9516-EXAMPLE565dc\",\n" +
                "    \"eventID\": \"ba0801a1-87ec-4d26-be87-EXAMPLE75bbb\",\n" +
                "    \"readOnly\": false,\n" +
                "    \"eventType\": \"AwsApiCall\",\n" +
                "    \"managementEvent\": true,\n" +
                "    \"recipientAccountId\": \"888888888888\",\n" +
                "    \"eventCategory\": \"Management\",\n" +
                "    \"tlsDetails\": {\n" +
                "        \"tlsVersion\": \"TLSv1.2\",\n" +
                "        \"cipherSuite\": \"ECDHE-RSA-AES128-GCM-SHA256\",\n" +
                "        \"clientProvidedHostHeader\": \"iam.amazonaws.com\"\n" +
                "    },\n" +
                "    \"sessionCredentialFromConsole\": \"true\"\n" +
                "}";
    }

    public static String randomAppLogDoc() {
        return "{\n" +
                "  \"endpoint\": \"/customer_records.txt\",\n" +
                "  \"http_method\": \"POST\",\n" +
                "  \"keywords\": \"INVALID\"\n" +
                "}";
    }

    public static String randomS3AccessLogDoc() {
        return "{\n" +
                "  \"aws.cloudtrail.eventSource\": \"s3.amazonaws.com\",\n" +
                "  \"aws.cloudtrail.eventName\": \"ReplicateObject\",\n" +
                "  \"aws.cloudtrail.eventTime\": 1\n" +
                "}";
    }

    public static String randomProductDocument() {
        return "{\n" +
                "  \"name\": \"laptop\",\n" +
                "  \"fieldA\": 123,\n" +
                "  \"mappedB\": 111,\n" +
                "  \"fieldC\": \"valueC\"\n" +
                "}\n";
    }

    public static String randomProductDocumentWithTime(long time) {
        return "{\n" +
                "  \"fieldA\": 123,\n" +
                "  \"mappedB\": 111,\n" +
                "  \"time\": " + (time) + ",\n" +
                "  \"fieldC\": \"valueC\"\n" +
                "}\n";
    }

    public static String windowsSysmonModificationDoc() {
           return "{\n" +
           "  \"@timestamp\": \"2025-01-31T00:00:00.000000+00:00\",\n" +
           "  \"process\": {\n" +
           "    \"name\": \"MpCmdRun.exe\",\n" +
           "    \"executable\": \"C:\\\\Users\\\\Public\\\\Downloads\\\\MpCmdRun.exe\"\n" +
           "  },\n" +
           "  \"event\": {\n" +
           "    \"code\": 1,\n" +
           "    \"module\": \"sysmon\"\n" +
           "  },\n" +
           "  \"host\": {\n" +
           "    \"name\": \"EC2AMAZ-EPO7HKA\"\n" +
           "  },\n" +
           "  \"source\": {\n" +
           "    \"ip\": \"192.168.1.100\"\n" +
           "  },\n" +
           "  \"user\": {\n" +
           "    \"id\": \"S-1-5-21-3623811015-3361044348-30300820-1013\",\n" +
           "    \"name\": \"JohnDoe\"\n" +
           "  },\n" +
           "  \"message\": \"Process MpCmdRun.exe executed from an unusual location.\"\n" +
           "}";
    }
}
