package org.opensearch.securityanalytics.helpers;

public class IndexMappingsHelper {

    public static String netFlowMappings() {
        return "    \"properties\": {" +
                "        \"netflow.event_data.SourceAddress\": {" +
                "          \"type\": \"ip\"" +
                "        }," +
                "        \"netflow.event_data.DestinationPort\": {" +
                "          \"type\": \"integer\"" +
                "        }," +
                "        \"netflow.event_data.DestAddress\": {" +
                "          \"type\": \"ip\"" +
                "        }," +
                "        \"netflow.event_data.SourcePort\": {" +
                "          \"type\": \"integer\"" +
                "        }," +
                "        \"netflow.event.stop\": {" +
                "          \"type\": \"integer\"" +
                "        }," +
                "        \"dns.event.stop\": {" +
                "          \"type\": \"integer\"" +
                "        }," +
                "        \"ipx.event.stop\": {" +
                "          \"type\": \"integer\"" +
                "        }," +
                "        \"plain1\": {" +
                "          \"type\": \"integer\"" +
                "        }," +
                "        \"user\":{" +
                "          \"type\":\"nested\"," +
                "            \"properties\":{" +
                "              \"first\":{" +
                "                \"type\":\"text\"," +
                "                  \"fields\":{" +
                "                    \"keyword\":{" +
                "                      \"type\":\"keyword\"," +
                "                      \"ignore_above\":256" +
                "}" +
                "}" +
                "}," +
                "              \"last\":{" +
                "\"type\":\"text\"," +
                "\"fields\":{" +
                "                      \"keyword\":{" +
                "                           \"type\":\"keyword\"," +
                "                           \"ignore_above\":256" +
                "}" +
                "}" +
                "}" +
                "}" +
                "}" +
                "    }";
    }

    public static String productIndexMapping() {
        return "\"properties\":{\n" +
                "   \"name\":{\n" +
                "      \"type\":\"keyword\"\n" +
                "   },\n" +
                "   \"fieldA\":{\n" +
                "      \"type\":\"long\"\n" +
                "   },\n" +
                "   \"mappedB\":{\n" +
                "      \"type\":\"long\"\n" +
                "   },\n" +
                "   \"time\":{\n" +
                "      \"type\":\"date\"\n" +
                "   },\n" +
                "   \"fieldC\":{\n" +
                "      \"type\":\"keyword\"\n" +
                "   }\n" +
                "}\n" +
                "}";
    }

    public static String cloudtrailOcsfMappings() {
        return "\"properties\": {\n" +
                "      \"time\": {\n" +
                "        \"type\": \"date\"\n" +
                "      },\n" +
                "      \"cloud.region\": {\n" +
                "        \"type\": \"keyword\"\n" +
                "      },\n" +
                "      \"api\": {\n" +
                "        \"properties\": {\n" +
                "           \"operation\": {\"type\": \"keyword\"},\n" +
                "            \"service\": {\n" +
                "               \"properties\": {\n" +
                "                   \"name\": {\"type\": \"text\"}\n" +
                "               }\n" +
                "            }\n" +
                "        }\n" +
                "      }\n" +
                "    }\n" +
                "        }";
    }

    public static String windowsIndexMapping() {
        return "\"properties\": {\n" +
                "      \"@timestamp\": {\"type\":\"date\"},\n" +
                "      \"AccessList\": {\n" +
                "        \"type\": \"text\"\n" +
                "      },\n" +
                "      \"AccessMask\": {\n" +
                "        \"type\": \"text\"\n" +
                "      },\n" +
                "      \"Accesses\": {\n" +
                "        \"type\": \"text\"\n" +
                "      },\n" +
                "      \"AccountName\": {\n" +
                "        \"type\": \"keyword\"\n" +
                "      },\n" +
                "      \"EventName\": {\n" +
                "        \"type\": \"keyword\"\n" +
                "      },\n" +
                "      \"AccountType\": {\n" +
                "        \"type\": \"text\",\n" +
                "        \"fields\": {\n" +
                "          \"keyword\": {\n" +
                "            \"type\": \"keyword\",\n" +
                "            \"ignore_above\": 256\n" +
                "          }\n" +
                "        }\n" +
                "      },\n" +
                "      \"Action\": {\n" +
                "        \"type\": \"integer\"\n" +
                "      },\n" +
                "      \"Address\": {\n" +
                "        \"type\": \"text\"\n" +
                "      },\n" +
                "      \"AllowedToDelegateTo\": {\n" +
                "        \"type\": \"text\"\n" +
                "      },\n" +
                "      \"Application\": {\n" +
                "        \"type\": \"text\"\n" +
                "      },\n" +
                "      \"ApplicationPath\": {\n" +
                "        \"type\": \"text\"\n" +
                "      },\n" +
                "      \"AttributeLDAPDisplayName\": {\n" +
                "        \"type\": \"text\"\n" +
                "      },\n" +
                "      \"AttributeValue\": {\n" +
                "        \"type\": \"text\"\n" +
                "      },\n" +
                "      \"AuditPolicyChanges\": {\n" +
                "        \"type\": \"text\"\n" +
                "      },\n" +
                "      \"AuditSourceName\": {\n" +
                "        \"type\": \"text\"\n" +
                "      },\n" +
                "      \"AuthenticationPackageName\": {\n" +
                "        \"type\": \"text\"\n" +
                "      },\n" +
                "      \"CallTrace\": {\n" +
                "        \"type\": \"text\"\n" +
                "      },\n" +
                "      \"CallerProcessName\": {\n" +
                "        \"type\": \"text\"\n" +
                "      },\n" +
                "      \"Caption\": {\n" +
                "        \"type\": \"text\"\n" +
                "      },\n" +
                "      \"Category\": {\n" +
                "        \"type\": \"text\",\n" +
                "        \"fields\": {\n" +
                "          \"keyword\": {\n" +
                "            \"type\": \"keyword\",\n" +
                "            \"ignore_above\": 256\n" +
                "          }\n" +
                "        }\n" +
                "      },\n" +
                "      \"CertThumbprint\": {\n" +
                "        \"type\": \"text\"\n" +
                "      },\n" +
                "      \"Channel\": {\n" +
                "        \"type\": \"text\"\n" +
                "      },\n" +
                "      \"ClassName\": {\n" +
                "        \"type\": \"text\"\n" +
                "      },\n" +
                "      \"CommandLine\": {\n" +
                "        \"type\": \"text\"\n" +
                "      },\n" +
                "      \"Company\": {\n" +
                "        \"type\": \"text\"\n" +
                "      },\n" +
                "      \"ComputerName\": {\n" +
                "        \"type\": \"text\"\n" +
                "      },\n" +
                "      \"ContextInfo\": {\n" +
                "        \"type\": \"text\"\n" +
                "      },\n" +
                "      \"CurrentDirectory\": {\n" +
                "        \"type\": \"text\"\n" +
                "      },\n" +
                "      \"Description\": {\n" +
                "        \"type\": \"text\"\n" +
                "      },\n" +
                "      \"DestAddress\": {\n" +
                "        \"type\": \"text\"\n" +
                "      },\n" +
                "      \"DestPort\": {\n" +
                "        \"type\": \"integer\"\n" +
                "      },\n" +
                "      \"Destination\": {\n" +
                "        \"type\": \"text\"\n" +
                "      },\n" +
                "      \"DestinationHostname\": {\n" +
                "        \"type\": \"text\"\n" +
                "      },\n" +
                "      \"DestinationIp\": {\n" +
                "        \"type\": \"text\"\n" +
                "      },\n" +
                "      \"DestinationIsIpv6\": {\n" +
                "        \"type\": \"text\"\n" +
                "      },\n" +
                "      \"DestinationPort\": {\n" +
                "        \"type\": \"integer\"\n" +
                "      },\n" +
                "      \"Details\": {\n" +
                "        \"type\": \"text\"\n" +
                "      },\n" +
                "      \"Device\": {\n" +
                "        \"type\": \"text\"\n" +
                "      },\n" +
                "      \"DeviceDescription\": {\n" +
                "        \"type\": \"text\"\n" +
                "      },\n" +
                "      \"DeviceName\": {\n" +
                "        \"type\": \"text\"\n" +
                "      },\n" +
                "      \"Domain\": {\n" +
                "        \"type\": \"text\",\n" +
                "        \"fields\": {\n" +
                "          \"keyword\": {\n" +
                "            \"type\": \"keyword\",\n" +
                "            \"ignore_above\": 256\n" +
                "          }\n" +
                "        }\n" +
                "      },\n" +
                "      \"EngineVersion\": {\n" +
                "        \"type\": \"text\"\n" +
                "      },\n" +
                "      \"ErrorCode\": {\n" +
                "        \"type\": \"text\"\n" +
                "      },\n" +
                "      \"EventReceivedTime\": {\n" +
                "        \"type\": \"date\"\n" +
                "      },\n" +
                "      \"EventTime\": {\n" +
                "        \"type\": \"date\"\n" +
                "      },\n" +
                "      \"EventType\": {\n" +
                "        \"type\": \"keyword\"\n" +
                "      },\n" +
                "      \"ExecutionProcessID\": {\n" +
                "        \"type\": \"long\"\n" +
                "      },\n" +
                "      \"ExecutionThreadID\": {\n" +
                "        \"type\": \"long\"\n" +
                "      },\n" +
                "      \"FailureCode\": {\n" +
                "        \"type\": \"text\"\n" +
                "      },\n" +
                "      \"FileName\": {\n" +
                "        \"type\": \"text\"\n" +
                "      },\n" +
                "      \"FileVersion\": {\n" +
                "        \"type\": \"text\"\n" +
                "      },\n" +
                "      \"GrantedAccess\": {\n" +
                "        \"type\": \"text\"\n" +
                "      },\n" +
                "      \"Hashes\": {\n" +
                "        \"type\": \"text\"\n" +
                "      },\n" +
                "      \"HostApplication\": {\n" +
                "        \"type\": \"text\"\n" +
                "      },\n" +
                "      \"HostName\": {\n" +
                "        \"type\": \"text\"\n" +
                "      },\n" +
                "      \"HostVersion\": {\n" +
                "        \"type\": \"text\"\n" +
                "      },\n" +
                "      \"Image\": {\n" +
                "        \"type\": \"text\"\n" +
                "      },\n" +
                "      \"ImageFileName\": {\n" +
                "        \"type\": \"text\"\n" +
                "      },\n" +
                "      \"ImageLoaded\": {\n" +
                "        \"type\": \"text\"\n" +
                "      },\n" +
                "      \"ImagePath\": {\n" +
                "        \"type\": \"text\"\n" +
                "      },\n" +
                "      \"Imphash\": {\n" +
                "        \"type\": \"text\"\n" +
                "      },\n" +
                "      \"Initiated\": {\n" +
                "        \"type\": \"text\"\n" +
                "      },\n" +
                "      \"IntegrityLevel\": {\n" +
                "        \"type\": \"text\"\n" +
                "      },\n" +
                "      \"IpAddress\": {\n" +
                "        \"type\": \"text\"\n" +
                "      },\n" +
                "      \"KeyLength\": {\n" +
                "        \"type\": \"text\"\n" +
                "      },\n" +
                "      \"Keywords\": {\n" +
                "        \"type\": \"text\"\n" +
                "      },\n" +
                "      \"LayerRTID\": {\n" +
                "        \"type\": \"integer\"\n" +
                "      },\n" +
                "      \"Level\": {\n" +
                "        \"type\": \"text\"\n" +
                "      },\n" +
                "      \"LocalName\": {\n" +
                "        \"type\": \"text\"\n" +
                "      },\n" +
                "      \"LogonId\": {\n" +
                "        \"type\": \"text\"\n" +
                "      },\n" +
                "      \"LogonProcessName\": {\n" +
                "        \"type\": \"text\"\n" +
                "      },\n" +
                "      \"LogonType\": {\n" +
                "        \"type\": \"integer\"\n" +
                "      },\n" +
                "      \"Message\": {\n" +
                "        \"type\": \"text\"\n" +
                "      },\n" +
                "      \"ModifyingApplication\": {\n" +
                "        \"type\": \"text\"\n" +
                "      },\n" +
                "      \"NewName\": {\n" +
                "        \"type\": \"text\"\n" +
                "      },\n" +
                "      \"NewTargetUserName\": {\n" +
                "        \"type\": \"text\"\n" +
                "      },\n" +
                "      \"NewTemplateContent\": {\n" +
                "        \"type\": \"text\"\n" +
                "      },\n" +
                "      \"NewUacValue\": {\n" +
                "        \"type\": \"text\"\n" +
                "      },\n" +
                "      \"NewValue\": {\n" +
                "        \"type\": \"text\"\n" +
                "      },\n" +
                "      \"ObjectClass\": {\n" +
                "        \"type\": \"text\"\n" +
                "      },\n" +
                "      \"ObjectName\": {\n" +
                "        \"type\": \"text\"\n" +
                "      },\n" +
                "      \"ObjectServer\": {\n" +
                "        \"type\": \"text\"\n" +
                "      },\n" +
                "      \"ObjectType\": {\n" +
                "        \"type\": \"text\"\n" +
                "      },\n" +
                "      \"ObjectValueName\": {\n" +
                "        \"type\": \"text\"\n" +
                "      },\n" +
                "      \"OldTargetUserName\": {\n" +
                "        \"type\": \"text\"\n" +
                "      },\n" +
                "      \"OldUacValue\": {\n" +
                "        \"type\": \"text\"\n" +
                "      },\n" +
                "      \"Opcode\": {\n" +
                "        \"type\": \"text\",\n" +
                "        \"fields\": {\n" +
                "          \"keyword\": {\n" +
                "            \"type\": \"keyword\",\n" +
                "            \"ignore_above\": 256\n" +
                "          }\n" +
                "        }\n" +
                "      },\n" +
                "      \"OpcodeValue\": {\n" +
                "        \"type\": \"long\"\n" +
                "      },\n" +
                "      \"Origin\": {\n" +
                "        \"type\": \"text\"\n" +
                "      },\n" +
                "      \"OriginalFileName\": {\n" +
                "        \"type\": \"text\"\n" +
                "      },\n" +
                "      \"OriginalFilename\": {\n" +
                "        \"type\": \"text\"\n" +
                "      },\n" +
                "      \"OriginalName\": {\n" +
                "        \"type\": \"text\"\n" +
                "      },\n" +
                "      \"ParentCommandLine\": {\n" +
                "        \"type\": \"text\"\n" +
                "      },\n" +
                "      \"ParentImage\": {\n" +
                "        \"type\": \"text\"\n" +
                "      },\n" +
                "      \"ParentUser\": {\n" +
                "        \"type\": \"text\"\n" +
                "      },\n" +
                "      \"PasswordLastSet\": {\n" +
                "        \"type\": \"text\"\n" +
                "      },\n" +
                "      \"Path\": {\n" +
                "        \"type\": \"text\"\n" +
                "      },\n" +
                "      \"Payload\": {\n" +
                "        \"type\": \"text\"\n" +
                "      },\n" +
                "      \"PipeName\": {\n" +
                "        \"type\": \"text\"\n" +
                "      },\n" +
                "      \"PossibleCause\": {\n" +
                "        \"type\": \"text\"\n" +
                "      },\n" +
                "      \"PrivilegeList\": {\n" +
                "        \"type\": \"text\"\n" +
                "      },\n" +
                "      \"ProcessGuid\": {\n" +
                "        \"type\": \"text\",\n" +
                "        \"fields\": {\n" +
                "          \"keyword\": {\n" +
                "            \"type\": \"keyword\",\n" +
                "            \"ignore_above\": 256\n" +
                "          }\n" +
                "        }\n" +
                "      },\n" +
                "      \"ProcessId\": {\n" +
                "        \"type\": \"integer\"\n" +
                "      },\n" +
                "      \"ProcessName\": {\n" +
                "        \"type\": \"text\"\n" +
                "      },\n" +
                "      \"Product\": {\n" +
                "        \"type\": \"text\"\n" +
                "      },\n" +
                "      \"Properties\": {\n" +
                "        \"type\": \"text\"\n" +
                "      },\n" +
                "      \"Provider\": {\n" +
                "        \"type\": \"text\"\n" +
                "      },\n" +
                "      \"ProviderGuid\": {\n" +
                "        \"type\": \"text\",\n" +
                "        \"fields\": {\n" +
                "          \"keyword\": {\n" +
                "            \"type\": \"keyword\",\n" +
                "            \"ignore_above\": 256\n" +
                "          }\n" +
                "        }\n" +
                "      },\n" +
                "      \"ProviderName\": {\n" +
                "        \"type\": \"text\"\n" +
                "      },\n" +
                "      \"Provider_Name\": {\n" +
                "        \"type\": \"text\"\n" +
                "      },\n" +
                "      \"QNAME\": {\n" +
                "        \"type\": \"text\"\n" +
                "      },\n" +
                "      \"Query\": {\n" +
                "        \"type\": \"text\"\n" +
                "      },\n" +
                "      \"QueryName\": {\n" +
                "        \"type\": \"text\"\n" +
                "      },\n" +
                "      \"QueryResults\": {\n" +
                "        \"type\": \"text\"\n" +
                "      },\n" +
                "      \"QueryStatus\": {\n" +
                "        \"type\": \"text\"\n" +
                "      },\n" +
                "      \"RecordNumber\": {\n" +
                "        \"type\": \"long\"\n" +
                "      },\n" +
                "      \"RelativeTargetName\": {\n" +
                "        \"type\": \"text\"\n" +
                "      },\n" +
                "      \"RemoteAddress\": {\n" +
                "        \"type\": \"text\"\n" +
                "      },\n" +
                "      \"RemoteName\": {\n" +
                "        \"type\": \"text\"\n" +
                "      },\n" +
                "      \"SamAccountName\": {\n" +
                "        \"type\": \"text\"\n" +
                "      },\n" +
                "      \"ScriptBlockText\": {\n" +
                "        \"type\": \"text\"\n" +
                "      },\n" +
                "      \"SearchFilter\": {\n" +
                "        \"type\": \"text\"\n" +
                "      },\n" +
                "      \"ServerName\": {\n" +
                "        \"type\": \"text\"\n" +
                "      },\n" +
                "      \"Service\": {\n" +
                "        \"type\": \"text\"\n" +
                "      },\n" +
                "      \"ServiceFileName\": {\n" +
                "        \"type\": \"text\"\n" +
                "      },\n" +
                "      \"ServiceName\": {\n" +
                "        \"type\": \"text\"\n" +
                "      },\n" +
                "      \"ServicePrincipalNames\": {\n" +
                "        \"type\": \"text\"\n" +
                "      },\n" +
                "      \"ServiceStartType\": {\n" +
                "        \"type\": \"text\"\n" +
                "      },\n" +
                "      \"ServiceType\": {\n" +
                "        \"type\": \"text\"\n" +
                "      },\n" +
                "      \"Severity\": {\n" +
                "        \"type\": \"text\",\n" +
                "        \"fields\": {\n" +
                "          \"keyword\": {\n" +
                "            \"type\": \"keyword\",\n" +
                "            \"ignore_above\": 256\n" +
                "          }\n" +
                "        }\n" +
                "      },\n" +
                "      \"SeverityValue\": {\n" +
                "        \"type\": \"long\"\n" +
                "      },\n" +
                "      \"ShareName\": {\n" +
                "        \"type\": \"text\"\n" +
                "      },\n" +
                "      \"SidHistory\": {\n" +
                "        \"type\": \"text\"\n" +
                "      },\n" +
                "      \"Signed\": {\n" +
                "        \"type\": \"text\"\n" +
                "      },\n" +
                "      \"SourceAddress\": {\n" +
                "        \"type\": \"text\"\n" +
                "      },\n" +
                "      \"SourceImage\": {\n" +
                "        \"type\": \"text\"\n" +
                "      },\n" +
                "      \"SourceIp\": {\n" +
                "        \"type\": \"text\"\n" +
                "      },\n" +
                "      \"SourceModuleName\": {\n" +
                "        \"type\": \"text\",\n" +
                "        \"fields\": {\n" +
                "          \"keyword\": {\n" +
                "            \"type\": \"keyword\",\n" +
                "            \"ignore_above\": 256\n" +
                "          }\n" +
                "        }\n" +
                "      },\n" +
                "      \"SourceModuleType\": {\n" +
                "        \"type\": \"text\",\n" +
                "        \"fields\": {\n" +
                "          \"keyword\": {\n" +
                "            \"type\": \"keyword\",\n" +
                "            \"ignore_above\": 256\n" +
                "          }\n" +
                "        }\n" +
                "      },\n" +
                "      \"SourceName\": {\n" +
                "        \"type\": \"text\",\n" +
                "        \"fields\": {\n" +
                "          \"keyword\": {\n" +
                "            \"type\": \"keyword\",\n" +
                "            \"ignore_above\": 256\n" +
                "          }\n" +
                "        }\n" +
                "      },\n" +
                "      \"SourcePort\": {\n" +
                "        \"type\": \"integer\"\n" +
                "      },\n" +
                "      \"Source_Name\": {\n" +
                "        \"type\": \"text\"\n" +
                "      },\n" +
                "      \"StartAddress\": {\n" +
                "        \"type\": \"text\"\n" +
                "      },\n" +
                "      \"StartFunction\": {\n" +
                "        \"type\": \"text\"\n" +
                "      },\n" +
                "      \"StartModule\": {\n" +
                "        \"type\": \"text\"\n" +
                "      },\n" +
                "      \"State\": {\n" +
                "        \"type\": \"text\"\n" +
                "      },\n" +
                "      \"Status\": {\n" +
                "        \"type\": \"text\"\n" +
                "      },\n" +
                "      \"SubjectDomainName\": {\n" +
                "        \"type\": \"text\"\n" +
                "      },\n" +
                "      \"SubjectLogonId\": {\n" +
                "        \"type\": \"text\"\n" +
                "      },\n" +
                "      \"SubjectUserName\": {\n" +
                "        \"type\": \"text\"\n" +
                "      },\n" +
                "      \"SubjectUserSid\": {\n" +
                "        \"type\": \"text\"\n" +
                "      },\n" +
                "      \"TargetFilename\": {\n" +
                "        \"type\": \"text\"\n" +
                "      },\n" +
                "      \"TargetImage\": {\n" +
                "        \"type\": \"text\"\n" +
                "      },\n" +
                "      \"TargetLogonId\": {\n" +
                "        \"type\": \"text\"\n" +
                "      },\n" +
                "      \"TargetName\": {\n" +
                "        \"type\": \"text\"\n" +
                "      },\n" +
                "      \"TargetObject\": {\n" +
                "        \"type\": \"text\"\n" +
                "      },\n" +
                "      \"TargetParentProcessId\": {\n" +
                "        \"type\": \"integer\"\n" +
                "      },\n" +
                "      \"TargetPort\": {\n" +
                "        \"type\": \"integer\"\n" +
                "      },\n" +
                "      \"TargetServerName\": {\n" +
                "        \"type\": \"text\"\n" +
                "      },\n" +
                "      \"TargetSid\": {\n" +
                "        \"type\": \"text\"\n" +
                "      },\n" +
                "      \"TargetUserName\": {\n" +
                "        \"type\": \"text\"\n" +
                "      },\n" +
                "      \"TargetUserSid\": {\n" +
                "        \"type\": \"text\"\n" +
                "      },\n" +
                "      \"TaskName\": {\n" +
                "        \"type\": \"text\"\n" +
                "      },\n" +
                "      \"TaskValue\": {\n" +
                "        \"type\": \"long\"\n" +
                "      },\n" +
                "      \"TemplateContent\": {\n" +
                "        \"type\": \"text\"\n" +
                "      },\n" +
                "      \"TicketEncryptionType\": {\n" +
                "        \"type\": \"text\"\n" +
                "      },\n" +
                "      \"TicketOptions\": {\n" +
                "        \"type\": \"text\"\n" +
                "      },\n" +
                "      \"Type\": {\n" +
                "        \"type\": \"text\"\n" +
                "      },\n" +
                "      \"User\": {\n" +
                "        \"type\": \"text\"\n" +
                "      },\n" +
                "      \"UserID\": {\n" +
                "        \"type\": \"text\",\n" +
                "        \"fields\": {\n" +
                "          \"keyword\": {\n" +
                "            \"type\": \"keyword\",\n" +
                "            \"ignore_above\": 256\n" +
                "          }\n" +
                "        }\n" +
                "      },\n" +
                "      \"UserName\": {\n" +
                "        \"type\": \"text\"\n" +
                "      },\n" +
                "      \"UtcTime\": {\n" +
                "        \"type\": \"text\",\n" +
                "        \"fields\": {\n" +
                "          \"keyword\": {\n" +
                "            \"type\": \"keyword\",\n" +
                "            \"ignore_above\": 256\n" +
                "          }\n" +
                "        }\n" +
                "      },\n" +
                "      \"Value\": {\n" +
                "        \"type\": \"text\"\n" +
                "      },\n" +
                "      \"Version\": {\n" +
                "        \"type\": \"long\"\n" +
                "      },\n" +
                "      \"Workstation\": {\n" +
                "        \"type\": \"text\"\n" +
                "      },\n" +
                "      \"WorkstationName\": {\n" +
                "        \"type\": \"text\"\n" +
                "      },\n" +
                "      \"EventID\": {\n" +
                "        \"type\": \"integer\"\n" +
                "      },\n" +
                "      \"param1\": {\n" +
                "        \"type\": \"text\"\n" +
                "      },\n" +
                "      \"param2\": {\n" +
                "        \"type\": \"text\"\n" +
                "      },\n" +
                "      \"processPath\": {\n" +
                "        \"type\": \"text\"\n" +
                "      },\n" +
                "      \"sha1\": {\n" +
                "        \"type\": \"text\"\n" +
                "      },\n" +
                "      \"src_ip\": {\n" +
                "        \"type\": \"text\"\n" +
                "      },\n" +
                "      \"unmapped_HiveName\": {\n" +
                "        \"type\": \"text\"\n" +
                "      }\n" +
                "    }";
    }

    public static String windowsIndexMappingOnlyNumericAndDate() {
        return "\"properties\": {\n" +
                "      \"@timestamp\": {\"type\":\"date\"},\n" +
                "      \"EventTime\": {\n" +
                "        \"type\": \"date\"\n" +
                "      },\n" +
                "      \"ExecutionProcessID\": {\n" +
                "        \"type\": \"long\"\n" +
                "      },\n" +
                "      \"ExecutionThreadID\": {\n" +
                "        \"type\": \"integer\"\n" +
                "      },\n" +
                "      \"EventID\": {\n" +
                "        \"type\": \"integer\"\n" +
                "      },\n" +
                "      \"TaskValue\": {\n" +
                "        \"type\": \"integer\"\n" +
                "      }\n" +
                "    }";
    }

    public static String windowsIndexMappingOnlyNumericAndText() {
        return "\"properties\": {\n" +
                "      \"TaskName\": {\n" +
                "        \"type\": \"text\"\n" +
                "      },\n" +
                "      \"ExecutionProcessID\": {\n" +
                "        \"type\": \"long\"\n" +
                "      },\n" +
                "      \"ExecutionThreadID\": {\n" +
                "        \"type\": \"integer\"\n" +
                "      },\n" +
                "      \"EventID\": {\n" +
                "        \"type\": \"integer\"\n" +
                "      },\n" +
                "      \"TaskValue\": {\n" +
                "        \"type\": \"integer\"\n" +
                "      }\n" +
                "    }";
    }

    public static String windowsSysmonModificationIndexMapping() {
    return "\"properties\": {\n" +
           "  \"@timestamp\": { \"type\": \"date\" },\n" +
           "  \"process\": {\n" +
           "    \"properties\": {\n" +
           "      \"name\": { \"type\": \"keyword\" },\n" +
           "      \"executable\": { \"type\": \"keyword\" }\n" +
           "    }\n" +
           "  },\n" +
           "  \"event\": {\n" +
           "    \"properties\": {\n" +
           "      \"code\": { \"type\": \"integer\" },\n" +
           "      \"module\": { \"type\": \"keyword\" }\n" +
           "    }\n" +
           "  },\n" +
           "  \"host\": {\n" +
           "    \"properties\": {\n" +
           "      \"name\": { \"type\": \"keyword\" }\n" +
           "    }\n" +
           "  },\n" +
           "  \"source\": {\n" +
           "    \"properties\": {\n" +
           "      \"ip\": { \"type\": \"ip\" }\n" +
           "    }\n" +
           "  },\n" +
           "  \"user\": {\n" +
           "    \"properties\": {\n" +
           "      \"id\": { \"type\": \"keyword\" },\n" +
           "      \"name\": { \"type\": \"keyword\" }\n" +
           "    }\n" +
           "  },\n" +
           "  \"message\": { \"type\": \"text\" }\n" +
           "}";
    }

    public static String oldThreatIntelJobMapping() {
        return "  \"dynamic\": \"strict\",\n" +
                "  \"_meta\": {\n" +
                "    \"schema_version\": 1\n" +
                "  },\n" +
                "  \"properties\": {\n" +
                "    \"schema_version\": {\n" +
                "      \"type\": \"integer\"\n" +
                "    },\n" +
                "    \"enabled_time\": {\n" +
                "      \"type\": \"long\"\n" +
                "    },\n" +
                "    \"indices\": {\n" +
                "      \"type\": \"text\"\n" +
                "    },\n" +
                "    \"last_update_time\": {\n" +
                "      \"type\": \"long\"\n" +
                "    },\n" +
                "    \"name\": {\n" +
                "      \"type\": \"text\"\n" +
                "    },\n" +
                "    \"schedule\": {\n" +
                "      \"properties\": {\n" +
                "        \"interval\": {\n" +
                "          \"properties\": {\n" +
                "            \"period\": {\n" +
                "              \"type\": \"long\"\n" +
                "            },\n" +
                "            \"start_time\": {\n" +
                "              \"type\": \"long\"\n" +
                "            },\n" +
                "            \"unit\": {\n" +
                "              \"type\": \"text\"\n" +
                "            }\n" +
                "          }\n" +
                "        }\n" +
                "      }\n" +
                "    },\n" +
                "    \"state\": {\n" +
                "      \"type\": \"text\"\n" +
                "    },\n" +
                "    \"update_enabled\": {\n" +
                "      \"type\": \"boolean\"\n" +
                "    },\n" +
                "    \"update_stats\": {\n" +
                "      \"properties\": {\n" +
                "        \"last_failed_at_in_epoch_millis\": {\n" +
                "          \"type\": \"long\"\n" +
                "        },\n" +
                "        \"last_processing_time_in_millis\": {\n" +
                "          \"type\": \"long\"\n" +
                "        },\n" +
                "        \"last_skipped_at_in_epoch_millis\": {\n" +
                "          \"type\": \"long\"\n" +
                "        },\n" +
                "        \"last_succeeded_at_in_epoch_millis\": {\n" +
                "          \"type\": \"long\"\n" +
                "        }\n" +
                "      }\n" +
                "    }\n" +
                "  }";
    }

    public static String adLdapLogMappings() {
        return "\"properties\": {\n" +
                "      \"ResultType\": {\n" +
                "        \"type\": \"integer\"\n" +
                "      },\n" +
                "      \"ResultDescription\": {\n" +
                "        \"type\": \"text\"\n" +
                "      },\n" +
                "      \"azure.signinlogs.props.user_id\": {\n" +
                "        \"type\": \"text\"\n" +
                "      }\n" +
                "    }";
    }

    public static String cloudtrailMappings() {
        return "\"properties\": {\n" +
                "        \"Records\": {\n" +
                "          \"properties\": {\n" +
                "            \"awsRegion\": {\n" +
                "              \"type\": \"text\",\n" +
                "              \"fields\": {\n" +
                "                \"keyword\": {\n" +
                "                  \"type\": \"keyword\",\n" +
                "                  \"ignore_above\": 256\n" +
                "                }\n" +
                "              }\n" +
                "            },\n" +
                "            \"eventCategory\": {\n" +
                "              \"type\": \"text\",\n" +
                "              \"fields\": {\n" +
                "                \"keyword\": {\n" +
                "                  \"type\": \"keyword\",\n" +
                "                  \"ignore_above\": 256\n" +
                "                }\n" +
                "              }\n" +
                "            },\n" +
                "            \"eventID\": {\n" +
                "              \"type\": \"text\",\n" +
                "              \"fields\": {\n" +
                "                \"keyword\": {\n" +
                "                  \"type\": \"keyword\",\n" +
                "                  \"ignore_above\": 256\n" +
                "                }\n" +
                "              }\n" +
                "            },\n" +
                "            \"eventName\": {\n" +
                "              \"type\": \"text\",\n" +
                "              \"fields\": {\n" +
                "                \"keyword\": {\n" +
                "                  \"type\": \"keyword\",\n" +
                "                  \"ignore_above\": 256\n" +
                "                }\n" +
                "              }\n" +
                "            },\n" +
                "            \"eventSource\": {\n" +
                "              \"type\": \"text\",\n" +
                "              \"fields\": {\n" +
                "                \"keyword\": {\n" +
                "                  \"type\": \"keyword\",\n" +
                "                  \"ignore_above\": 256\n" +
                "                }\n" +
                "              }\n" +
                "            },\n" +
                "            \"eventTime\": {\n" +
                "              \"type\": \"date\"\n" +
                "            },\n" +
                "            \"eventType\": {\n" +
                "              \"type\": \"text\",\n" +
                "              \"fields\": {\n" +
                "                \"keyword\": {\n" +
                "                  \"type\": \"keyword\",\n" +
                "                  \"ignore_above\": 256\n" +
                "                }\n" +
                "              }\n" +
                "            },\n" +
                "            \"eventVersion\": {\n" +
                "              \"type\": \"text\",\n" +
                "              \"fields\": {\n" +
                "                \"keyword\": {\n" +
                "                  \"type\": \"keyword\",\n" +
                "                  \"ignore_above\": 256\n" +
                "                }\n" +
                "              }\n" +
                "            },\n" +
                "            \"managementEvent\": {\n" +
                "              \"type\": \"boolean\"\n" +
                "            },\n" +
                "            \"readOnly\": {\n" +
                "              \"type\": \"boolean\"\n" +
                "            },\n" +
                "            \"recipientAccountId\": {\n" +
                "              \"type\": \"text\",\n" +
                "              \"fields\": {\n" +
                "                \"keyword\": {\n" +
                "                  \"type\": \"keyword\",\n" +
                "                  \"ignore_above\": 256\n" +
                "                }\n" +
                "              }\n" +
                "            },\n" +
                "            \"requestID\": {\n" +
                "              \"type\": \"text\",\n" +
                "              \"fields\": {\n" +
                "                \"keyword\": {\n" +
                "                  \"type\": \"keyword\",\n" +
                "                  \"ignore_above\": 256\n" +
                "                }\n" +
                "              }\n" +
                "            },\n" +
                "            \"requestParameters\": {\n" +
                "              \"properties\": {\n" +
                "                \"userName\": {\n" +
                "                  \"type\": \"text\",\n" +
                "                  \"fields\": {\n" +
                "                    \"keyword\": {\n" +
                "                      \"type\": \"keyword\",\n" +
                "                      \"ignore_above\": 256\n" +
                "                    }\n" +
                "                  }\n" +
                "                }\n" +
                "              }\n" +
                "            },\n" +
                "            \"responseElements\": {\n" +
                "              \"properties\": {\n" +
                "                \"user\": {\n" +
                "                  \"properties\": {\n" +
                "                    \"arn\": {\n" +
                "                      \"type\": \"text\",\n" +
                "                      \"fields\": {\n" +
                "                        \"keyword\": {\n" +
                "                          \"type\": \"keyword\",\n" +
                "                          \"ignore_above\": 256\n" +
                "                        }\n" +
                "                      }\n" +
                "                    },\n" +
                "                    \"createDate\": {\n" +
                "                      \"type\": \"text\",\n" +
                "                      \"fields\": {\n" +
                "                        \"keyword\": {\n" +
                "                          \"type\": \"keyword\",\n" +
                "                          \"ignore_above\": 256\n" +
                "                        }\n" +
                "                      }\n" +
                "                    },\n" +
                "                    \"path\": {\n" +
                "                      \"type\": \"text\",\n" +
                "                      \"fields\": {\n" +
                "                        \"keyword\": {\n" +
                "                          \"type\": \"keyword\",\n" +
                "                          \"ignore_above\": 256\n" +
                "                        }\n" +
                "                      }\n" +
                "                    },\n" +
                "                    \"userId\": {\n" +
                "                      \"type\": \"text\",\n" +
                "                      \"fields\": {\n" +
                "                        \"keyword\": {\n" +
                "                          \"type\": \"keyword\",\n" +
                "                          \"ignore_above\": 256\n" +
                "                        }\n" +
                "                      }\n" +
                "                    },\n" +
                "                    \"userName\": {\n" +
                "                      \"type\": \"text\",\n" +
                "                      \"fields\": {\n" +
                "                        \"keyword\": {\n" +
                "                          \"type\": \"keyword\",\n" +
                "                          \"ignore_above\": 256\n" +
                "                        }\n" +
                "                      }\n" +
                "                    }\n" +
                "                  }\n" +
                "                }\n" +
                "              }\n" +
                "            },\n" +
                "            \"sessionCredentialFromConsole\": {\n" +
                "              \"type\": \"text\",\n" +
                "              \"fields\": {\n" +
                "                \"keyword\": {\n" +
                "                  \"type\": \"keyword\",\n" +
                "                  \"ignore_above\": 256\n" +
                "                }\n" +
                "              }\n" +
                "            },\n" +
                "            \"sourceIPAddress\": {\n" +
                "              \"type\": \"text\",\n" +
                "              \"fields\": {\n" +
                "                \"keyword\": {\n" +
                "                  \"type\": \"keyword\",\n" +
                "                  \"ignore_above\": 256\n" +
                "                }\n" +
                "              }\n" +
                "            },\n" +
                "            \"tlsDetails\": {\n" +
                "              \"properties\": {\n" +
                "                \"cipherSuite\": {\n" +
                "                  \"type\": \"text\",\n" +
                "                  \"fields\": {\n" +
                "                    \"keyword\": {\n" +
                "                      \"type\": \"keyword\",\n" +
                "                      \"ignore_above\": 256\n" +
                "                    }\n" +
                "                  }\n" +
                "                },\n" +
                "                \"clientProvidedHostHeader\": {\n" +
                "                  \"type\": \"text\",\n" +
                "                  \"fields\": {\n" +
                "                    \"keyword\": {\n" +
                "                      \"type\": \"keyword\",\n" +
                "                      \"ignore_above\": 256\n" +
                "                    }\n" +
                "                  }\n" +
                "                },\n" +
                "                \"tlsVersion\": {\n" +
                "                  \"type\": \"text\",\n" +
                "                  \"fields\": {\n" +
                "                    \"keyword\": {\n" +
                "                      \"type\": \"keyword\",\n" +
                "                      \"ignore_above\": 256\n" +
                "                    }\n" +
                "                  }\n" +
                "                }\n" +
                "              }\n" +
                "            },\n" +
                "            \"userAgent\": {\n" +
                "              \"type\": \"text\",\n" +
                "              \"fields\": {\n" +
                "                \"keyword\": {\n" +
                "                  \"type\": \"keyword\",\n" +
                "                  \"ignore_above\": 256\n" +
                "                }\n" +
                "              }\n" +
                "            },\n" +
                "            \"userIdentity\": {\n" +
                "              \"properties\": {\n" +
                "                \"accessKeyId\": {\n" +
                "                  \"type\": \"text\",\n" +
                "                  \"fields\": {\n" +
                "                    \"keyword\": {\n" +
                "                      \"type\": \"keyword\",\n" +
                "                      \"ignore_above\": 256\n" +
                "                    }\n" +
                "                  }\n" +
                "                },\n" +
                "                \"accountId\": {\n" +
                "                  \"type\": \"text\",\n" +
                "                  \"fields\": {\n" +
                "                    \"keyword\": {\n" +
                "                      \"type\": \"keyword\",\n" +
                "                      \"ignore_above\": 256\n" +
                "                    }\n" +
                "                  }\n" +
                "                },\n" +
                "                \"arn\": {\n" +
                "                  \"type\": \"text\",\n" +
                "                  \"fields\": {\n" +
                "                    \"keyword\": {\n" +
                "                      \"type\": \"keyword\",\n" +
                "                      \"ignore_above\": 256\n" +
                "                    }\n" +
                "                  }\n" +
                "                },\n" +
                "                \"principalId\": {\n" +
                "                  \"type\": \"text\",\n" +
                "                  \"fields\": {\n" +
                "                    \"keyword\": {\n" +
                "                      \"type\": \"keyword\",\n" +
                "                      \"ignore_above\": 256\n" +
                "                    }\n" +
                "                  }\n" +
                "                },\n" +
                "                \"sessionContext\": {\n" +
                "                  \"properties\": {\n" +
                "                    \"attributes\": {\n" +
                "                      \"properties\": {\n" +
                "                        \"creationDate\": {\n" +
                "                          \"type\": \"date\"\n" +
                "                        },\n" +
                "                        \"mfaAuthenticated\": {\n" +
                "                          \"type\": \"text\",\n" +
                "                          \"fields\": {\n" +
                "                            \"keyword\": {\n" +
                "                              \"type\": \"keyword\",\n" +
                "                              \"ignore_above\": 256\n" +
                "                            }\n" +
                "                          }\n" +
                "                        }\n" +
                "                      }\n" +
                "                    },\n" +
                "                    \"sessionIssuer\": {\n" +
                "                      \"type\": \"object\"\n" +
                "                    },\n" +
                "                    \"webIdFederationData\": {\n" +
                "                      \"type\": \"object\"\n" +
                "                    }\n" +
                "                  }\n" +
                "                },\n" +
                "                \"type\": {\n" +
                "                  \"type\": \"text\",\n" +
                "                  \"fields\": {\n" +
                "                    \"keyword\": {\n" +
                "                      \"type\": \"keyword\",\n" +
                "                      \"ignore_above\": 256\n" +
                "                    }\n" +
                "                  }\n" +
                "                },\n" +
                "                \"userName\": {\n" +
                "                  \"type\": \"text\",\n" +
                "                  \"fields\": {\n" +
                "                    \"keyword\": {\n" +
                "                      \"type\": \"keyword\",\n" +
                "                      \"ignore_above\": 256\n" +
                "                    }\n" +
                "                  }\n" +
                "                }\n" +
                "              }\n" +
                "            }\n" +
                "          }\n" +
                "        }}";
    }

    public static String s3AccessLogMappings() {
        return "    \"properties\": {" +
                "        \"aws.cloudtrail.eventSource\": {" +
                "          \"type\": \"text\"" +
                "        }," +
                "        \"aws.cloudtrail.eventName\": {" +
                "          \"type\": \"text\"" +
                "        }," +
                "        \"aws.cloudtrail.eventTime\": {" +
                "          \"type\": \"integer\"" +
                "        }" +
                "    }";
    }

    public static String appLogMappings() {
        return "    \"properties\": {" +
                "        \"http_method\": {" +
                "          \"type\": \"text\"" +
                "        }," +
                "        \"endpoint\": {" +
                "          \"type\": \"text\"" +
                "        }," +
                "        \"keywords\": {" +
                "          \"type\": \"text\"" +
                "        }" +
                "    }";
    }

    public static String vpcFlowMappings() {
        return "    \"properties\": {" +
                "        \"version\": {" +
                "          \"type\": \"integer\"" +
                "        }," +
                "        \"account-id\": {" +
                "          \"type\": \"text\"" +
                "        }," +
                "        \"interface-id\": {" +
                "          \"type\": \"text\"" +
                "        }," +
                "        \"srcaddr\": {" +
                "          \"type\": \"text\"" +
                "        }," +
                "        \"dstaddr\": {" +
                "          \"type\": \"text\"" +
                "        }," +
                "        \"srcport\": {" +
                "          \"type\": \"integer\"" +
                "        }," +
                "        \"dstport\": {" +
                "          \"type\": \"integer\"" +
                "        }," +
                "        \"severity_id\": {" +
                "          \"type\": \"text\"" +
                "        }," +
                "        \"class_name\": {" +
                "          \"type\": \"text\"" +
                "        }" +
                "    }";
    }
}
