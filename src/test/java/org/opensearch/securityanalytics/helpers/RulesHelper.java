package org.opensearch.securityanalytics.helpers;

import java.util.Locale;

public class RulesHelper {

    public static String randomRule() {
        return "title: Remote Encrypting File System Abuse\n" +
                "id: 5f92fff9-82e2-48eb-8fc1-8b133556a551\n" +
                "description: Detects remote RPC calls to possibly abuse remote encryption service via MS-EFSR\n" +
                "references:\n" +
                "    - https://attack.mitre.org/tactics/TA0008/\n" +
                "    - https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-36942\n" +
                "    - https://github.com/jsecurity101/MSRPC-to-ATTACK/blob/main/documents/MS-EFSR.md\n" +
                "    - https://github.com/zeronetworks/rpcfirewall\n" +
                "    - https://zeronetworks.com/blog/stopping_lateral_movement_via_the_rpc_firewall/\n" +
                "tags:\n" +
                "    - attack.defense_evasion\n" +
                "status: experimental\n" +
                "author: Sagie Dulce, Dekel Paz\n" +
                "date: 2022/01/01\n" +
                "modified: 2022/01/01\n" +
                "logsource:\n" +
                "    product: rpc_firewall\n" +
                "    category: application\n" +
                "    definition: 'Requirements: install and apply the RPC Firewall to all processes with \"audit:true action:block uuid:df1941c5-fe89-4e79-bf10-463657acf44d or c681d488-d850-11d0-8c52-00c04fd90f7e'\n" +
                "detection:\n" +
                "    selection:\n" +
                "        EventID: 22\n" +
                "    condition: selection\n" +
                "falsepositives:\n" +
                "    - Legitimate usage of remote file encryption\n" +
                "level: high";
    }

    public static String randomRuleWithRawField() {
        return "title: Remote Encrypting File System Abuse\n" +
                "id: 5f92fff9-82e2-48eb-8fc1-8b133556a551\n" +
                "description: Detects remote RPC calls to possibly abuse remote encryption service via MS-EFSR\n" +
                "references:\n" +
                "    - https://attack.mitre.org/tactics/TA0008/\n" +
                "    - https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-36942\n" +
                "    - https://github.com/jsecurity101/MSRPC-to-ATTACK/blob/main/documents/MS-EFSR.md\n" +
                "    - https://github.com/zeronetworks/rpcfirewall\n" +
                "    - https://zeronetworks.com/blog/stopping_lateral_movement_via_the_rpc_firewall/\n" +
                "tags:\n" +
                "    - attack.defense_evasion\n" +
                "status: experimental\n" +
                "author: Sagie Dulce, Dekel Paz\n" +
                "date: 2022/01/01\n" +
                "modified: 2022/01/01\n" +
                "logsource:\n" +
                "    product: rpc_firewall\n" +
                "    category: application\n" +
                "    definition: 'Requirements: install and apply the RPC Firewall to all processes with \"audit:true action:block uuid:df1941c5-fe89-4e79-bf10-463657acf44d or c681d488-d850-11d0-8c52-00c04fd90f7e'\n" +
                "detection:\n" +
                "    selection:\n" +
                "        eventName: testinghere\n" +
                "    condition: selection\n" +
                "falsepositives:\n" +
                "    - Legitimate usage of remote file encryption\n" +
                "level: high";
    }

    public static String randomRuleWithNotCondition() {
        return "title: Remote Encrypting File System Abuse\n" +
                "id: 5f92fff9-82e2-48eb-8fc1-8b133556a551\n" +
                "description: Detects remote RPC calls to possibly abuse remote encryption service via MS-EFSR\n" +
                "references:\n" +
                "    - https://attack.mitre.org/tactics/TA0008/\n" +
                "    - https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-36942\n" +
                "    - https://github.com/jsecurity101/MSRPC-to-ATTACK/blob/main/documents/MS-EFSR.md\n" +
                "    - https://github.com/zeronetworks/rpcfirewall\n" +
                "    - https://zeronetworks.com/blog/stopping_lateral_movement_via_the_rpc_firewall/\n" +
                "tags:\n" +
                "    - attack.defense_evasion\n" +
                "status: experimental\n" +
                "author: Sagie Dulce, Dekel Paz\n" +
                "date: 2022/01/01\n" +
                "modified: 2022/01/01\n" +
                "logsource:\n" +
                "    product: rpc_firewall\n" +
                "    category: application\n" +
                "    definition: 'Requirements: install and apply the RPC Firewall to all processes with \"audit:true action:block uuid:df1941c5-fe89-4e79-bf10-463657acf44d or c681d488-d850-11d0-8c52-00c04fd90f7e'\n" +
                "detection:\n" +
                "    selection1:\n" +
                "        AccountType: TestAccountType\n" +
                "    selection2:\n" +
                "        AccountName: TestAccountName\n" +
                "    selection3:\n" +
                "        EventID: 22\n" +
                "    condition: (not selection1 and not selection2) and selection3\n" +
                "falsepositives:\n" +
                "    - Legitimate usage of remote file encryption\n" +
                "level: high";
    }

    public static String randomRuleWithCriticalSeverity() {
        return "title: Remote Encrypting File System Abuse\n" +
                "id: 5f92fff9-82e2-48eb-8fc1-8b133556a551\n" +
                "description: Detects remote RPC calls to possibly abuse remote encryption service via MS-EFSR\n" +
                "references:\n" +
                "    - https://attack.mitre.org/tactics/TA0008/\n" +
                "    - https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-36942\n" +
                "    - https://github.com/jsecurity101/MSRPC-to-ATTACK/blob/main/documents/MS-EFSR.md\n" +
                "    - https://github.com/zeronetworks/rpcfirewall\n" +
                "    - https://zeronetworks.com/blog/stopping_lateral_movement_via_the_rpc_firewall/\n" +
                "tags:\n" +
                "    - attack.defense_evasion\n" +
                "status: experimental\n" +
                "author: Sagie Dulce, Dekel Paz\n" +
                "date: 2022/01/01\n" +
                "modified: 2022/01/01\n" +
                "logsource:\n" +
                "    product: rpc_firewall\n" +
                "    category: application\n" +
                "    definition: 'Requirements: install and apply the RPC Firewall to all processes with \"audit:true action:block uuid:df1941c5-fe89-4e79-bf10-463657acf44d or c681d488-d850-11d0-8c52-00c04fd90f7e'\n" +
                "detection:\n" +
                "    selection:\n" +
                "        EventID: 22\n" +
                "    condition: selection\n" +
                "falsepositives:\n" +
                "    - Legitimate usage of remote file encryption\n" +
                "level: critical";
    }

    public static String randomRuleWithNotConditionBoolAndNum() {
        return "title: Remote Encrypting File System Abuse\n" +
                "id: 5f92fff9-82e2-48eb-8fc1-8b133556a551\n" +
                "description: Detects remote RPC calls to possibly abuse remote encryption service via MS-EFSR\n" +
                "references:\n" +
                "    - https://attack.mitre.org/tactics/TA0008/\n" +
                "    - https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-36942\n" +
                "    - https://github.com/jsecurity101/MSRPC-to-ATTACK/blob/main/documents/MS-EFSR.md\n" +
                "    - https://github.com/zeronetworks/rpcfirewall\n" +
                "    - https://zeronetworks.com/blog/stopping_lateral_movement_via_the_rpc_firewall/\n" +
                "tags:\n" +
                "    - attack.defense_evasion\n" +
                "status: experimental\n" +
                "author: Sagie Dulce, Dekel Paz\n" +
                "date: 2022/01/01\n" +
                "modified: 2022/01/01\n" +
                "logsource:\n" +
                "    product: rpc_firewall\n" +
                "    category: application\n" +
                "    definition: 'Requirements: install and apply the RPC Firewall to all processes with \"audit:true action:block uuid:df1941c5-fe89-4e79-bf10-463657acf44d or c681d488-d850-11d0-8c52-00c04fd90f7e'\n" +
                "detection:\n" +
                "    selection1:\n" +
                "        Initiated: \"false\"\n" +
                "    selection2:\n" +
                "        AccountName: TestAccountName\n" +
                "    selection3:\n" +
                "        EventID: 21\n" +
                "    condition: not selection1 and not selection3\n" +
                "falsepositives:\n" +
                "    - Legitimate usage of remote file encryption\n" +
                "level: high";
    }

    // TODO: not used, can we remove?
    public static String randomNullRule() {
        return "title: null field\n" +
                "id: 5f92fff9-82e2-48eb-8fc1-8b133556a551\n" +
                "description: Detects remote RPC calls to possibly abuse remote encryption service via MS-EFSR\n" +
                "references:\n" +
                "    - https://attack.mitre.org/tactics/TA0008/\n" +
                "    - https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-36942\n" +
                "    - https://github.com/jsecurity101/MSRPC-to-ATTACK/blob/main/documents/MS-EFSR.md\n" +
                "    - https://github.com/zeronetworks/rpcfirewall\n" +
                "    - https://zeronetworks.com/blog/stopping_lateral_movement_via_the_rpc_firewall/\n" +
                "tags:\n" +
                "    - attack.defense_evasion\n" +
                "status: experimental\n" +
                "author: Sagie Dulce, Dekel Paz\n" +
                "date: 2022/01/01\n" +
                "modified: 2022/01/01\n" +
                "logsource:\n" +
                "    product: rpc_firewall\n" +
                "    category: application\n" +
                "    definition: 'Requirements: install and apply the RPC Firew all to all processes with \"audit:true action:block uuid:df1941c5-fe89-4e79-bf10-463657acf44d or c681d488-d850-11d0-8c52-00c04fd90f7e'\n" +
                "detection:\n" +
                "    selection:\n" +
                "        EventID: 22\n" +
                "        RecordNumber: null\n" +
                "    condition: selection\n" +
                "falsepositives:\n" +
                "    - Legitimate usage of remote file encryption\n" +
                "level: high";
    }

    public static String randomCloudtrailRuleForCorrelations(String value) {
        return "id: 5f92fff9-82e2-48ab-8fc1-8b133556a551\n" +
                "logsource:\n" +
                "  product: cloudtrail\n" +
                "title: AWS User Created\n" +
                "description: AWS User Created\n" +
                "tags:\n" +
                "  - attack.test1\n" +
                "falsepositives:\n" +
                "  - Legit User Account Administration\n" +
                "level: high\n" +
                "date: 2022/01/01\n" +
                "status: experimental\n" +
                "references:\n" +
                "  - 'https://github.com/RhinoSecurityLabs/AWS-IAM-Privilege-Escalation'\n" +
                "author: toffeebr33k\n" +
                "detection:\n" +
                "  condition: selection_source\n" +
                "  selection_source:\n" +
                "    EventName:\n" +
                "      - " + value;
    }

    public static String randomRuleForMappingView(String field) {
        return "title: Remote Encrypting File System Abuse\n" +
                "id: 5f92fff9-82e2-48eb-8fc1-8b133556a551\n" +
                "description: Detects remote RPC calls to possibly abuse remote encryption service via MS-EFSR\n" +
                "references:\n" +
                "    - https://attack.mitre.org/tactics/TA0008/\n" +
                "    - https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-36942\n" +
                "    - https://github.com/jsecurity101/MSRPC-to-ATTACK/blob/main/documents/MS-EFSR.md\n" +
                "    - https://github.com/zeronetworks/rpcfirewall\n" +
                "    - https://zeronetworks.com/blog/stopping_lateral_movement_via_the_rpc_firewall/\n" +
                "tags:\n" +
                "    - attack.defense_evasion\n" +
                "status: experimental\n" +
                "author: Sagie Dulce, Dekel Paz\n" +
                "date: 2022/01/01\n" +
                "modified: 2022/01/01\n" +
                "logsource:\n" +
                "    product: rpc_firewall\n" +
                "    category: application\n" +
                "    definition: 'Requirements: install and apply the RPC Firewall to all processes with \"audit:true action:block uuid:df1941c5-fe89-4e79-bf10-463657acf44d or c681d488-d850-11d0-8c52-00c04fd90f7e'\n" +
                "detection:\n" +
                "    selection:\n" +
                "        " + field + ": 'ACL'\n" +
                "    condition: selection\n" +
                "falsepositives:\n" +
                "    - Legitimate usage of remote file encryption\n" +
                "level: high";
    }

    public static String randomRuleForCustomLogType() {
        return "title: Remote Encrypting File System Abuse\n" +
                "id: 5f92fff9-82e2-48eb-8fc1-8b133556a551\n" +
                "description: Detects remote RPC calls to possibly abuse remote encryption service via MS-EFSR\n" +
                "references:\n" +
                "    - https://attack.mitre.org/tactics/TA0008/\n" +
                "    - https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-36942\n" +
                "    - https://github.com/jsecurity101/MSRPC-to-ATTACK/blob/main/documents/MS-EFSR.md\n" +
                "    - https://github.com/zeronetworks/rpcfirewall\n" +
                "    - https://zeronetworks.com/blog/stopping_lateral_movement_via_the_rpc_firewall/\n" +
                "tags:\n" +
                "    - attack.defense_evasion\n" +
                "status: experimental\n" +
                "author: Sagie Dulce, Dekel Paz\n" +
                "date: 2022/01/01\n" +
                "modified: 2022/01/01\n" +
                "logsource:\n" +
                "    product: rpc_firewall\n" +
                "    category: application\n" +
                "    definition: 'Requirements: install and apply the RPC Firewall to all processes with \"audit:true action:block uuid:df1941c5-fe89-4e79-bf10-463657acf44d or c681d488-d850-11d0-8c52-00c04fd90f7e'\n" +
                "detection:\n" +
                "    selection:\n" +
                "        EventID: 22\n" +
                "        Author: 'Hello'\n" +
                "    condition: selection\n" +
                "falsepositives:\n" +
                "    - Legitimate usage of remote file encryption\n" +
                "level: high";
    }

    public static String randomRuleWithAlias() {
        return "title: Remote Encrypting File System Abuse\n" +
                "id: 5f92fff9-82e2-48eb-8fc1-8b133556a551\n" +
                "description: Detects remote RPC calls to possibly abuse remote encryption service via MS-EFSR\n" +
                "references:\n" +
                "    - https://attack.mitre.org/tactics/TA0008/\n" +
                "    - https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-36942\n" +
                "    - https://github.com/jsecurity101/MSRPC-to-ATTACK/blob/main/documents/MS-EFSR.md\n" +
                "    - https://github.com/zeronetworks/rpcfirewall\n" +
                "    - https://zeronetworks.com/blog/stopping_lateral_movement_via_the_rpc_firewall/\n" +
                "tags:\n" +
                "    - attack.defense_evasion\n" +
                "status: experimental\n" +
                "author: Sagie Dulce, Dekel Paz\n" +
                "date: 2022/01/01\n" +
                "modified: 2022/01/01\n" +
                "logsource:\n" +
                "    product: rpc_firewall\n" +
                "    category: application\n" +
                "    definition: 'Requirements: install and apply the RPC Firewall to all processes with \"audit:true action:block uuid:df1941c5-fe89-4e79-bf10-463657acf44d or c681d488-d850-11d0-8c52-00c04fd90f7e'\n" +
                "detection:\n" +
                "    selection:\n" +
                "        event_uid: 22\n" +
                "    condition: selection\n" +
                "falsepositives:\n" +
                "    - Legitimate usage of remote file encryption\n" +
                "level: high";
    }

    public static String randomRuleWithKeywords() {
        return "title: Remote Encrypting File System Abuse\n" +
                "id: 5f92fff9-82e2-48eb-8fc1-8b133556a551\n" +
                "description: Detects remote RPC calls to possibly abuse remote encryption service via MS-EFSR\n" +
                "references:\n" +
                "    - https://attack.mitre.org/tactics/TA0008/\n" +
                "    - https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-36942\n" +
                "    - https://github.com/jsecurity101/MSRPC-to-ATTACK/blob/main/documents/MS-EFSR.md\n" +
                "    - https://github.com/zeronetworks/rpcfirewall\n" +
                "    - https://zeronetworks.com/blog/stopping_lateral_movement_via_the_rpc_firewall/\n" +
                "tags:\n" +
                "    - attack.defense_evasion\n" +
                "status: experimental\n" +
                "author: Sagie Dulce, Dekel Paz\n" +
                "date: 2022/01/01\n" +
                "modified: 2022/01/01\n" +
                "logsource:\n" +
                "    product: rpc_firewall\n" +
                "    category: application\n" +
                "    definition: 'Requirements: install and apply the RPC Firewall to all processes with \"audit:true action:block uuid:df1941c5-fe89-4e79-bf10-463657acf44d or c681d488-d850-11d0-8c52-00c04fd90f7e'\n" +
                "detection:\n" +
                "    selection:\n" +
                "        EventID: 21\n" +
                "    keywords:\n" +
                "        - 1996\n" +
                "        - EC2AMAZ*\n" +
                "    condition: selection or keywords\n" +
                "falsepositives:\n" +
                "    - Legitimate usage of remote file encryption\n" +
                "level: high";
    }

    public static String randomRuleWithStringKeywords() {
        return "title: Remote Encrypting File System Abuse\n" +
                "id: 5f92fff9-82e2-48eb-8fc1-8b133556a551\n" +
                "description: Detects remote RPC calls to possibly abuse remote encryption service via MS-EFSR\n" +
                "references:\n" +
                "    - https://attack.mitre.org/tactics/TA0008/\n" +
                "    - https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-36942\n" +
                "    - https://github.com/jsecurity101/MSRPC-to-ATTACK/blob/main/documents/MS-EFSR.md\n" +
                "    - https://github.com/zeronetworks/rpcfirewall\n" +
                "    - https://zeronetworks.com/blog/stopping_lateral_movement_via_the_rpc_firewall/\n" +
                "tags:\n" +
                "    - attack.defense_evasion\n" +
                "status: experimental\n" +
                "author: Sagie Dulce, Dekel Paz\n" +
                "date: 2022/01/01\n" +
                "modified: 2022/01/01\n" +
                "logsource:\n" +
                "    product: rpc_firewall\n" +
                "    category: application\n" +
                "    definition: 'Requirements: install and apply the RPC Firewall to all processes with \"audit:true action:block uuid:df1941c5-fe89-4e79-bf10-463657acf44d or c681d488-d850-11d0-8c52-00c04fd90f7e'\n" +
                "detection:\n" +
                "    selection:\n" +
                "        EventID: 21\n" +
                "    keywords:\n" +
                "        - \"INFO\"\n" +
                "    condition: selection or keywords\n" +
                "falsepositives:\n" +
                "    - Legitimate usage of remote file encryption\n" +
                "level: high";
    }

    public static String randomRuleWithDateKeywords() {
        return "title: Remote Encrypting File System Abuse\n" +
                "id: 5f92fff9-82e2-48eb-8fc1-8b133556a551\n" +
                "description: Detects remote RPC calls to possibly abuse remote encryption service via MS-EFSR\n" +
                "references:\n" +
                "    - https://attack.mitre.org/tactics/TA0008/\n" +
                "    - https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-36942\n" +
                "    - https://github.com/jsecurity101/MSRPC-to-ATTACK/blob/main/documents/MS-EFSR.md\n" +
                "    - https://github.com/zeronetworks/rpcfirewall\n" +
                "    - https://zeronetworks.com/blog/stopping_lateral_movement_via_the_rpc_firewall/\n" +
                "tags:\n" +
                "    - attack.defense_evasion\n" +
                "status: experimental\n" +
                "author: Sagie Dulce, Dekel Paz\n" +
                "date: 2022/01/01\n" +
                "modified: 2022/01/01\n" +
                "logsource:\n" +
                "    product: rpc_firewall\n" +
                "    category: application\n" +
                "    definition: 'Requirements: install and apply the RPC Firewall to all processes with \"audit:true action:block uuid:df1941c5-fe89-4e79-bf10-463657acf44d or c681d488-d850-11d0-8c52-00c04fd90f7e'\n" +
                "detection:\n" +
                "    selection:\n" +
                "        EventID: 21\n" +
                "    keywords:\n" +
                "        - \"2020-02-04T14:59:39.343541+00:00\"\n" +
                "    condition: selection or keywords\n" +
                "falsepositives:\n" +
                "    - Legitimate usage of remote file encryption\n" +
                "level: high";
    }

    public static String countAggregationTestRule() {
        return "            title: Test\n" +
                "            id: 39f919f3-980b-4e6f-a975-8af7e507ef2b\n" +
                "            status: test\n" +
                "            level: critical\n" +
                "            description: Detects QuarksPwDump clearing access history in hive\n" +
                "            author: Florian Roth\n" +
                "            date: 2017/05/15\n" +
                "            logsource:\n" +
                "                category: test_category\n" +
                "                product: test_product\n" +
                "            detection:\n" +
                "                sel:\n" +
                "                    fieldA: valueA\n" +
                "                    fieldB: valueB\n" +
                "                    fieldC: valueC\n" +
                "                condition: sel | count(*) > 1";
    }

    public static String sumAggregationTestRule() {
        return "            title: Test\n" +
                "            id: 39f919f3-980b-4e6f-a975-8af7e507ef2b\n" +
                "            status: test\n" +
                "            level: critical\n" +
                "            description: Detects QuarksPwDump clearing access history in hive\n" +
                "            author: Florian Roth\n" +
                "            date: 2017/05/15\n" +
                "            logsource:\n" +
                "                category: test_category\n" +
                "                product: test_product\n" +
                "            detection:\n" +
                "                sel:\n" +
                "                    fieldA: 123\n" +
                "                    fieldB: 111\n" +
                "                    fieldC: valueC\n" +
                "                condition: sel | sum(fieldA) by fieldB > 110";
    }

    // TODO: not used, can we remove?
    public static String productIndexMaxAggRule() {
        return "            title: Test\n" +
                "            id: 5f92fff9-82e3-48eb-8fc1-8b133556a551\n" +
                "            status: test\n" +
                "            level: critical\n" +
                "            description: Detects QuarksPwDump clearing access history in hive\n" +
                "            author: Florian Roth\n" +
                "            date: 2017/05/15\n" +
                "            logsource:\n" +
                "                category: test_category\n" +
                "                product: test_product\n" +
                "            detection:\n" +
                "                sel:\n" +
                "                    fieldA: 123\n" +
                "                    fieldB: 111\n" +
                "                    fieldC: valueC\n" +
                "                condition: sel | max(fieldA) by fieldB > 110";
    }

    public static String randomEditedRule() {
        return "title: Remote Encrypting File System Abuse\n" +
                "id: 5f92fff9-82e2-48eb-8fc1-8b133556a551\n" +
                "description: Detects remote RPC calls to possibly abuse remote encryption service via MS-EFSR\n" +
                "references:\n" +
                "    - https://attack.mitre.org/tactics/TA0008/\n" +
                "    - https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-36942\n" +
                "    - https://github.com/jsecurity101/MSRPC-to-ATTACK/blob/main/documents/MS-EFSR.md\n" +
                "    - https://github.com/zeronetworks/rpcfirewall\n" +
                "    - https://zeronetworks.com/blog/stopping_lateral_movement_via_the_rpc_firewall/\n" +
                "tags:\n" +
                "    - attack.lateral_movement\n" +
                "status: experimental\n" +
                "author: Sagie Dulce, Dekel Paz\n" +
                "date: 2022/01/01\n" +
                "modified: 2022/01/01\n" +
                "logsource:\n" +
                "    product: rpc_firewall\n" +
                "    category: application\n" +
                "    definition: 'Requirements: install and apply the RPC Firewall to all processes with \"audit:true action:block uuid:df1941c5-fe89-4e79-bf10-463657acf44d or c681d488-d850-11d0-8c52-00c04fd90f7e'\n" +
                "detection:\n" +
                "    selection:\n" +
                "        EventID: 24\n" +
                "    condition: selection\n" +
                "falsepositives:\n" +
                "    - Legitimate usage of remote file encryption\n" +
                "level: high";
    }

    public static String randomEditedRuleInvalidSyntax(String title) {
        return "title: " + title + "\n" +
                "id: 5f92fff9-82e2-48eb-8fc1-8b133556a551\n" +
                "description: Detects remote RPC calls to possibly abuse remote encryption service via MS-EFSR\n" +
                "references:\n" +
                "    - https://attack.mitre.org/tactics/TA0008/\n" +
                "    - https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-36942\n" +
                "    - https://github.com/jsecurity101/MSRPC-to-ATTACK/blob/main/documents/MS-EFSR.md\n" +
                "    - https://github.com/zeronetworks/rpcfirewall\n" +
                "    - https://zeronetworks.com/blog/stopping_lateral_movement_via_the_rpc_firewall/\n" +
                "tags:\n" +
                "    - attack.lateral_movement\n" +
                "status: experimental\n" +
                "author: Sagie Dulce, Dekel Paz\n" +
                "date: 2022/01/01\n" +
                "modified: 2022/01/01\n" +
                "logsource:\n" +
                "    product: rpc_firewall\n" +
                "    category: application\n" +
                "    definition: 'Requirements: install and apply the RPC Firewall to all processes with \"audit:true action:block uuid:df1941c5-fe89-4e79-bf10-463657acf44d or c681d488-d850-11d0-8c52-00c04fd90f7e'\n" +
                "detection:\n" +
                "    selection:\n" +
                "        EventID: 24\n" +
                "    condition: selection\n" +
                "falsepositives:\n" +
                "    - Legitimate usage of remote file encryption\n" +
                "level: high";
    }

    public static String randomRuleWithErrors() {
        return "title: Remote Encrypting File System Abuse\n" +
                "id: 5f92fff9-82e2-48eb-8fc1-8b133556a551\n" +
                "description: Detects remote RPC calls to possibly abuse remote encryption service via MS-EFSR\n" +
                "references:\n" +
                "    - https://attack.mitre.org/tactics/TA0008/\n" +
                "    - https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-36942\n" +
                "    - https://github.com/jsecurity101/MSRPC-to-ATTACK/blob/main/documents/MS-EFSR.md\n" +
                "    - https://github.com/zeronetworks/rpcfirewall\n" +
                "    - https://zeronetworks.com/blog/stopping_lateral_movement_via_the_rpc_firewall/\n" +
                "tags:\n" +
                "    - attack.lateral_movement\n" +
                "status: experimental\n" +
                "author: Sagie Dulce, Dekel Paz\n" +
                "date: 2022/01/01\n" +
                "modified: 2022/01/01\n" +
                "falsepositives:\n" +
                "    - Legitimate usage of remote file encryption\n" +
                "level: high";
    }

    public static String randomRuleWithErrors(String title) {
        return "title: " + title + "\n" +
                "id: 5f92fff9-82e2-48eb-8fc1-8b133556a551\n" +
                "description: Detects remote RPC calls to possibly abuse remote encryption service via MS-EFSR\n" +
                "references:\n" +
                "    - https://attack.mitre.org/tactics/TA0008/\n" +
                "    - https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-36942\n" +
                "    - https://github.com/jsecurity101/MSRPC-to-ATTACK/blob/main/documents/MS-EFSR.md\n" +
                "    - https://github.com/zeronetworks/rpcfirewall\n" +
                "    - https://zeronetworks.com/blog/stopping_lateral_movement_via_the_rpc_firewall/\n" +
                "tags:\n" +
                "    - attack.lateral_movement\n" +
                "status: experimental\n" +
                "author: Sagie Dulce, Dekel Paz\n" +
                "date: 2022/01/01\n" +
                "modified: 2022/01/01\n" +
                "falsepositives:\n" +
                "    - Legitimate usage of remote file encryption\n" +
                "level: high";
    }

    public static String productIndexAvgAggRule() {
        return "            title: Test\n" +
                "            id: 39f918f3-981b-4e6f-a975-8af7e507ef2b\n" +
                "            status: test\n" +
                "            level: critical\n" +
                "            description: Detects QuarksPwDump clearing access history in hive\n" +
                "            author: Florian Roth\n" +
                "            date: 2017/05/15\n" +
                "            logsource:\n" +
                "                category: test_category\n" +
                "                product: test_product\n" +
                "            detection:\n" +
                "                timeframe: 5m\n" +
                "                sel:\n" +
                "                    fieldA: 123\n" +
                "                    fieldB: 111\n" +
                "                    fieldC: valueC\n" +
                "                condition: sel | avg(fieldA) by fieldC > 110";
    }

    public static String productIndexCountAggRule() {
        return "            title: Test\n" +
                "            id: 39f918f3-981b-4e6f-a975-8af7e507ef2b\n" +
                "            status: test\n" +
                "            level: critical\n" +
                "            description: Detects QuarksPwDump clearing access history in hive\n" +
                "            author: Florian Roth\n" +
                "            date: 2017/05/15\n" +
                "            logsource:\n" +
                "                category: test_category\n" +
                "                product: test_product\n" +
                "            detection:\n" +
                "                timeframe: 5m\n" +
                "                sel:\n" +
                "                    name: laptop\n" +
                "                condition: sel | count(*) by name > 2";
    }

    public static String randomAggregationRule(String aggFunction, String signAndValue) {
        String rule = "title: Remote Encrypting File System Abuse\n" +
                "id: 5f92fff9-82e2-48eb-8fc1-8b133556a551\n" +
                "description: Detects remote RPC calls to possibly abuse remote encryption service via MS-EFSR\n" +
                "references:\n" +
                "    - https://attack.mitre.org/tactics/TA0008/\n" +
                "    - https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-36942\n" +
                "    - https://github.com/jsecurity101/MSRPC-to-ATTACK/blob/main/documents/MS-EFSR.md\n" +
                "    - https://github.com/zeronetworks/rpcfirewall\n" +
                "    - https://zeronetworks.com/blog/stopping_lateral_movement_via_the_rpc_firewall/\n" +
                "tags:\n" +
                "    - attack.defense_evasion\n" +
                "status: experimental\n" +
                "author: Sagie Dulce, Dekel Paz\n" +
                "date: 2022/01/01\n" +
                "modified: 2022/01/01\n" +
                "logsource:\n" +
                "    product: rpc_firewall\n" +
                "    category: application\n" +
                "    definition: 'Requirements: install and apply the RPC Firewall to all processes with \"audit:true action:block uuid:df1941c5-fe89-4e79-bf10-463657acf44d or c681d488-d850-11d0-8c52-00c04fd90f7e'\n" +
                "detection:\n" +
                "    timeframe: 5m\n" +
                "    sel:\n" +
                "        Opcode: Info\n" +
                "    condition: sel | %s(SeverityValue) by Version %s\n" +
                "falsepositives:\n" +
                "    - Legitimate usage of remote file encryption\n" +
                "level: high";
        return String.format(Locale.ROOT, rule, aggFunction, signAndValue);
    }

    public static String randomAggregationRule(String aggFunction, String signAndValue, String opCode) {
        String rule = "title: Remote Encrypting File System Abuse\n" +
                "id: 5f92fff9-82e2-48eb-8fc1-8b133556a551\n" +
                "description: Detects remote RPC calls to possibly abuse remote encryption service via MS-EFSR\n" +
                "references:\n" +
                "    - https://attack.mitre.org/tactics/TA0008/\n" +
                "    - https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-36942\n" +
                "    - https://github.com/jsecurity101/MSRPC-to-ATTACK/blob/main/documents/MS-EFSR.md\n" +
                "    - https://github.com/zeronetworks/rpcfirewall\n" +
                "    - https://zeronetworks.com/blog/stopping_lateral_movement_via_the_rpc_firewall/\n" +
                "tags:\n" +
                "    - attack.defense_evasion\n" +
                "status: experimental\n" +
                "author: Sagie Dulce, Dekel Paz\n" +
                "date: 2022/01/01\n" +
                "modified: 2022/01/01\n" +
                "logsource:\n" +
                "    product: rpc_firewall\n" +
                "    category: application\n" +
                "    definition: 'Requirements: install and apply the RPC Firewall to all processes with \"audit:true action:block uuid:df1941c5-fe89-4e79-bf10-463657acf44d or c681d488-d850-11d0-8c52-00c04fd90f7e'\n" +
                "detection:\n" +
                "    timeframe: 5m\n" +
                "    sel:\n" +
                "        Opcode: %s\n" +
                "    condition: sel | %s(SeverityValue) by Version %s\n" +
                "falsepositives:\n" +
                "    - Legitimate usage of remote file encryption\n" +
                "level: high";
        return String.format(Locale.ROOT, rule, opCode, aggFunction, signAndValue);
    }

    public static String randomCloudtrailAggrRule() {
        return "id: c64c5175-5189-431b-a55e-6d9882158250\n" +
                "logsource:\n" +
                "  product: cloudtrail\n" +
                "title: Accounts created and deleted within 24h\n" +
                "description: Flag suspicious activity of accounts created and deleted within 24h\n" +
                "date: 2021/09/23\n" +
                "tags:\n" +
                "  - attack.exfiltration\n" +
                "falsepositives: [ ]\n" +
                "level: high\n" +
                "status: test\n" +
                "references: [ ]\n" +
                "author: Sashank\n" +
                "detection:\n" +
                "  selection:\n" +
                "    EventName:\n" +
                "      - CREATED\n" +
                "      - DELETED\n" +
                "  timeframe: 24h\n" +
                "  condition: selection | count(*) by AccountName >= 2";
    }

    public static String randomCloudtrailAggrRuleWithDotFields() {
        return "id: 25b9c01c-350d-4c96-bed1-836d04a4f324\n" +
                "title: test\n" +
                "description: Detects when an user creates or invokes a lambda function.\n" +
                "status: experimental\n" +
                "author: deysubho\n" +
                "date: 2023/12/07\n" +
                "modified: 2023/12/07\n" +
                "logsource:\n" +
                "  category: cloudtrail\n" +
                "level: low\n" +
                "detection:\n" +
                "  condition: selection1 or selection2 | count(api.operation) by cloud.region > 1\n" +
                "  selection1:\n" +
                "    api.service.name:\n" +
                "      - lambda.amazonaws.com\n" +
                "    api.operation:\n" +
                "      - CreateFunction\n" +
                "  selection2:\n" +
                "    api.service.name:\n" +
                "      - lambda.amazonaws.com\n" +
                "    api.operation:      \n" +
                "      - Invoke\n" +
                "  timeframe: 1m\n" +
                "  tags:\n" +
                "    - attack.privilege_escalation\n" +
                "    - attack.t1078";
    }

    public static String randomCloudtrailAggrRuleWithEcsFields() {
        return "id: 25b9c01c-350d-4c96-bed1-836d04a4f324\n" +
                "title: test\n" +
                "description: Detects when an user creates or invokes a lambda function.\n" +
                "status: experimental\n" +
                "author: deysubho\n" +
                "date: 2023/12/07\n" +
                "modified: 2023/12/07\n" +
                "logsource:\n" +
                "  category: cloudtrail\n" +
                "level: low\n" +
                "detection:\n" +
                "  condition: selection1 or selection2 | count(eventName) by awsRegion > 1\n" +
                "  selection1:\n" +
                "    eventSource:\n" +
                "      - lambda.amazonaws.com\n" +
                "    eventName:\n" +
                "      - CreateFunction\n" +
                "  selection2:\n" +
                "    eventSource:\n" +
                "      - lambda.amazonaws.com\n" +
                "    eventName:      \n" +
                "      - Invoke\n" +
                "  timeframe: 20m\n" +
                "  tags:\n" +
                "    - attack.privilege_escalation\n" +
                "    - attack.t1078";
    }

    public static String windowsKillingSysmonSilentlyRule() {
        return "title: Killing Sysmon Silently\n" +
               "id: 1f2b5353-573f-4880-8e33-7d04dcf97744\n" +
               "description: Killing Sysmon Silently\n" +
               "references:\n" +
               "    - https://talesfrominfosec.blogspot.com/2017/12/killing-sysmon-silently.html\n" +
               "    - https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1562.001/T1562.001.md\n" +
               "tags:\n" +
               "    - attack.t1564\n" +
               "    - attack.defense_evasion\n" +
               "status: experimental\n" +
               "author: talesfrominfosec\n" +
               "date: 2025/01/31\n" +
               "logsource:\n" +
               "    product: windows\n" +
               "detection:\n" +
               "    selection:\n" +
               "        process.name:\n" +
               "            - MpCmdRun.exe\n" +
               "            - NisSrv.exe\n" +
               "    selection_evt:\n" +
               "        event.code: 1\n" +
               "        event.module: sysmon\n" +
               "    filter_main_known_locations:\n" +
               "        process.executable|contains:\n" +
               "            - C:\\Program Files (x86)\\Windows Defender\\\n" +
               "            - C:\\Program Files\\Microsoft Security Client\\\n" +
               "            - C:\\Program Files\\Windows Defender\\\n" +
               "            - C:\\ProgramData\\Microsoft\\Windows Defender\\Platform\\\n" +
               "            - C:\\Windows\\WinSxS\\\n" +
               "    condition: (selection and selection_evt) and not filter_main_known_locations\n"+
               "falsepositives:\n" +
               "    - Legitimate administrative action\n" +
               "level: high";
    }

    public static String windowsSysmonModificationDummy1Rule() {
        return "title: Sysmon Modification Dummy 01\n" +
               "id: 1f2b5353-573f-4880-8e33-7d04dcf97755\n" +
               "description: Sysmon Modification Dummy 01\n" +
               "references:\n" +
               "    - https://talesfrominfosec.blogspot.com/2017/12/killing-sysmon-silently.html\n" +
               "    - https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1562.001/T1562.001.md\n" +
               "tags:\n" +
               "    - attack.t1564\n" +
               "    - attack.defense_evasion\n" +
               "status: experimental\n" +
               "author: rios0rios0\n" +
               "date: 2025/01/31\n" +
               "logsource:\n" +
               "    product: windows\n" +
               "detection:\n" +
               "    selection:\n" +
               "        message|contains: 'executed from an unusual'\n" +
               "    condition: selection\n"+
               "falsepositives:\n" +
               "    - Legitimate administrative action\n" +
               "level: high";
    }

    public static String windowsSysmonModificationDummy2Rule() {
        return "title: Sysmon Modification Dummy 02\n" +
               "id: 1f2b5353-573f-4880-8e33-7d04dcf97766\n" +
               "description: Sysmon Modification Dummy 02\n" +
               "references:\n" +
               "    - https://talesfrominfosec.blogspot.com/2017/12/killing-sysmon-silently.html\n" +
               "    - https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1562.001/T1562.001.md\n" +
               "tags:\n" +
               "    - attack.t1564\n" +
               "    - attack.defense_evasion\n" +
               "status: experimental\n" +
               "author: rios0rios0\n" +
               "date: 2025/01/31\n" +
               "logsource:\n" +
               "    product: windows\n" +
               "detection:\n" +
               "    selection:\n" +
               "        message|startswith: 'Process MpCmdRun.exe executed'\n" +
               "    condition: selection\n"+
               "falsepositives:\n" +
               "    - Legitimate administrative action\n" +
               "level: high";
    }

    public static String windowsSysmonModificationDummy3Rule() {
        return "title: Sysmon Modification Dummy 03\n" +
               "id: 1f2b5353-573f-4880-8e33-7d04dcf97777\n" +
               "description: Sysmon Modification Dummy 03\n" +
               "references:\n" +
               "    - https://talesfrominfosec.blogspot.com/2017/12/killing-sysmon-silently.html\n" +
               "    - https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1562.001/T1562.001.md\n" +
               "tags:\n" +
               "    - attack.t1564\n" +
               "    - attack.defense_evasion\n" +
               "status: experimental\n" +
               "author: rios0rios0\n" +
               "date: 2025/01/31\n" +
               "logsource:\n" +
               "    product: windows\n" +
               "detection:\n" +
               "    selection:\n" +
               "        message|endswith: 'unusual location.'\n" +
               "    condition: selection\n"+
               "falsepositives:\n" +
               "    - Legitimate administrative action\n" +
               "level: high";
    }
}
