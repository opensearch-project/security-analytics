/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.securityanalytics;

import com.carrotsearch.randomizedtesting.generators.RandomNumbers;
import org.apache.lucene.tests.util.LuceneTestCase;
import org.opensearch.common.xcontent.LoggingDeprecationHandler;
import org.opensearch.common.xcontent.XContentFactory;
import org.opensearch.common.xcontent.XContentType;
import org.opensearch.commons.alerting.model.IntervalSchedule;
import org.opensearch.commons.alerting.model.Schedule;
import org.opensearch.commons.alerting.model.action.Action;
import org.opensearch.commons.alerting.model.action.Throttle;
import org.opensearch.commons.authuser.User;
import org.opensearch.core.common.bytes.BytesReference;
import org.opensearch.core.xcontent.NamedXContentRegistry;
import org.opensearch.core.xcontent.ToXContent;
import org.opensearch.core.xcontent.XContentBuilder;
import org.opensearch.core.xcontent.XContentParser;
import org.opensearch.script.Script;
import org.opensearch.script.ScriptType;
import org.opensearch.securityanalytics.commons.model.IOCType;
import org.opensearch.securityanalytics.model.CorrelationQuery;
import org.opensearch.securityanalytics.model.CorrelationRule;
import org.opensearch.securityanalytics.model.CorrelationRuleTrigger;
import org.opensearch.securityanalytics.model.CustomLogType;
import org.opensearch.securityanalytics.model.Detector;
import org.opensearch.securityanalytics.model.DetectorInput;
import org.opensearch.securityanalytics.model.DetectorRule;
import org.opensearch.securityanalytics.model.DetectorTrigger;
import org.opensearch.securityanalytics.model.STIX2IOCDto;
import org.opensearch.securityanalytics.model.ThreatIntelFeedData;
import org.opensearch.securityanalytics.model.threatintel.IocFinding;
import org.opensearch.securityanalytics.model.threatintel.ThreatIntelAlert;
import org.opensearch.securityanalytics.threatIntel.common.RefreshType;
import org.opensearch.securityanalytics.threatIntel.common.SourceConfigType;
import org.opensearch.securityanalytics.threatIntel.common.TIFJobState;
import org.opensearch.securityanalytics.threatIntel.model.DefaultIocStoreConfig;
import org.opensearch.securityanalytics.threatIntel.model.IocStoreConfig;
import org.opensearch.securityanalytics.threatIntel.model.S3Source;
import org.opensearch.securityanalytics.threatIntel.model.SATIFSourceConfig;
import org.opensearch.securityanalytics.threatIntel.model.SATIFSourceConfigDto;
import org.opensearch.securityanalytics.threatIntel.model.Source;
import org.opensearch.test.OpenSearchTestCase;
import org.opensearch.test.rest.OpenSearchRestTestCase;

import java.io.IOException;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.stream.Collectors;

import static org.opensearch.test.OpenSearchTestCase.randomInt;

public class TestHelpers {

    static class AccessRoles {
        static final String ALL_ACCESS_ROLE = "all_access";
    }

    public static Detector randomDetector(List<String> rules) {
        DetectorInput input = new DetectorInput("windows detector for security analytics", List.of("windows"), Collections.emptyList(),
                rules.stream().map(DetectorRule::new).collect(Collectors.toList()));
        return randomDetector(null, null, null, List.of(input), List.of(), null, null, null, null, false);
    }

    public static Detector randomDetector(List<String> rules, String detectorType) {
        DetectorInput input = new DetectorInput("windows detector for security analytics", List.of("windows"), Collections.emptyList(),
                rules.stream().map(DetectorRule::new).collect(Collectors.toList()));
        return randomDetector(null, detectorType, null, List.of(input), List.of(), null, null, null, null, false);
    }

    public static Detector randomDetectorWithInputs(List<DetectorInput> inputs) {
        return randomDetector(null, null, null, inputs, List.of(), null, null, null, null, false);
    }

    public static Detector randomDetectorWithInputsAndThreatIntel(List<DetectorInput> inputs, Boolean threatIntel) {
        return randomDetector(null, null, null, inputs, List.of(), null, null, null, null, threatIntel);
    }

    public static Detector randomDetectorWithInputsAndThreatIntelAndTriggers(List<DetectorInput> inputs, Boolean threatIntel, List<DetectorTrigger> triggers) {
        return randomDetector(null, null, null, inputs, triggers, null, null, null, null, threatIntel);
    }

    public static Detector randomDetectorWithInputsAndTriggers(List<DetectorInput> inputs, List<DetectorTrigger> triggers) {
        return randomDetector(null, null, null, inputs, triggers, null, null, null, null, false);
    }

    public static Detector randomDetectorWithInputs(List<DetectorInput> inputs, String detectorType) {
        return randomDetector(null, detectorType, null, inputs, List.of(), null, null, null, null, false);
    }


    public static Detector randomDetectorWithTriggers(List<DetectorTrigger> triggers) {
        return randomDetector(null, null, null, List.of(), triggers, null, null, null, null, false);
    }

    public static Detector randomDetectorWithTriggers(List<String> rules, List<DetectorTrigger> triggers) {
        DetectorInput input = new DetectorInput("windows detector for security analytics", List.of("windows"), Collections.emptyList(),
                rules.stream().map(DetectorRule::new).collect(Collectors.toList()));
        return randomDetector(null, null, null, List.of(input), triggers, null, null, null, null, false);
    }

    public static Detector randomDetectorWithTriggers(List<String> rules, List<DetectorTrigger> triggers, List<String> inputIndices) {
        DetectorInput input = new DetectorInput("windows detector for security analytics", inputIndices, Collections.emptyList(),
                rules.stream().map(DetectorRule::new).collect(Collectors.toList()));
        return randomDetector(null, null, null, List.of(input), triggers, null, true, null, null, false);
    }

    public static Detector randomDetectorWithTriggersAndScheduleAndEnabled(List<String> rules, List<DetectorTrigger> triggers, Schedule schedule, boolean enabled) {
        DetectorInput input = new DetectorInput("windows detector for security analytics", List.of("windows"), Collections.emptyList(),
                rules.stream().map(DetectorRule::new).collect(Collectors.toList()));
        return randomDetector(null, null, null, List.of(input), triggers, schedule, enabled, null, null, false);
    }

    public static Detector randomDetectorWithTriggers(List<String> rules, List<DetectorTrigger> triggers, String detectorType, DetectorInput input) {
        return randomDetector(null, detectorType, null, List.of(input), triggers, null, null, null, null, false);
    }

    public static Detector randomDetectorWithInputsAndTriggersAndType(List<DetectorInput> inputs, List<DetectorTrigger> triggers, String detectorType) {
        return randomDetector(null, detectorType, null, inputs, triggers, null, null, null, null, false);
    }

    public static Detector randomDetector(String name,
                                          String detectorType,
                                          User user,
                                          List<DetectorInput> inputs,
                                          List<DetectorTrigger> triggers,
                                          Schedule schedule,
                                          Boolean enabled,
                                          Instant enabledTime,
                                          Instant lastUpdateTime,
                                          Boolean threatIntel) {
        if (name == null) {
            name = OpenSearchRestTestCase.randomAlphaOfLength(10);
        }
        if (detectorType == null) {
            detectorType = randomDetectorType();
        }
        if (user == null) {
            user = randomUser();
        }
        if (inputs == null) {
            inputs = Collections.emptyList();
        }
        if (schedule == null) {
            schedule = new IntervalSchedule(5, ChronoUnit.MINUTES, null);
        }
        if (enabled == null) {
            enabled = OpenSearchTestCase.randomBoolean();
        }
        if (enabledTime == null) {
            if (enabled) {
                enabledTime = Instant.now().truncatedTo(ChronoUnit.MILLIS);
            }
        }
        if (lastUpdateTime == null) {
            lastUpdateTime = Instant.now().truncatedTo(ChronoUnit.MILLIS);
        }
        if (inputs.size() == 0) {
            inputs = new ArrayList<>();

            DetectorInput input = new DetectorInput("windows detector for security analytics", List.of("windows"), Collections.emptyList(), null);
            inputs.add(input);
        }
        if (triggers.size() == 0) {
            triggers = new ArrayList<>();

            DetectorTrigger trigger = new DetectorTrigger(null, "windows-trigger", "1", List.of(randomDetectorType()), List.of("QuarksPwDump Clearing Access History"), List.of("high"), List.of("T0008"), List.of(), List.of());
            triggers.add(trigger);
        }
        return new Detector(null, null, name, enabled, schedule, lastUpdateTime, enabledTime, detectorType, user, inputs, triggers, Collections.singletonList(""), "", "", "", "", "", "", Collections.emptyMap(), Collections.emptyList(), threatIntel);
    }

    public static CustomLogType randomCustomLogType(String name, String description, String category, String source) {
        if (name == null) {
            name = "custom-log-type";
        }
        if (description == null) {
            description = "custom-log-type-desc";
        }
        if (category == null) {
            category = "Other";
        }
        if (source == null) {
            source = "Sigma";
        }
        return new CustomLogType(null, null, name, description, category, source, null);
    }

    public static ThreatIntelFeedData randomThreatIntelFeedData() {
        return new ThreatIntelFeedData(
                "IP_ADDRESS",
                "ip",
                "alientVault",
                Instant.now()
        );
    }

    public static Detector randomDetectorWithNoUser() {
        String name = OpenSearchRestTestCase.randomAlphaOfLength(10);
        String detectorType = randomDetectorType();
        List<DetectorInput> inputs = Collections.emptyList();
        Schedule schedule = new IntervalSchedule(5, ChronoUnit.MINUTES, null);
        Boolean enabled = OpenSearchTestCase.randomBoolean();
        Instant enabledTime = enabled ? Instant.now().truncatedTo(ChronoUnit.MILLIS) : null;
        Instant lastUpdateTime = Instant.now().truncatedTo(ChronoUnit.MILLIS);

        return new Detector(
                null,
                null,
                name,
                enabled,
                schedule,
                lastUpdateTime,
                enabledTime,
                detectorType,
                null,
                inputs,
                Collections.emptyList(),
                Collections.singletonList(""),
                "",
                "",
                "",
                "",
                "",
                "",
                Collections.emptyMap(),
                Collections.emptyList(),
                false
        );
    }

    public static CorrelationRule randomCorrelationRule(String name) {
        name = name.isEmpty() ? "><script>prompt(document.domain)</script>" : name;
        return new CorrelationRule(CorrelationRule.NO_ID, CorrelationRule.NO_VERSION, name,
                List.of(
                        new CorrelationQuery("vpc_flow1", "dstaddr:192.168.1.*", "network", null),
                        new CorrelationQuery("ad_logs1", "azure.platformlogs.result_type:50126", "ad_ldap", null)
                ), 300000L, null);
    }

    public static CorrelationRule randomCorrelationRuleWithTrigger(String name) {
        name = name.isEmpty() ? "><script>prompt(document.domain)</script>" : name;
        List<Action> actions = new ArrayList<Action>();
        CorrelationRuleTrigger trigger = new CorrelationRuleTrigger("trigger-123", "Trigger 1", "high", actions);
        return new CorrelationRule(CorrelationRule.NO_ID, CorrelationRule.NO_VERSION, name,
                List.of(
                        new CorrelationQuery("vpc_flow1", "dstaddr:192.168.1.*", "network", null),
                        new CorrelationQuery("ad_logs1", "azure.platformlogs.result_type:50126", "ad_ldap", null)
                ), 300000L, trigger);
    }

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

    public static String toJsonStringWithUser(Detector detector) throws IOException {
        XContentBuilder builder = XContentFactory.jsonBuilder();
        builder = detector.toXContentWithUser(builder, ToXContent.EMPTY_PARAMS);
        return BytesReference.bytes(builder).utf8ToString();
    }

    public static String toJsonString(IocFinding iocFinding) throws IOException {
        XContentBuilder builder = XContentFactory.jsonBuilder();
        builder = iocFinding.toXContent(builder, ToXContent.EMPTY_PARAMS);
        return BytesReference.bytes(builder).utf8ToString();
    }

    public static String toJsonString(ThreatIntelAlert alert) throws IOException {
        XContentBuilder builder = XContentFactory.jsonBuilder();
        builder = alert.toXContent(builder, ToXContent.EMPTY_PARAMS);
        return BytesReference.bytes(builder).utf8ToString();
    }

    public static String toJsonString(ThreatIntelFeedData threatIntelFeedData) throws IOException {
        XContentBuilder builder = XContentFactory.jsonBuilder();
        builder = threatIntelFeedData.toXContent(builder, ToXContent.EMPTY_PARAMS);
        return BytesReference.bytes(builder).utf8ToString();
    }

    public static User randomUser() {
        return new User(
                OpenSearchRestTestCase.randomAlphaOfLength(10),
                List.of(
                        OpenSearchRestTestCase.randomAlphaOfLength(10),
                        OpenSearchRestTestCase.randomAlphaOfLength(10)
                ),
                List.of(OpenSearchRestTestCase.randomAlphaOfLength(10), AccessRoles.ALL_ACCESS_ROLE),
                List.of("test_attr=test")
        );
    }

    public static User randomUserEmpty() {
        return new User(
                "",
                List.of(),
                List.of(),
                List.of()
        );
    }

    public static String randomDetectorType() {
        return "test_windows";
    }

    public static DetectorInput randomDetectorInput() {
        String description = OpenSearchRestTestCase.randomAlphaOfLength(randomInt(10));

        List<String> indices = new ArrayList<>();
        for (int i = 0; i < 10; ++i) {
            indices.add(OpenSearchRestTestCase.randomAlphaOfLength(10));
        }

        List<DetectorRule> detectorRules = new ArrayList<>();
        for (int i = 0; i < 10; ++i) {
            detectorRules.add(randomDetectorRule());
        }

        return new DetectorInput(description, indices, detectorRules, detectorRules);
    }

    public static DetectorRule randomDetectorRule() {
        String id = OpenSearchRestTestCase.randomAlphaOfLength(10);
        return new DetectorRule(id);
    }

    public static Action randomAction(String destinationId) {
        String name = OpenSearchRestTestCase.randomUnicodeOfLength(10);
        Script template = randomTemplateScript("Detector {{ctx.detector.name}} just entered alert status. Please investigate the issue.\n" +
                "  - Trigger: {{ctx.trigger.name}}\n" +
                "  - Severity: {{ctx.trigger.severity}}", null);
        Boolean throttleEnabled = false;
        Throttle throttle = randomThrottle(null, null);
        return new Action(name, destinationId, template, template, throttleEnabled, throttle, OpenSearchRestTestCase.randomAlphaOfLength(10), null);
    }

    public static Script randomTemplateScript(String source, Map<String, Object> params) {
        if (params == null) {
            params = new HashMap<>();
        }
        return new Script(ScriptType.INLINE, Script.DEFAULT_TEMPLATE_LANG, source, params);
    }

    public static Throttle randomThrottle(Integer value, ChronoUnit unit) {
        if (value == null) {
            value = RandomNumbers.randomIntBetween(LuceneTestCase.random(), 60, 120);
        }
        if (unit == null) {
            unit = ChronoUnit.MINUTES;
        }
        return new Throttle(value, unit);
    }

    public static String randomIndex() {
        return "windows";
    }

    public static String randomNetFlowDoc() {
        return "{" +
                "  \"netflow.event_data.SourceAddress\":\"10.50.221.10\"," +
                "  \"netflow.event_data.DestinationPort\":1234," +
                "  \"netflow.event_data.DestAddress\":\"10.53.111.14\"," +
                "  \"netflow.event_data.SourcePort\":4444" +
                "}";
    }

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
                "  timeframe: 20m\n" +
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
                "  \"time\": 1702952105000,\n" +
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

    private static String randomString() {
        return OpenSearchTestCase.randomAlphaOfLengthBetween(2, 16);
    }

    public static String randomLowerCaseString() {
        return randomString().toLowerCase(Locale.ROOT);
    }

    public static List<String> randomLowerCaseStringList() {
        List<String> stringList = new ArrayList<>();
        stringList.add(randomLowerCaseString());
        return stringList;
    }

    public static XContentParser parser(String xc) throws IOException {
        XContentParser parser = XContentType.JSON.xContent().createParser(xContentRegistry(), LoggingDeprecationHandler.INSTANCE, xc);
        parser.nextToken();
        return parser;
    }

    public static NamedXContentRegistry xContentRegistry() {
        return new NamedXContentRegistry(
                List.of(
                        Detector.XCONTENT_REGISTRY,
                        DetectorInput.XCONTENT_REGISTRY,
                        ThreatIntelFeedData.XCONTENT_REGISTRY
                )
        );
    }

    public static XContentBuilder builder() throws IOException {
        return XContentBuilder.builder(XContentType.JSON.xContent());
    }

    public static SATIFSourceConfigDto randomSATIFSourceConfigDto() {
        return randomSATIFSourceConfigDto(
                null,
                null,
                null,
                null,
                null,
                null,
                null,
                null,
                null,
                null,
                null,
                null,
                null,
                null,
                null,
                null
        );
    }

    public static SATIFSourceConfigDto randomSATIFSourceConfigDto(
            String feedName,
            String feedFormat,
            SourceConfigType sourceConfigType,
            User createdByUser,
            Instant createdAt,
            Source source,
            String description,
            Instant enabledTime,
            Instant lastUpdateTime,
            org.opensearch.jobscheduler.spi.schedule.IntervalSchedule schedule,
            TIFJobState state,
            RefreshType refreshType,
            Instant lastRefreshedTime,
            User lastRefreshedUser,
            Boolean isEnabled,
            List<String> iocTypes
    ) {
        if (feedName == null) {
            feedName = randomString();
        }
        if (feedFormat == null) {
            feedFormat = "STIX";
        }
        if (sourceConfigType == null) {
            sourceConfigType = SourceConfigType.S3_CUSTOM;
        }
        if (isEnabled == null) {
            isEnabled = true;
        }
        if (source == null) {
            source = new S3Source("bucket", "objectkey", "region", "rolearn");
        }
        if (schedule == null) {
            schedule = new org.opensearch.jobscheduler.spi.schedule.IntervalSchedule(Instant.now(), 1, ChronoUnit.DAYS);
        }
        if (iocTypes == null) {
            iocTypes = List.of("ip");
        }

        return new SATIFSourceConfigDto(
                null,
                null,
                feedName,
                feedFormat,
                sourceConfigType,
                description,
                createdByUser,
                createdAt,
                source,
                enabledTime,
                lastUpdateTime,
                schedule,
                state,
                refreshType,
                lastRefreshedTime,
                lastRefreshedUser,
                isEnabled,
                iocTypes,
                true
        );
    }

    public static SATIFSourceConfig randomSATIFSourceConfig() {
        return randomSATIFSourceConfig(
                null,
                null,
                null,
                null,
                null,
                null,
                null,
                null,
                null,
                null,
                null,
                null,
                null,
                null,
                null,
                null,
                null
        );
    }

    public static SATIFSourceConfig randomSATIFSourceConfig(
            String feedName,
            String feedFormat,
            SourceConfigType sourceConfigType,
            User createdByUser,
            Instant createdAt,
            Source source,
            String description,
            Instant enabledTime,
            Instant lastUpdateTime,
            org.opensearch.jobscheduler.spi.schedule.IntervalSchedule schedule,
            TIFJobState state,
            RefreshType refreshType,
            Instant lastRefreshedTime,
            User lastRefreshedUser,
            Boolean isEnabled,
            IocStoreConfig iocStoreConfig,
            List<String> iocTypes
    ) {
        if (feedName == null) {
            feedName = randomString();
        }
        if (feedFormat == null) {
            feedFormat = "STIX";
        }
        if (sourceConfigType == null) {
            sourceConfigType = SourceConfigType.S3_CUSTOM;
        }
        if (isEnabled == null) {
            isEnabled = true;
        }
        if (source == null) {
            source = new S3Source("bucket", "objectkey", "region", "rolearn");
        }
        if (schedule == null) {
            schedule = new org.opensearch.jobscheduler.spi.schedule.IntervalSchedule(Instant.now(), 1, ChronoUnit.DAYS);
        }
        if (iocStoreConfig == null) {
            iocStoreConfig = new DefaultIocStoreConfig(List.of(new DefaultIocStoreConfig.IocToIndexDetails(new IOCType(IOCType.DOMAIN_NAME_TYPE), "indexPattern", "writeIndex")));
        }
        if (iocTypes == null) {
            iocTypes = List.of("ip");
        }

        return new SATIFSourceConfig(
                null,
                null,
                feedName,
                feedFormat,
                sourceConfigType,
                description,
                new User("wrgrer", List.of("b1"), List.of("r1"), List.of("ca")),
                createdAt,
                source,
                enabledTime,
                lastUpdateTime,
                schedule,
                state,
                refreshType,
                lastRefreshedTime,
                lastRefreshedUser,
                isEnabled,
                iocStoreConfig,
                iocTypes,
                true
        );
    }
}
