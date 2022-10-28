/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.securityanalytics;

import com.carrotsearch.randomizedtesting.generators.RandomNumbers;
import org.apache.lucene.tests.util.LuceneTestCase;
import org.opensearch.common.bytes.BytesReference;
import org.opensearch.common.xcontent.LoggingDeprecationHandler;
import org.opensearch.common.xcontent.NamedXContentRegistry;
import org.opensearch.common.xcontent.ToXContent;
import org.opensearch.common.xcontent.XContentBuilder;
import org.opensearch.common.xcontent.XContentFactory;
import org.opensearch.common.xcontent.XContentParser;
import org.opensearch.common.xcontent.XContentType;
import org.opensearch.commons.alerting.model.IntervalSchedule;
import org.opensearch.commons.alerting.model.Schedule;
import org.opensearch.commons.alerting.model.action.Action;
import org.opensearch.commons.alerting.model.action.Throttle;
import org.opensearch.commons.authuser.User;
import org.opensearch.script.Script;
import org.opensearch.script.ScriptType;
import org.opensearch.securityanalytics.model.Detector;
import org.opensearch.securityanalytics.model.DetectorInput;
import org.opensearch.securityanalytics.model.DetectorRule;
import org.opensearch.securityanalytics.model.DetectorTrigger;
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
import java.util.function.Function;
import java.util.stream.Collectors;

import static org.opensearch.test.OpenSearchTestCase.randomInt;

public class TestHelpers {

    static class AccessRoles {
        static final String ALL_ACCESS_ROLE = "all_access";
    }

    public static Detector randomDetector(List<String> rules) {
        DetectorInput input = new DetectorInput("windows detector for security analytics", List.of("windows"), Collections.emptyList(),
                rules.stream().map(DetectorRule::new).collect(Collectors.toList()));
        return randomDetector(null, null, null, List.of(input), List.of(), null, null, null, null);
    }

    public static Detector randomDetectorWithInputs(List<DetectorInput> inputs) {
        return randomDetector(null, null, null, inputs, List.of(), null, null, null, null);
    }
    public static Detector randomDetectorWithTriggers(List<DetectorTrigger> triggers) {
        return randomDetector(null, null, null, List.of(), triggers, null, null, null, null);
    }
    public static Detector randomDetectorWithTriggers(List<String> rules, List<DetectorTrigger> triggers) {
        DetectorInput input = new DetectorInput("windows detector for security analytics", List.of("windows"), Collections.emptyList(),
                rules.stream().map(DetectorRule::new).collect(Collectors.toList()));
        return randomDetector(null, null, null, List.of(input), triggers, null, null, null, null);
    }

    public static Detector randomDetectorWithInputsAndTriggers(List<DetectorInput> inputs, List<DetectorTrigger> triggers) {
        return randomDetector(null, null, null, inputs, triggers, null, null, null, null);
    }

    public static Detector randomDetectorWithTriggers(List<String> rules, List<DetectorTrigger> triggers, Detector.DetectorType detectorType, DetectorInput input) {
        return randomDetector(null, detectorType, null, List.of(input), triggers, null, null, null, null);
    }

    public static Detector randomDetector(String name,
                                          Detector.DetectorType detectorType,
                                          User user,
                                          List<DetectorInput> inputs,
                                          List<DetectorTrigger> triggers,
                                          Schedule schedule,
                                          Boolean enabled,
                                          Instant enabledTime,
                                          Instant lastUpdateTime) {
        if (name == null) {
            name = OpenSearchRestTestCase.randomAlphaOfLength(10);
        }
        if (detectorType == null) {
            detectorType = Detector.DetectorType.valueOf(randomDetectorType().toUpperCase(Locale.ROOT));
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

            DetectorTrigger trigger = new DetectorTrigger(null, "windows-trigger", "1", List.of("windows"), List.of("QuarksPwDump Clearing Access History"), List.of("high"), List.of("T0008"), List.of());
            triggers.add(trigger);
        }
        return new Detector(null, null, name, enabled, schedule, lastUpdateTime, enabledTime, detectorType, user, inputs, triggers, Collections.singletonList(""), "", "", "", "", "", "");
    }

    public static Detector randomDetectorWithNoUser() {
        String name = OpenSearchRestTestCase.randomAlphaOfLength(10);
        Detector.DetectorType detectorType = Detector.DetectorType.valueOf(randomDetectorType().toUpperCase(Locale.ROOT));
        List<DetectorInput> inputs = Collections.emptyList();
        Schedule schedule = new IntervalSchedule(5, ChronoUnit.MINUTES, null);
        Boolean enabled = OpenSearchTestCase.randomBoolean();
        Instant enabledTime = enabled ? Instant.now().truncatedTo(ChronoUnit.MILLIS) : null;
        Instant lastUpdateTime = Instant.now().truncatedTo(ChronoUnit.MILLIS);

        return new Detector(null, null, name, enabled, schedule, lastUpdateTime, enabledTime, detectorType, null, inputs, Collections.emptyList(),Collections.singletonList(""), "", "", "", "", "", "");
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

    public static String toJsonStringWithUser(Detector detector) throws IOException {
        XContentBuilder builder = XContentFactory.jsonBuilder();
        builder = detector.toXContentWithUser(builder, ToXContent.EMPTY_PARAMS);
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
        return "windows";
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

    public static String windowsIndexMapping() {
        return "\"properties\": {\n" +
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
                "        \"type\": \"text\"\n" +
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
                "        \"type\": \"integer\"\n" +
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
                "      \"_0\": {\n" +
                "        \"type\": \"text\"\n" +
                "      },\n" +
                "      \"_1\": {\n" +
                "        \"type\": \"text\"\n" +
                "      },\n" +
                "      \"_10\": {\n" +
                "        \"type\": \"text\"\n" +
                "      },\n" +
                "      \"_100\": {\n" +
                "        \"type\": \"text\"\n" +
                "      },\n" +
                "      \"_101\": {\n" +
                "        \"type\": \"text\"\n" +
                "      },\n" +
                "      \"_102\": {\n" +
                "        \"type\": \"text\"\n" +
                "      },\n" +
                "      \"_103\": {\n" +
                "        \"type\": \"text\"\n" +
                "      },\n" +
                "      \"_104\": {\n" +
                "        \"type\": \"text\"\n" +
                "      },\n" +
                "      \"_105\": {\n" +
                "        \"type\": \"text\"\n" +
                "      },\n" +
                "      \"_106\": {\n" +
                "        \"type\": \"text\"\n" +
                "      },\n" +
                "      \"_107\": {\n" +
                "        \"type\": \"text\"\n" +
                "      },\n" +
                "      \"_108\": {\n" +
                "        \"type\": \"text\"\n" +
                "      },\n" +
                "      \"_109\": {\n" +
                "        \"type\": \"text\"\n" +
                "      },\n" +
                "      \"_11\": {\n" +
                "        \"type\": \"text\"\n" +
                "      },\n" +
                "      \"_110\": {\n" +
                "        \"type\": \"text\"\n" +
                "      },\n" +
                "      \"_111\": {\n" +
                "        \"type\": \"text\"\n" +
                "      },\n" +
                "      \"_112\": {\n" +
                "        \"type\": \"text\"\n" +
                "      },\n" +
                "      \"_113\": {\n" +
                "        \"type\": \"text\"\n" +
                "      },\n" +
                "      \"_114\": {\n" +
                "        \"type\": \"text\"\n" +
                "      },\n" +
                "      \"_115\": {\n" +
                "        \"type\": \"text\"\n" +
                "      },\n" +
                "      \"_116\": {\n" +
                "        \"type\": \"text\"\n" +
                "      },\n" +
                "      \"_117\": {\n" +
                "        \"type\": \"text\"\n" +
                "      },\n" +
                "      \"_118\": {\n" +
                "        \"type\": \"text\"\n" +
                "      },\n" +
                "      \"_119\": {\n" +
                "        \"type\": \"text\"\n" +
                "      },\n" +
                "      \"_12\": {\n" +
                "        \"type\": \"text\"\n" +
                "      },\n" +
                "      \"_120\": {\n" +
                "        \"type\": \"text\"\n" +
                "      },\n" +
                "      \"_121\": {\n" +
                "        \"type\": \"text\"\n" +
                "      },\n" +
                "      \"_122\": {\n" +
                "        \"type\": \"text\"\n" +
                "      },\n" +
                "      \"_123\": {\n" +
                "        \"type\": \"text\"\n" +
                "      },\n" +
                "      \"_124\": {\n" +
                "        \"type\": \"text\"\n" +
                "      },\n" +
                "      \"_13\": {\n" +
                "        \"type\": \"text\"\n" +
                "      },\n" +
                "      \"_14\": {\n" +
                "        \"type\": \"text\"\n" +
                "      },\n" +
                "      \"_15\": {\n" +
                "        \"type\": \"text\"\n" +
                "      },\n" +
                "      \"_16\": {\n" +
                "        \"type\": \"text\"\n" +
                "      },\n" +
                "      \"_17\": {\n" +
                "        \"type\": \"text\"\n" +
                "      },\n" +
                "      \"_18\": {\n" +
                "        \"type\": \"text\"\n" +
                "      },\n" +
                "      \"_19\": {\n" +
                "        \"type\": \"text\"\n" +
                "      },\n" +
                "      \"_2\": {\n" +
                "        \"type\": \"text\"\n" +
                "      },\n" +
                "      \"_20\": {\n" +
                "        \"type\": \"text\"\n" +
                "      },\n" +
                "      \"_21\": {\n" +
                "        \"type\": \"text\"\n" +
                "      },\n" +
                "      \"_22\": {\n" +
                "        \"type\": \"text\"\n" +
                "      },\n" +
                "      \"_23\": {\n" +
                "        \"type\": \"text\"\n" +
                "      },\n" +
                "      \"_24\": {\n" +
                "        \"type\": \"text\"\n" +
                "      },\n" +
                "      \"_25\": {\n" +
                "        \"type\": \"text\"\n" +
                "      },\n" +
                "      \"_26\": {\n" +
                "        \"type\": \"text\"\n" +
                "      },\n" +
                "      \"_27\": {\n" +
                "        \"type\": \"text\"\n" +
                "      },\n" +
                "      \"_28\": {\n" +
                "        \"type\": \"text\"\n" +
                "      },\n" +
                "      \"_29\": {\n" +
                "        \"type\": \"text\"\n" +
                "      },\n" +
                "      \"_3\": {\n" +
                "        \"type\": \"text\"\n" +
                "      },\n" +
                "      \"_30\": {\n" +
                "        \"type\": \"text\"\n" +
                "      },\n" +
                "      \"_31\": {\n" +
                "        \"type\": \"text\"\n" +
                "      },\n" +
                "      \"_32\": {\n" +
                "        \"type\": \"text\"\n" +
                "      },\n" +
                "      \"_33\": {\n" +
                "        \"type\": \"text\"\n" +
                "      },\n" +
                "      \"_34\": {\n" +
                "        \"type\": \"text\"\n" +
                "      },\n" +
                "      \"_35\": {\n" +
                "        \"type\": \"text\"\n" +
                "      },\n" +
                "      \"_36\": {\n" +
                "        \"type\": \"text\"\n" +
                "      },\n" +
                "      \"_37\": {\n" +
                "        \"type\": \"text\"\n" +
                "      },\n" +
                "      \"_38\": {\n" +
                "        \"type\": \"text\"\n" +
                "      },\n" +
                "      \"_39\": {\n" +
                "        \"type\": \"text\"\n" +
                "      },\n" +
                "      \"_4\": {\n" +
                "        \"type\": \"text\"\n" +
                "      },\n" +
                "      \"_40\": {\n" +
                "        \"type\": \"text\"\n" +
                "      },\n" +
                "      \"_41\": {\n" +
                "        \"type\": \"text\"\n" +
                "      },\n" +
                "      \"_42\": {\n" +
                "        \"type\": \"text\"\n" +
                "      },\n" +
                "      \"_43\": {\n" +
                "        \"type\": \"text\"\n" +
                "      },\n" +
                "      \"_44\": {\n" +
                "        \"type\": \"text\"\n" +
                "      },\n" +
                "      \"_45\": {\n" +
                "        \"type\": \"text\"\n" +
                "      },\n" +
                "      \"_46\": {\n" +
                "        \"type\": \"text\"\n" +
                "      },\n" +
                "      \"_47\": {\n" +
                "        \"type\": \"text\"\n" +
                "      },\n" +
                "      \"_48\": {\n" +
                "        \"type\": \"text\"\n" +
                "      },\n" +
                "      \"_49\": {\n" +
                "        \"type\": \"text\"\n" +
                "      },\n" +
                "      \"_5\": {\n" +
                "        \"type\": \"text\"\n" +
                "      },\n" +
                "      \"_50\": {\n" +
                "        \"type\": \"text\"\n" +
                "      },\n" +
                "      \"_51\": {\n" +
                "        \"type\": \"text\"\n" +
                "      },\n" +
                "      \"_52\": {\n" +
                "        \"type\": \"text\"\n" +
                "      },\n" +
                "      \"_53\": {\n" +
                "        \"type\": \"text\"\n" +
                "      },\n" +
                "      \"_54\": {\n" +
                "        \"type\": \"text\"\n" +
                "      },\n" +
                "      \"_55\": {\n" +
                "        \"type\": \"text\"\n" +
                "      },\n" +
                "      \"_56\": {\n" +
                "        \"type\": \"text\"\n" +
                "      },\n" +
                "      \"_57\": {\n" +
                "        \"type\": \"text\"\n" +
                "      },\n" +
                "      \"_58\": {\n" +
                "        \"type\": \"text\"\n" +
                "      },\n" +
                "      \"_59\": {\n" +
                "        \"type\": \"text\"\n" +
                "      },\n" +
                "      \"_6\": {\n" +
                "        \"type\": \"text\"\n" +
                "      },\n" +
                "      \"_60\": {\n" +
                "        \"type\": \"text\"\n" +
                "      },\n" +
                "      \"_61\": {\n" +
                "        \"type\": \"text\"\n" +
                "      },\n" +
                "      \"_62\": {\n" +
                "        \"type\": \"text\"\n" +
                "      },\n" +
                "      \"_63\": {\n" +
                "        \"type\": \"text\"\n" +
                "      },\n" +
                "      \"_64\": {\n" +
                "        \"type\": \"text\"\n" +
                "      },\n" +
                "      \"_65\": {\n" +
                "        \"type\": \"text\"\n" +
                "      },\n" +
                "      \"_66\": {\n" +
                "        \"type\": \"text\"\n" +
                "      },\n" +
                "      \"_67\": {\n" +
                "        \"type\": \"text\"\n" +
                "      },\n" +
                "      \"_68\": {\n" +
                "        \"type\": \"text\"\n" +
                "      },\n" +
                "      \"_69\": {\n" +
                "        \"type\": \"text\"\n" +
                "      },\n" +
                "      \"_7\": {\n" +
                "        \"type\": \"text\"\n" +
                "      },\n" +
                "      \"_70\": {\n" +
                "        \"type\": \"text\"\n" +
                "      },\n" +
                "      \"_71\": {\n" +
                "        \"type\": \"text\"\n" +
                "      },\n" +
                "      \"_72\": {\n" +
                "        \"type\": \"text\"\n" +
                "      },\n" +
                "      \"_73\": {\n" +
                "        \"type\": \"text\"\n" +
                "      },\n" +
                "      \"_74\": {\n" +
                "        \"type\": \"text\"\n" +
                "      },\n" +
                "      \"_75\": {\n" +
                "        \"type\": \"text\"\n" +
                "      },\n" +
                "      \"_76\": {\n" +
                "        \"type\": \"text\"\n" +
                "      },\n" +
                "      \"_77\": {\n" +
                "        \"type\": \"text\"\n" +
                "      },\n" +
                "      \"_78\": {\n" +
                "        \"type\": \"text\"\n" +
                "      },\n" +
                "      \"_79\": {\n" +
                "        \"type\": \"text\"\n" +
                "      },\n" +
                "      \"_8\": {\n" +
                "        \"type\": \"text\"\n" +
                "      },\n" +
                "      \"_80\": {\n" +
                "        \"type\": \"text\"\n" +
                "      },\n" +
                "      \"_81\": {\n" +
                "        \"type\": \"text\"\n" +
                "      },\n" +
                "      \"_82\": {\n" +
                "        \"type\": \"text\"\n" +
                "      },\n" +
                "      \"_83\": {\n" +
                "        \"type\": \"text\"\n" +
                "      },\n" +
                "      \"_84\": {\n" +
                "        \"type\": \"text\"\n" +
                "      },\n" +
                "      \"_85\": {\n" +
                "        \"type\": \"text\"\n" +
                "      },\n" +
                "      \"_86\": {\n" +
                "        \"type\": \"text\"\n" +
                "      },\n" +
                "      \"_87\": {\n" +
                "        \"type\": \"text\"\n" +
                "      },\n" +
                "      \"_88\": {\n" +
                "        \"type\": \"text\"\n" +
                "      },\n" +
                "      \"_89\": {\n" +
                "        \"type\": \"text\"\n" +
                "      },\n" +
                "      \"_9\": {\n" +
                "        \"type\": \"text\"\n" +
                "      },\n" +
                "      \"_90\": {\n" +
                "        \"type\": \"text\"\n" +
                "      },\n" +
                "      \"_91\": {\n" +
                "        \"type\": \"text\"\n" +
                "      },\n" +
                "      \"_92\": {\n" +
                "        \"type\": \"text\"\n" +
                "      },\n" +
                "      \"_93\": {\n" +
                "        \"type\": \"text\"\n" +
                "      },\n" +
                "      \"_94\": {\n" +
                "        \"type\": \"text\"\n" +
                "      },\n" +
                "      \"_95\": {\n" +
                "        \"type\": \"text\"\n" +
                "      },\n" +
                "      \"_96\": {\n" +
                "        \"type\": \"text\"\n" +
                "      },\n" +
                "      \"_97\": {\n" +
                "        \"type\": \"text\"\n" +
                "      },\n" +
                "      \"_98\": {\n" +
                "        \"type\": \"text\"\n" +
                "      },\n" +
                "      \"_99\": {\n" +
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

    public static String randomDoc() {
        return "{\n" +
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

    public static XContentParser parser(String xc) throws IOException {
        XContentParser parser = XContentType.JSON.xContent().createParser(xContentRegistry(), LoggingDeprecationHandler.INSTANCE, xc);
        parser.nextToken();
        return parser;
    }

    public static NamedXContentRegistry xContentRegistry() {
        return new NamedXContentRegistry(
                List.of(
                        Detector.XCONTENT_REGISTRY,
                        DetectorInput.XCONTENT_REGISTRY
                )
        );
    }

    public static XContentBuilder builder() throws IOException {
        return XContentBuilder.builder(XContentType.JSON.xContent());
    }
}