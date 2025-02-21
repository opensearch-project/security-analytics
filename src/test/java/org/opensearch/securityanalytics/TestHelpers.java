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

    // TODO: not used, can we remove?
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

    public static Action randomThreatInteMonitorAction(String destinationId) {
        String name = OpenSearchRestTestCase.randomUnicodeOfLength(10);
        Script template = randomTemplateScript("Threat intel Monitor {{ctx.monitor.name}} just entered alert status. Please investigate the issue.\n" +
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

    private static String randomString() {
        return OpenSearchTestCase.randomAlphaOfLengthBetween(2, 16);
    }

    public static String randomLowerCaseString() {
        return randomString().toLowerCase(Locale.ROOT);
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
