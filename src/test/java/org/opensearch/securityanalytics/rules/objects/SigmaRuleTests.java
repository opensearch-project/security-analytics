/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.securityanalytics.rules.objects;

import org.junit.Assert;
import org.opensearch.securityanalytics.rules.condition.ConditionOR;
import org.opensearch.securityanalytics.rules.exceptions.*;
import org.opensearch.securityanalytics.rules.modifiers.SigmaContainsModifier;
import org.opensearch.securityanalytics.rules.modifiers.SigmaEndswithModifier;
import org.opensearch.securityanalytics.rules.types.SigmaNumber;
import org.opensearch.securityanalytics.rules.types.SigmaString;
import org.opensearch.securityanalytics.rules.utils.Either;
import org.opensearch.test.OpenSearchTestCase;

import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.*;

public class SigmaRuleTests extends OpenSearchTestCase {

    public void testSigmaRuleBadUuid() {
        Exception exception = assertThrows(SigmaIdentifierError.class, () -> {
            SigmaRule.fromDict(Collections.singletonMap("id", "no-uuid"), false);
        });

        String expectedMessage = "Sigma rule identifier must be an UUID";
        String actualMessage = exception.getMessage();

        assertTrue(actualMessage.contains(expectedMessage));
    }

    public void testSigmaRuleBadLevel() {
        Map<String, Object> sigmaRule = new HashMap<>();
        sigmaRule.put("id", java.util.UUID.randomUUID().toString());

        Exception exception = assertThrows(SigmaLevelError.class, () -> {
            SigmaRule.fromDict(sigmaRule, false);
        });

        String expectedMessage = "null is no valid Sigma rule level";
        String actualMessage = exception.getMessage();

        assertTrue(actualMessage.contains(expectedMessage));
    }

    public void testSigmaRuleBadStatus() {
        Map<String, Object> sigmaRule = new HashMap<>();
        sigmaRule.put("id", java.util.UUID.randomUUID().toString());
        sigmaRule.put("level", "critical");

        Exception exception = assertThrows(SigmaStatusError.class, () -> {
            SigmaRule.fromDict(sigmaRule, false);
        });

        String expectedMessage = "null is no valid Sigma rule status";
        String actualMessage = exception.getMessage();

        assertTrue(actualMessage.contains(expectedMessage));
    }

    public void testSigmaRuleBadDate() {
        Map<String, Object> sigmaRule = new HashMap<>();
        sigmaRule.put("id", java.util.UUID.randomUUID().toString());
        sigmaRule.put("level", "critical");
        sigmaRule.put("status", "experimental");
        sigmaRule.put("date", "15/05");

        assertThrows(SigmaDateError.class, () -> {
            SigmaRule.fromDict(sigmaRule, false);
        });
    }

    public void testSigmaRuleNoLogSource() {
        Map<String, Object> sigmaRule = new HashMap<>();
        sigmaRule.put("id", java.util.UUID.randomUUID().toString());
        sigmaRule.put("level", "critical");
        sigmaRule.put("status", "experimental");
        sigmaRule.put("date", "2017/05/15");

        Exception exception = assertThrows(SigmaLogsourceError.class, () -> {
            SigmaRule.fromDict(sigmaRule, false);
        });

        String expectedMessage = "Sigma rule must have a log source";
        String actualMessage = exception.getMessage();

        assertTrue(actualMessage.contains(expectedMessage));
    }

    public void testSigmaRuleNoDetections() {
        Map<String, Object> sigmaRule = new HashMap<>();
        sigmaRule.put("id", java.util.UUID.randomUUID().toString());
        sigmaRule.put("level", "critical");
        sigmaRule.put("status", "experimental");
        sigmaRule.put("date", "2017/05/15");

        Map<String, Object> logSource = new HashMap<>();
        logSource.put("product", "windows");
        sigmaRule.put("logsource", logSource);


        Exception exception = assertThrows(SigmaDetectionError.class, () -> {
            SigmaRule.fromDict(sigmaRule, false);
        });

        String expectedMessage = "Sigma rule must have a detection definitions";
        String actualMessage = exception.getMessage();

        assertTrue(actualMessage.contains(expectedMessage));
    }

    public void testSigmaRuleNoneToList() throws SigmaRegularExpressionError, SigmaValueError, SigmaModifierError, SigmaDetectionError, SigmaLogsourceError {
        SigmaLogSource logSource = new SigmaLogSource(null, "test", null);
        SigmaDetectionItem detectionItem = new SigmaDetectionItem("CommandLine", Arrays.asList(SigmaContainsModifier.class),
                List.of(new SigmaString("*test.exe*")), null, null, false);

        SigmaDetection detection = new SigmaDetection(Collections.singletonList(Either.left(detectionItem)),
                Either.right(ConditionOR.class));
        SigmaDetections detections = new SigmaDetections(Collections.singletonMap("selection", detection), Collections.singletonList("selection"));
        SigmaRule rule = new SigmaRule("Test", logSource, detections, null, null, null, null, null,
                null, null, null, null, null, null);

        Assert.assertEquals(0, rule.getReferences().size());
        Assert.assertEquals(0, rule.getFields().size());
        Assert.assertEquals(0, rule.getTags().size());
        Assert.assertEquals(0, rule.getFalsePositives().size());
    }

    public void testSigmaRuleFromYaml() throws SigmaError, ParseException {
        SigmaRule sigmaRuleFromYaml = SigmaRule.fromYaml(
                "title: QuarksPwDump Clearing Access History\n" +
                "id: 39f919f3-980b-4e6f-a975-8af7e507ef2b\n" +
                "status: experimental\n" +
                "description: Detects QuarksPwDump clearing access history in hive\n" +
                "author: Florian Roth\n" +
                "date: 2017/05/15\n" +
                "modified: 2019/11/13\n" +
                "tags:\n" +
                "    - attack.credential_access\n" +
                "    - attack.t1003          # an old one\n" +
                "    - attack.t1003.002\n" +
                "level: critical\n" +
                "logsource:\n" +
                "    product: windows\n" +
                "    service: system\n" +
                "detection:\n" +
                "    selection:\n" +
                "        EventID: 16\n" +
                "        HiveName|contains: '\\AppData\\Local\\Temp\\SAM'\n" +
                "        HiveName|endswith: '.dmp'\n" +
                "    condition: selection\n" +
                "falsepositives:\n" +
                "    - Unknown", true);

        SigmaRule expectedSigmaRule = sigmaRule();

        Assert.assertEquals(expectedSigmaRule.getTitle(), sigmaRuleFromYaml.getTitle());
        Assert.assertEquals(expectedSigmaRule.getLogSource().getProduct(), sigmaRuleFromYaml.getLogSource().getProduct());
        Assert.assertEquals(expectedSigmaRule.getLogSource().getService(), sigmaRuleFromYaml.getLogSource().getService());

        Assert.assertTrue(sigmaRuleFromYaml.getDetection().getDetections().containsKey("selection"));
        Assert.assertEquals(expectedSigmaRule.getDetection().getDetections().get("selection").getDetectionItems().size(),
                sigmaRuleFromYaml.getDetection().getDetections().get("selection").getDetectionItems().size());

        Assert.assertEquals(expectedSigmaRule.getId(), sigmaRuleFromYaml.getId());
        Assert.assertEquals(expectedSigmaRule.getStatus(), sigmaRuleFromYaml.getStatus());
        Assert.assertEquals(expectedSigmaRule.getDescription(), sigmaRuleFromYaml.getDescription());
        Assert.assertEquals(expectedSigmaRule.getReferences().size(), sigmaRuleFromYaml.getReferences().size());
        Assert.assertEquals(expectedSigmaRule.getTags().size(), sigmaRuleFromYaml.getTags().size());
        Assert.assertEquals(expectedSigmaRule.getAuthor(), sigmaRuleFromYaml.getAuthor());
        Assert.assertEquals(expectedSigmaRule.getDate(), sigmaRuleFromYaml.getDate());
        Assert.assertEquals(expectedSigmaRule.getFields().size(), sigmaRuleFromYaml.getFields().size());
        Assert.assertEquals(expectedSigmaRule.getFalsePositives().size(), sigmaRuleFromYaml.getFalsePositives().size());
        Assert.assertEquals(expectedSigmaRule.getLevel(), sigmaRuleFromYaml.getLevel());
        Assert.assertEquals(expectedSigmaRule.getErrors().size(), sigmaRuleFromYaml.getErrors().size());
    }

    public void testEmptyDetection() {
        Exception exception = assertThrows(SigmaDetectionError.class, () -> {
            new SigmaDetections(Collections.emptyMap(), Collections.emptyList());
        });

        String expectedMessage = "No detections defined in Sigma rule";
        String actualMessage = exception.getMessage();

        assertTrue(actualMessage.contains(expectedMessage));
    }

    private SigmaRule sigmaRule() throws SigmaRegularExpressionError, SigmaValueError, SigmaModifierError, SigmaDetectionError, ParseException, SigmaLogsourceError {
        SigmaLogSource logSource = new SigmaLogSource("windows", null, "system");

        SigmaDetectionItem detectionItem1 = new SigmaDetectionItem("EventID", Collections.emptyList(),
                List.of(new SigmaNumber(16)), null, null, false);
        SigmaDetectionItem detectionItem2 = new SigmaDetectionItem("HiveName", Collections.singletonList(SigmaContainsModifier.class),
                List.of(new SigmaString("\\AppData\\Local\\Temp\\SAM")), null, null, false);
        SigmaDetectionItem detectionItem4 = new SigmaDetectionItem("HiveName", Collections.singletonList(SigmaEndswithModifier.class),
                List.of(new SigmaString(".dmp")), null, null, false);

        SigmaDetection detection = new SigmaDetection(List.of(Either.left(detectionItem1), Either.left(detectionItem2), Either.left(detectionItem4)),
                Either.right(ConditionOR.class));
        SigmaDetections detections = new SigmaDetections(Collections.singletonMap("selection", detection), Collections.singletonList("selection"));

        SimpleDateFormat formatter = new SimpleDateFormat("yyyy/MM/dd", Locale.getDefault());
        Date ruleDate = formatter.parse("2017/05/15");

        return new SigmaRule("QuarksPwDump Clearing Access History", logSource, detections, UUID.fromString("39f919f3-980b-4e6f-a975-8af7e507ef2b"),
                SigmaStatus.EXPERIMENTAL, "Detects QuarksPwDump clearing access history in hive", Collections.emptyList(),
                List.of(new SigmaRuleTag("attack", "credential_access"), new SigmaRuleTag("attack", "t1003"),
                        new SigmaRuleTag("attack", "t1003.002")), "Florian Roth", ruleDate, Collections.emptyList(),
                List.of("Unknown"), SigmaLevel.CRITICAL, Collections.emptyList());
    }
}