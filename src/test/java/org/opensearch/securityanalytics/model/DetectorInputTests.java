/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.securityanalytics.model;

import org.junit.Assert;
import org.opensearch.common.bytes.BytesReference;
import org.opensearch.common.xcontent.XContentType;
import org.opensearch.core.xcontent.ToXContent;
import org.opensearch.core.xcontent.XContentBuilder;
import org.opensearch.test.OpenSearchTestCase;

import java.io.IOException;
import java.util.List;
import java.util.Map;

import static org.opensearch.securityanalytics.TestHelpers.randomDetectorInput;
import static org.opensearch.securityanalytics.TestHelpers.randomDetectorRule;

public class DetectorInputTests extends OpenSearchTestCase {

    public void testDetectorRuleAsTemplateArgs() {
        DetectorRule rule = randomDetectorRule();

        Map<String, Object> templateArgs = rule.asTemplateArg();

        Assert.assertEquals("Template args 'id' field does not match:", templateArgs.get(DetectorRule.RULE_ID_FIELD), rule.getId());
    }

    public void testDetectorInputAsTemplateArgs() throws IOException {
        DetectorInput input = randomDetectorInput();

        String inputString = BytesReference.bytes(input.toXContent(XContentBuilder.builder(XContentType.JSON.xContent()), ToXContent.EMPTY_PARAMS)).utf8ToString();

        Map<String, Object> templateArgs = input.asTemplateArg();

        Assert.assertEquals("Template args 'description' field does not match:",
                templateArgs.get(DetectorInput.DESCRIPTION_FIELD),
                input.getDescription());

        Assert.assertEquals("Template args 'indices' field does not match:",
                templateArgs.get(DetectorInput.INDICES_FIELD),
                input.getIndices());

        Assert.assertEquals("Template args 'rules' field does not contain the expected number of rules:",
                ((List<?>) templateArgs.get(DetectorInput.CUSTOM_RULES_FIELD)).size(),
                input.getCustomRules().size());

        input.getCustomRules().forEach(detectorRule -> Assert.assertTrue(((List<?>) templateArgs.get(DetectorInput.CUSTOM_RULES_FIELD)).contains(detectorRule.asTemplateArg())));
    }
}