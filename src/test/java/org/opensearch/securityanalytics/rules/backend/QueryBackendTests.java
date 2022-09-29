/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.securityanalytics.rules.backend;

import org.junit.Assert;
import org.opensearch.securityanalytics.rules.exceptions.SigmaError;
import org.opensearch.securityanalytics.rules.exceptions.SigmaIdentifierError;
import org.opensearch.securityanalytics.rules.exceptions.SigmaTypeError;
import org.opensearch.securityanalytics.rules.exceptions.SigmaValueError;
import org.opensearch.securityanalytics.rules.objects.SigmaRule;
import org.opensearch.test.OpenSearchTestCase;

import java.io.IOException;
import java.util.Collections;
import java.util.List;

public class QueryBackendTests extends OpenSearchTestCase {

    public void testBackendPipeline() throws IOException, SigmaError {
        OSQueryBackend queryBackend = testBackend();
        List<Object> queries = queryBackend.convertRule(SigmaRule.fromYaml(
                "            title: Test\n" +
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
                "                condition: sel", false));
        Assert.assertEquals("(fieldA: \"valueA\") AND (mappedB: \"valueB\") AND (fieldC: \"valueC\")", queries.get(0).toString());
    }

    public void testBackendAndCustomPipeline() throws IOException, SigmaError {
        OSQueryBackend queryBackend = testBackend();
        List<Object> queries = queryBackend.convertRule(SigmaRule.fromYaml(
                "            title: Test\n" +
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
                "                    fieldA1: valueA\n" +
                "                    fieldB1: valueB\n" +
                "                    fieldC1: valueC\n" +
                "                condition: sel", false));
        Assert.assertEquals("(mappedA: \"valueA\") AND (fieldB1: \"valueB\") AND (fieldC1: \"valueC\")", queries.get(0).toString());
    }

    public void testConvertValueStr() throws IOException, SigmaError {
        OSQueryBackend queryBackend = testBackend();
        List<Object> queries = queryBackend.convertRule(SigmaRule.fromYaml(
                "            title: Test\n" +
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
                "                    fieldA1: value\n" +
                "                condition: sel", false));
        Assert.assertEquals("mappedA: \"value\"", queries.get(0).toString());
    }

    public void testConvertValueStrStartsWith() throws IOException, SigmaError {
        OSQueryBackend queryBackend = testBackend();
        List<Object> queries = queryBackend.convertRule(SigmaRule.fromYaml(
                "            title: Test\n" +
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
                "                    fieldA1|startswith: \"value\"\n" +
                "                condition: sel", false));
        Assert.assertEquals("mappedA: value*", queries.get(0).toString());
    }

    public void testConvertValueStrStartsWithFurtherWildcard() throws IOException, SigmaError {
        OSQueryBackend queryBackend = testBackend();
        List<Object> queries = queryBackend.convertRule(SigmaRule.fromYaml(
                "            title: Test\n" +
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
                "                    fieldA1|startswith: \"va*lue\"\n" +
                "                condition: sel", false));
        Assert.assertEquals("mappedA: va*lue*", queries.get(0).toString());
    }

    public void testConvertValueStrEndsWith() throws IOException, SigmaError {
        OSQueryBackend queryBackend = testBackend();
        List<Object> queries = queryBackend.convertRule(SigmaRule.fromYaml(
                "            title: Test\n" +
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
                "                    fieldA1|endswith: \"value\"\n" +
                "                condition: sel", false));
        Assert.assertEquals("mappedA: *value", queries.get(0).toString());
    }

    public void testConvertValueStrEndsWithFurtherWildcard() throws IOException, SigmaError {
        OSQueryBackend queryBackend = testBackend();
        List<Object> queries = queryBackend.convertRule(SigmaRule.fromYaml(
                "            title: Test\n" +
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
                "                    fieldA1|endswith: \"va*lue\"\n" +
                "                condition: sel", false));
        Assert.assertEquals("mappedA: *va*lue", queries.get(0).toString());
    }

    public void testConvertValueStrContains() throws IOException, SigmaError {
        OSQueryBackend queryBackend = testBackend();
        List<Object> queries = queryBackend.convertRule(SigmaRule.fromYaml(
                "            title: Test\n" +
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
                        "                    fieldA1|contains: \"value\"\n" +
                        "                condition: sel", false));
        Assert.assertEquals("mappedA: *value*", queries.get(0).toString());
    }

    public void testConvertValueStrContainsFurtherWildcard() throws IOException, SigmaError {
        OSQueryBackend queryBackend = testBackend();
        List<Object> queries = queryBackend.convertRule(SigmaRule.fromYaml(
                "            title: Test\n" +
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
                        "                    fieldA1|contains: \"va*lue\"\n" +
                        "                condition: sel", false));
        Assert.assertEquals("mappedA: *va*lue*", queries.get(0).toString());
    }

    public void testConvertValueExpansionWithAll() throws IOException, SigmaError {
        OSQueryBackend queryBackend = testBackend();
        List<Object> queries = queryBackend.convertRule(SigmaRule.fromYaml(
                "            title: Test\n" +
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
                "                    CommandLine|windash|contains|all:\n" +
                "                    - -foo\n" +
                "                    - -bar\n" +
                "                condition: sel", false));
        Assert.assertEquals("((CommandLine: *\\-foo*) OR (CommandLine: *\\/foo*)) AND ((CommandLine: *\\-bar*) OR (CommandLine: *\\/bar*))", queries.get(0).toString());
    }

    public void testConvertValueNum() throws IOException, SigmaError {
        OSQueryBackend queryBackend = testBackend();
        List<Object> queries = queryBackend.convertRule(SigmaRule.fromYaml(
                "            title: Test\n" +
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
                "                    fieldA1: 123\n" +
                "                condition: sel", false));
        Assert.assertEquals("mappedA: 123", queries.get(0).toString());
    }

    public void testConvertValueBool() throws IOException, SigmaError {
        OSQueryBackend queryBackend = testBackend();
        List<Object> queries = queryBackend.convertRule(SigmaRule.fromYaml(
                "            title: Test\n" +
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
                "                    fieldA1: true\n" +
                "                    fieldB1: false\n" +
                "                condition: sel", false));
        Assert.assertEquals("(mappedA: true) AND (fieldB1: false)", queries.get(0).toString());
    }

    public void testConvertValueNull() throws IOException, SigmaError {
        OSQueryBackend queryBackend = testBackend();
        List<Object> queries = queryBackend.convertRule(SigmaRule.fromYaml(
                "            title: Test\n" +
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
                "                    fieldA1: null\n" +
                "                condition: sel", false));
        Assert.assertEquals("mappedA: null", queries.get(0).toString());
    }

    public void testConvertValueRegex() throws IOException, SigmaError {
        OSQueryBackend queryBackend = testBackend();
        List<Object> queries = queryBackend.convertRule(SigmaRule.fromYaml(
                "            title: Test\n" +
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
                "                    fieldA1|re: pat.*tern\"foo\"bar\n" +
                "                condition: sel", false));
        Assert.assertEquals("mappedA: /pat.*tern\\\"foo\\\"bar/", queries.get(0).toString());
    }

    public void testConvertValueRegexUnbound() throws IOException, SigmaError {
        OSQueryBackend queryBackend = testBackend();
        List<Object> queries = queryBackend.convertRule(SigmaRule.fromYaml(
                "            title: Test\n" +
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
                "                    \"|re\": pat.*tern\"foo\"bar\n" +
                "                condition: sel", false));
        Assert.assertEquals("_0: /pat.*tern\\\"foo\\\"bar/", queries.get(0).toString());
    }

    public void testConvertValueCidrWildcardNone() throws IOException, SigmaError {
        OSQueryBackend queryBackend = testBackend();
        List<Object> queries = queryBackend.convertRule(SigmaRule.fromYaml(
                "            title: Test\n" +
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
                "                    fieldA1|cidr: 192.168.0.0/14\n" +
                "                condition: sel", false));
        Assert.assertEquals("mappedA: \"192.168.0.0/14\"", queries.get(0).toString());
    }

    public void testConvertCompare() throws IOException, SigmaError {
        OSQueryBackend queryBackend = testBackend();
        List<Object> queries = queryBackend.convertRule(SigmaRule.fromYaml(
                "            title: Test\n" +
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
                "                    fieldA|lt: 123\n" +
                "                    fieldB|lte: 123\n" +
                "                    fieldC|gt: 123\n" +
                "                    fieldD|gte: 123\n" +
                "                condition: sel", false));
        Assert.assertEquals("(\"fieldA\" \"lt\" 123) AND (\"mappedB\" \"lte\" 123) AND (\"fieldC\" \"gt\" 123) AND (\"fieldD\" \"gte\" 123)", queries.get(0).toString());
    }

    public void testConvertCompareStr() throws IOException {
        OSQueryBackend queryBackend = testBackend();
        assertThrows(SigmaTypeError.class, () -> {
            queryBackend.convertRule(SigmaRule.fromYaml(
                    "            title: Test\n" +
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
                    "                    fieldA|lt: test\n" +
                    "                condition: sel", false));
        });}

    public void testConvertOrInList() throws IOException, SigmaError {
        OSQueryBackend queryBackend = testBackend();
        List<Object> queries = queryBackend.convertRule(SigmaRule.fromYaml(
                "            title: Test\n" +
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
                "                    fieldA1: \n" +
                "                        - value1\n" +
                "                        - value2\n" +
                "                        - value4\n" +
                "                condition: sel", false));
        Assert.assertEquals("(mappedA: \"value1\") OR (mappedA: \"value2\") OR (mappedA: \"value4\")", queries.get(0).toString());
    }

    public void testConvertOrInListWithWildcards() throws IOException, SigmaError {
        OSQueryBackend queryBackend = testBackend();
        List<Object> queries = queryBackend.convertRule(SigmaRule.fromYaml(
                "            title: Test\n" +
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
                "                    fieldA1: \n" +
                "                        - value1\n" +
                "                        - value2*\n" +
                "                        - val*ue3\n" +
                "                condition: sel", false));
        Assert.assertEquals("(mappedA: \"value1\") OR (mappedA: value2*) OR (mappedA: val*ue3)", queries.get(0).toString());
    }

    public void testConvertOrInSeparate() throws IOException, SigmaError {
        OSQueryBackend queryBackend = testBackend();
        List<Object> queries = queryBackend.convertRule(SigmaRule.fromYaml(
                "            title: Test\n" +
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
                "                sel1:\n" +
                "                    fieldA1: value1\n" +
                "                sel2:\n" +
                "                    fieldA1: value2\n" +
                "                sel3:\n" +
                "                    fieldA1: value4\n" +
                "                condition: sel1 or sel2 or sel3", false));
        Assert.assertEquals("((mappedA: \"value1\") OR (mappedA: \"value2\")) OR (mappedA: \"value4\")", queries.get(0).toString());
    }

    public void testConvertOrInMixedKeywordField() throws IOException, SigmaError {
        OSQueryBackend queryBackend = testBackend();
        List<Object> queries = queryBackend.convertRule(SigmaRule.fromYaml(
                "            title: Test\n" +
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
                "                sel1:\n" +
                "                    fieldA: value1\n" +
                "                sel2:\n" +
                "                    fieldB: value2\n" +
                "                sel3: value3\n" +
                "                condition: sel1 or sel2 or sel3", false));
        Assert.assertEquals("((fieldA: \"value1\") OR (mappedB: \"value2\")) OR (_0: \"value3\")", queries.get(0).toString());
    }

    public void testConvertOrInMixedFields() throws IOException, SigmaError {
        OSQueryBackend queryBackend = testBackend();
        List<Object> queries = queryBackend.convertRule(SigmaRule.fromYaml(
                "            title: Test\n" +
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
                "                sel1:\n" +
                "                    fieldA1: value1\n" +
                "                sel2:\n" +
                "                    fieldB1: value2\n" +
                "                sel3:\n" +
                "                    fieldA1: value4\n" +
                "                condition: sel1 or sel2 or sel3", false));
        Assert.assertEquals("((mappedA: \"value1\") OR (fieldB1: \"value2\")) OR (mappedA: \"value4\")", queries.get(0).toString());
    }

    public void testConvertOrInUnallowedValueType() throws IOException, SigmaError {
        OSQueryBackend queryBackend = testBackend();
        List<Object> queries = queryBackend.convertRule(SigmaRule.fromYaml(
                "            title: Test\n" +
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
                "                    fieldA1: \n" +
                "                        - value1\n" +
                "                        - value2\n" +
                "                        - null\n" +
                "                condition: sel", false));
        Assert.assertEquals("(mappedA: \"value1\") OR (mappedA: \"value2\") OR (mappedA: null)", queries.get(0).toString());
    }

    public void testConvertOrInListNumbers() throws IOException, SigmaError {
        OSQueryBackend queryBackend = testBackend();
        List<Object> queries = queryBackend.convertRule(SigmaRule.fromYaml(
                "            title: Test\n" +
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
                "                    fieldA1: \n" +
                "                        - 1\n" +
                "                        - 2\n" +
                "                        - 4\n" +
                "                condition: sel", false));
        Assert.assertEquals("(mappedA: 1) OR (mappedA: 2) OR (mappedA: 4)", queries.get(0).toString());
    }

    public void testConvertAndInList() throws IOException, SigmaError {
        OSQueryBackend queryBackend = testBackend();
        List<Object> queries = queryBackend.convertRule(SigmaRule.fromYaml(
                "            title: Test\n" +
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
                "                    fieldA1|all:\n" +
                "                        - value1\n" +
                "                        - value2\n" +
                "                        - value4\n" +
                "                condition: sel", false));
        Assert.assertEquals("(mappedA: \"value1\") AND (mappedA: \"value2\") AND (mappedA: \"value4\")", queries.get(0).toString());
    }

    public void testConvertUnboundValues() throws IOException, SigmaError {
        OSQueryBackend queryBackend = testBackend();
        List<Object> queries = queryBackend.convertRule(SigmaRule.fromYaml(
                "            title: Test\n" +
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
            "                        - value1\n" +
            "                        - value2\n" +
            "                        - 4\n" +
                "                condition: sel", false));
        Assert.assertEquals("(_0: \"value1\") OR (_1: \"value2\") OR (_2: 4)", queries.get(0).toString());
    }

    public void testConvertInvalidUnboundBool() throws IOException {
        OSQueryBackend queryBackend = testBackend();
        Exception exception = assertThrows(SigmaValueError.class, () -> {
            queryBackend.convertRule(SigmaRule.fromYaml(
                    "            title: Test\n" +
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
                    "                sel: true\n" +
                    "                condition: sel", false));
        });

        String expectedMessage = "Unexpected Values";
        String actualMessage = exception.getMessage();

        assertTrue(actualMessage.contains(expectedMessage));
    }

    public void testConvertInvalidCidr() throws IOException {
        OSQueryBackend queryBackend = testBackend();
        Exception exception = assertThrows(SigmaValueError.class, () -> {
            queryBackend.convertRule(SigmaRule.fromYaml(
                    "            title: Test\n" +
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
                    "                sel: \n" +
                    "                \"|cidr\": 192.168.0/16\n" +
                    "                condition: sel", false));
        });

        String expectedMessage = "Unexpected Values";
        String actualMessage = exception.getMessage();

        assertTrue(actualMessage.contains(expectedMessage));
    }

    public void testConvertAnd() throws IOException, SigmaError {
        OSQueryBackend queryBackend = testBackend();
        List<Object> queries = queryBackend.convertRule(SigmaRule.fromYaml(
                "            title: Test\n" +
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
                "                sel1:\n" +
                "                    fieldA: value1\n" +
                "                sel2:\n" +
                "                    fieldC: value2\n" +
                "                condition: sel1 and sel2", false));
        Assert.assertEquals("(fieldA: \"value1\") AND (fieldC: \"value2\")", queries.get(0).toString());
    }

    public void testConvertOr() throws IOException, SigmaError {
        OSQueryBackend queryBackend = testBackend();
        List<Object> queries = queryBackend.convertRule(SigmaRule.fromYaml(
                "            title: Test\n" +
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
                "                sel1:\n" +
                "                    fieldA: value1\n" +
                "                sel2:\n" +
                "                    fieldC: value2\n" +
                "                condition: sel1 or sel2", false));
        Assert.assertEquals("(fieldA: \"value1\") OR (fieldC: \"value2\")", queries.get(0).toString());
    }

    public void testConvertNot() throws IOException, SigmaError {
        OSQueryBackend queryBackend = testBackend();
        List<Object> queries = queryBackend.convertRule(SigmaRule.fromYaml(
                "            title: Test\n" +
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
                "                    fieldA: value1\n" +
                "                condition: not sel", false));
        Assert.assertEquals("(NOT fieldA: \"value1\")", queries.get(0).toString());
    }

    public void testConvertPrecedence() throws IOException, SigmaError {
        OSQueryBackend queryBackend = testBackend();
        List<Object> queries = queryBackend.convertRule(SigmaRule.fromYaml(
                "            title: Test\n" +
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
                "                sel1:\n" +
                "                    fieldA: value1\n" +
                "                sel2:\n" +
                "                    fieldB: value2\n" +
                "                sel3:\n" +
                "                    fieldC: value4\n" +
                "                sel4:\n" +
                "                    fieldD: value5\n" +
                "                condition: (sel1 or sel2) and not (sel3 and sel4)", false));
        Assert.assertEquals("((fieldA: \"value1\") OR (mappedB: \"value2\")) AND ((NOT ((fieldC: \"value4\") AND (fieldD: \"value5\"))))", queries.get(0).toString());
    }

    public void testConvertMultiConditions() throws IOException, SigmaError {
        OSQueryBackend queryBackend = testBackend();
        List<Object> queries = queryBackend.convertRule(SigmaRule.fromYaml(
                "            title: Test\n" +
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
                "                sel1:\n" +
                "                    fieldA: value1\n" +
                "                sel2:\n" +
                "                    fieldC: value2\n" +
                "                condition:\n" +
                "                    - sel1\n" +
                "                    - sel2", false));
        Assert.assertEquals("fieldA: \"value1\"", queries.get(0).toString());
        Assert.assertEquals("fieldC: \"value2\"", queries.get(1).toString());
    }

    public void testConvertListCidrWildcardNone() throws IOException, SigmaError {
        OSQueryBackend queryBackend = testBackend();
        List<Object> queries = queryBackend.convertRule(SigmaRule.fromYaml(
                "            title: Test\n" +
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
                        "                sel: \n" +
                        "                    fieldA|cidr:\n" +
                        "                        - 192.168.0.0/14\n" +
                        "                        - 10.10.10.0/24\n" +
                        "                condition: sel", false));
        Assert.assertEquals("(fieldA: \"192.168.0.0/14\") OR (fieldA: \"10.10.10.0/24\")", queries.get(0).toString());
    }

    public void testConvertNetworkRule() throws IOException, SigmaError {
        OSQueryBackend queryBackend = testBackend();
        List<Object> queries = queryBackend.convertRule(SigmaRule.fromYaml(
                "            title: Test\n" +
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
                "                selection_webdav:\n" +
                "                    - c-useragent|contains: 'WebDAV'\n" +
                "                    - c-uri|contains: 'webdav'\n" +
                "                selection_executable:\n" +
                "                    - resp_mime_types|contains: 'dosexec'\n" +
                "                    - c-uri|endswith: '.exe'\n" +
                "                condition: selection_webdav and selection_executable", false));
        Assert.assertEquals("((c-useragent: *WebDAV*) OR (c-uri: *webdav*)) AND ((resp_mime_types: *dosexec*) OR (c-uri: *.exe))", queries.get(0).toString());
    }

    public void testConvertRegexpRule() throws IOException, SigmaError {
        OSQueryBackend queryBackend = testBackend();
        List<Object> queries = queryBackend.convertRule(SigmaRule.fromYaml(
                "            title: Test\n" +
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
                "                select_file_with_asterisk:\n" +
                "                    Image: '/usr/bin/file'\n" +
                "                    CommandLine|re: '(.){200,}' # execution of the 'file */* *>> /tmp/output.txt' will produce huge commandline\n" +
                "                select_recursive_ls:\n" +
                "                    Image: '/bin/ls'\n" +
                "                    CommandLine|contains: '-R'\n" +
                "                select_find_execution:\n" +
                "                    Image: '/usr/bin/find'\n" +
                "                select_mdfind_execution:\n" +
                "                    Image: '/usr/bin/mdfind'\n" +
                "                select_tree_execution|endswith:\n" +
                "                    Image: '/tree'\n" +
                "                condition: 1 of select*", false));
        Assert.assertEquals("(Image: \"\\/usr\\/bin\\/find\") OR (Image: \"\\/tree\") OR (Image: \"\\/usr\\/bin\\/mdfind\") OR ((Image: \"\\/usr\\/bin\\/file\") AND (CommandLine: /(.){200,}/)) OR ((Image: \"\\/bin\\/ls\") AND (CommandLine: *\\-R*))", queries.get(0).toString());
    }

    public void testConvertProxyRule() throws IOException, SigmaError {
        OSQueryBackend queryBackend = testBackend();
        List<Object> queries = queryBackend.convertRule(SigmaRule.fromYaml("title: Bitsadmin to Uncommon TLD\n" +
                "id: 9eb68894-7476-4cd6-8752-23b51f5883a7\n" +
                "status: experimental\n" +
                "description: Detects Bitsadmin connections to domains with uncommon TLDs - https://twitter.com/jhencinski/status/1102695118455349248 - https://isc.sans.edu/forums/diary/Investigating+Microsoft+BITS+Activity/23281/\n" +
                "author: Florian Roth, Tim Shelton\n" +
                "date: 2019/03/07\n" +
                "modified: 2022/05/09\n" +
                "logsource:\n" +
                "    category: proxy\n" +
                "detection:\n" +
                "    selection:\n" +
                "        c-useragent|startswith: 'Microsoft BITS/'\n" +
                "    falsepositives:\n" +
                "        r-dns|endswith:\n" +
                "            - '.com' \n" +
                "            - '.net' \n" +
                "            - '.org' \n" +
                "            - '.scdn.co' # spotify streaming\n" +
                "    condition: selection and not falsepositives\n" +
                "fields:\n" +
                "    - ClientIP\n" +
                "    - c-uri\n" +
                "    - c-useragent\n" +
                "falsepositives:\n" +
                "    - Rare programs that use Bitsadmin and update from regional TLDs e.g. .uk or .ca\n" +
                "level: high\n" +
                "tags:\n" +
                "    - attack.command_and_control\n" +
                "    - attack.t1071.001\n" +
                "    - attack.defense_evasion\n" +
                "    - attack.persistence\n" +
                "    - attack.t1197\n" +
                "    - attack.s0190", false));
        Assert.assertEquals(true, true);
    }

    private OSQueryBackend testBackend() throws IOException {
        return new OSQueryBackend("proxy", true, true);
    }
}