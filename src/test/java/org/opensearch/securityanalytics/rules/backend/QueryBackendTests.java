/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.securityanalytics.rules.backend;

import java.io.IOException;
import org.opensearch.index.query.RangeQueryBuilder;
import org.opensearch.securityanalytics.rules.exceptions.SigmaValueError;
import java.util.List;
import java.util.Map;
import org.junit.Assert;
import org.opensearch.securityanalytics.rules.exceptions.SigmaError;
import org.opensearch.securityanalytics.rules.exceptions.CompositeSigmaErrors;
import org.opensearch.securityanalytics.rules.objects.SigmaRule;
import org.opensearch.test.OpenSearchTestCase;

public class QueryBackendTests extends OpenSearchTestCase {

    private static Map<String, String> testFieldMapping = Map.of(
        "EventID", "event_uid",
        "HiveName", "unmapped.HiveName",
        "fieldB", "mappedB",
        "fieldA1", "mappedA",
        "creationTime", "timestamp"
    );

    public void testBackendPipeline() throws IOException, SigmaError, CompositeSigmaErrors {
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

    public void testBackendAndCustomPipeline() throws IOException, SigmaError, CompositeSigmaErrors {
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

    public void testConvertValueStr() throws IOException, SigmaError, CompositeSigmaErrors {
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

    public void testConvertValueStrStartsWith() throws IOException, SigmaError, CompositeSigmaErrors {
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

    public void testConvertValueStrStartsWithFurtherWildcard() throws IOException, SigmaError, CompositeSigmaErrors {
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

    public void testConvertValueStrEndsWith() throws IOException, SigmaError, CompositeSigmaErrors {
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

    public void testConvertValueStrEndsWithFurtherWildcard() throws IOException, SigmaError, CompositeSigmaErrors {
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

    public void testConvertValueStrContains() throws IOException, SigmaError, CompositeSigmaErrors {
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

    public void testConvertValueStrContainsFurtherWildcard() throws IOException, SigmaError, CompositeSigmaErrors {
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

    public void testConvertValueExpansionWithAll() throws IOException, SigmaError, CompositeSigmaErrors {
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

    public void testConvertValueNum() throws IOException, SigmaError, CompositeSigmaErrors {
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

    public void testConvertValueBool() throws IOException, SigmaError, CompositeSigmaErrors {
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

    public void testConvertValueNull() throws IOException, SigmaError, CompositeSigmaErrors {
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
        Assert.assertEquals("mappedA: (NOT [* TO *])", queries.get(0).toString());
    }

    public void testConvertValueRegex() throws IOException, SigmaError, CompositeSigmaErrors {
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

    public void testConvertValueRegexUnbound() throws IOException, SigmaError, CompositeSigmaErrors {
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
        Assert.assertEquals("/pat.*tern\\\"foo\\\"bar/", queries.get(0).toString());
    }

    public void testConvertValueCidrWildcardNone() throws IOException, SigmaError, CompositeSigmaErrors {
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

    public void testConvertCompare() throws IOException, SigmaError, CompositeSigmaErrors {
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
        assertThrows(CompositeSigmaErrors.class, () -> {
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

    public void testConvertOrInList() throws IOException, SigmaError, CompositeSigmaErrors {
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

    public void testConvertOrInListWithWildcards() throws IOException, SigmaError, CompositeSigmaErrors {
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

    public void testConvertOrInSeparate() throws IOException, SigmaError, CompositeSigmaErrors {
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

    public void testConvertOrInMixedKeywordField() throws IOException, SigmaError, CompositeSigmaErrors {
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
        Assert.assertEquals("((fieldA: \"value1\") OR (mappedB: \"value2\")) OR (\"value3\")", queries.get(0).toString());
    }

    public void testConvertOrInMixedFields() throws IOException, SigmaError, CompositeSigmaErrors {
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

    public void testConvertOrInUnallowedValueType() throws IOException, SigmaError, CompositeSigmaErrors {
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
        Assert.assertEquals("(mappedA: \"value1\") OR (mappedA: \"value2\") OR (mappedA: (NOT [* TO *]))", queries.get(0).toString());
    }

    public void testConvertOrInListNumbers() throws IOException, SigmaError, CompositeSigmaErrors {
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

    public void testConvertAndInList() throws IOException, SigmaError, CompositeSigmaErrors {
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

    public void testConvertUnboundValues() throws IOException, SigmaError, CompositeSigmaErrors {
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
                        "                        - 123\n" +
                        "                condition: sel", false));
        Assert.assertEquals("(\"value1\") OR (\"value2\") OR (\"123\")", queries.get(0).toString());
    }

    public void testConvertInvalidUnboundBool() throws IOException {
        OSQueryBackend queryBackend = testBackend();
        CompositeSigmaErrors exception = assertThrows(CompositeSigmaErrors.class, () -> {
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

        String expectedMessage = "Sigma rule must have a detection definitions";
        String actualMessage = exception.getErrors().get(0).getMessage();

        assertTrue(actualMessage.contains(expectedMessage));
    }

    public void testConvertInvalidCidr() throws IOException {
        OSQueryBackend queryBackend = testBackend();
        CompositeSigmaErrors exception = assertThrows(CompositeSigmaErrors.class, () -> {
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

        String expectedMessage = "Sigma rule must have a detection definitions";
        String actualMessage = exception.getErrors().get(0).getMessage();

        assertTrue(actualMessage.contains(expectedMessage));
    }

    public void testConvertAnd() throws IOException, SigmaError, CompositeSigmaErrors {
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

    public void testConvertOr() throws IOException, SigmaError, CompositeSigmaErrors {
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

    public void testConvertNot() throws IOException, SigmaError, CompositeSigmaErrors {
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
        Assert.assertEquals("(NOT fieldA: \"value1\" AND _exists_: fieldA)", queries.get(0).toString());
    }

    public void testConvertNotWithParenthesis() throws IOException, SigmaError, CompositeSigmaErrors {
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
                        "                    Opcode: Info\n" +
                        "                sel2:\n" +
                        "                    Severity: value2\n" +
                        "                condition: not (sel1 or sel2)", false));
        Assert.assertEquals("(((NOT Opcode: \"Info\" AND _exists_: Opcode) AND (NOT Severity: \"value2\" AND _exists_: Severity)))", queries.get(0).toString());
    }

    public void testConvertNotComplicatedExpression() throws IOException, SigmaError, CompositeSigmaErrors {
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
                        "                selection1:\n" +
                        "                    CommandLine|endswith: '.cpl'\n" +
                        "                filter:\n" +
                        "                    CommandLine|contains:\n" +
                        "                        - '\\System32\\'\n" +
                        "                        - '%System%'\n" +
                        "                fp1_igfx:\n" +
                        "                    CommandLine|contains|all:\n" +
                        "                        - 'regsvr32 '\n" +
                        "                        - ' /s '\n" +
                        "                        - 'igfxCPL.cpl'\n" +
                        "                condition: selection1 and not filter and not fp1_igfx", false));
        Assert.assertEquals("((CommandLine: *.cpl) AND ((((NOT CommandLine: *\\\\System32\\\\* AND _exists_: CommandLine) AND " +
                "(NOT CommandLine: *%System%* AND _exists_: CommandLine))))) AND ((((NOT CommandLine: *regsvr32_ws_* AND _exists_: CommandLine) OR " +
                "(NOT CommandLine: *_ws_\\/s_ws_* AND _exists_: CommandLine) OR (NOT CommandLine: *igfxCPL.cpl* AND _exists_: CommandLine))))", queries.get(0).toString());
    }

    public void testConvertNotWithAnd() throws IOException, SigmaError, CompositeSigmaErrors {
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
                        "                selection:\n" +
                        "                    EventType: SetValue\n" +
                        "                    TargetObject|endswith: '\\Software\\Microsoft\\WAB\\DLLPath'\n" +
                        "                filter:\n" +
                        "                    Details: '%CommonProgramFiles%\\System\\wab32.dll'\n" +
                        "                condition: selection and not filter", false));
        Assert.assertEquals("((EventType: \"SetValue\") AND (TargetObject: *\\\\Software\\\\Microsoft\\\\WAB\\\\DLLPath)) AND ((NOT Details: \"%CommonProgramFiles%\\\\System\\\\wab32.dll\" AND _exists_: Details))", queries.get(0).toString());
    }

    public void testConvertNotWithOrAndList() throws IOException, SigmaError, CompositeSigmaErrors {
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
                        "                    field1: valueA1\n" +
                        "                    field2: valueA2\n" +
                        "                    field3: valueA3\n" +
                        "                sel3:\n" +
                        "                    - resp_mime_types|contains: 'dosexec'\n" +
                        "                    - c-uri|endswith: '.exe'\n" +
                        "                condition: not sel1 or sel3", false));
        Assert.assertEquals("((((NOT field1: \"valueA1\" AND _exists_: field1) OR (NOT field2: \"valueA2\" AND _exists_: field2) OR (NOT field3: \"valueA3\" AND _exists_: field3)))) OR ((resp_mime_types: *dosexec*) OR (c-uri: *.exe))", queries.get(0).toString());
    }

    public void testConvertNotWithNumAndBool() throws IOException, SigmaError, CompositeSigmaErrors {
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
                        "                    field1: 1\n" +
                        "                sel2:\n" +
                        "                    field2: true\n" +
                        "                condition: not sel1 and not sel2", false));
        Assert.assertEquals("((NOT field1: 1 AND _exists_: field1)) AND ((NOT field2: true AND _exists_: field2))", queries.get(0).toString());
    }

    public void testConvertNotWithNull() throws IOException, SigmaError, CompositeSigmaErrors {
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
                        "                    fieldA: null\n" +
                        "                sel2:\n" +
                        "                    fieldB: true\n" +
                        "                condition: not sel1", false));
        Assert.assertEquals("(NOT fieldA: (NOT [* TO *]) AND _exists_: fieldA)", queries.get(0).toString());
    }

    public void testConvertNotWithKeywords() throws IOException, SigmaError, CompositeSigmaErrors {
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
                        "                keywords:\n" +
                        "                     - test1\n" +
                        "                     - 123\n" +
                        "                condition: not keywords", false));
        Assert.assertEquals("(((NOT \"test1\") AND (NOT \"123\")))", queries.get(0).toString());
    }

    public void testConvertPrecedence() throws IOException, SigmaError, CompositeSigmaErrors {
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
        Assert.assertEquals("((fieldA: \"value1\") OR (mappedB: \"value2\")) AND ((((NOT fieldC: \"value4\" AND _exists_: fieldC) OR (NOT fieldD: \"value5\" AND _exists_: fieldD))))", queries.get(0).toString());
    }

    public void testConvertMultiConditions() throws IOException, SigmaError, CompositeSigmaErrors {
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

    public void testConvertListCidrWildcardNone() throws IOException, SigmaError, CompositeSigmaErrors {
        OSQueryBackend queryBackend = new OSQueryBackend(null, false, false);
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

    public void testConvertNetworkRule() throws IOException, SigmaError, CompositeSigmaErrors {
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

    public void testConvertRegexpRule() throws IOException, SigmaError, CompositeSigmaErrors {
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

    public void testConvertProxyRule() throws IOException, SigmaError, CompositeSigmaErrors {
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

    public void testConvertUnboundValuesAsWildcard() throws IOException, SigmaError, CompositeSigmaErrors {
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
                        "                        - value3\n" +
                        "                keywords:\n" +
                        "                     - test*\n" +
                        "                condition: sel or keywords", false));
        Assert.assertEquals("((mappedA: \"value1\") OR (mappedA: \"value2\") OR (mappedA: \"value3\")) OR (test*)", queries.get(0).toString());
    }

    public void testConvertSkipEmptyStringStartsWithModifier() throws IOException, SigmaError {
        OSQueryBackend queryBackend = testBackend();
        Assert.assertThrows(CompositeSigmaErrors.class, () -> {
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
                            "                    fieldA1|startswith: \n" +
                            "                        - value1\n" +
                            "                        - value2\n" +
                            "                        - ''\n" +
                            "                condition: sel", false));
        });
    }

    public void testConvertSkipEmptyStringEndsWithModifier() throws IOException, SigmaError {
        OSQueryBackend queryBackend = testBackend();
        Assert.assertThrows(CompositeSigmaErrors.class, () -> {
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
                            "                    fieldA1|endswith: \n" +
                            "                        - value1\n" +
                            "                        - value2\n" +
                            "                        - ''\n" +
                            "                condition: sel", false));
        });
    }

    public void testConvertSkipEmptyStringContainsModifier() throws IOException, SigmaError {
        OSQueryBackend queryBackend = testBackend();
        Assert.assertThrows(CompositeSigmaErrors.class, () -> {
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
                            "                    fieldA1|contains: \n" +
                            "                        - value1\n" +
                            "                        - value2\n" +
                            "                        - ''\n" +
                            "                condition: sel", false));
        });
    }

    // -----------------------------------------------------------------------
    // TDD: wildcard-typed field emits native wildcard DSL instead of query_string
    // -----------------------------------------------------------------------

    /**
     * When the target field is mapped as OpenSearch type "wildcard", the backend
     * must emit a native wildcard DSL clause:
     *   {"wildcard":{"<field>":{"value":"<pattern>"}}}
     * instead of a query_string expression.  query_string calls
     * normalizedWildcardQuery() on the field type, which WildcardFieldMapper does
     * not override, causing a QueryShardException that is silently swallowed (0 hits).
     */
    public void testContainsOnWildcardTypedFieldEmitsWildcardDSL() throws IOException, SigmaError, CompositeSigmaErrors {
        // fieldWild is declared as type "wildcard" in the index mapping
        Map<String, String> fieldTypes = Map.of("attributes.message", "wildcard");
        OSQueryBackend queryBackend = new OSQueryBackend(testFieldMapping, false, true, fieldTypes);

        List<Object> queries = queryBackend.convertRule(SigmaRule.fromYaml(
                "            title: Test Wildcard Field\n" +
                "            id: 39f919f3-980b-4e6f-a975-8af7e507ef2c\n" +
                "            status: test\n" +
                "            level: high\n" +
                "            description: Detects admin login via wildcard-typed field\n" +
                "            author: Test\n" +
                "            date: 2024/01/01\n" +
                "            logsource:\n" +
                "                category: test_category\n" +
                "                product: test_product\n" +
                "            detection:\n" +
                "                sel:\n" +
                "                    attributes.message|contains: 'admin Logging in success'\n" +
                "                condition: sel", false));

        // Must produce native wildcard DSL — NOT a query_string expression
        Assert.assertEquals(org.opensearch.index.query.QueryBuilders.wildcardQuery("attributes.message", "*admin Logging in success*"), queries.get(0));
    }

    /**
     * Existing text/keyword fields must be unaffected — they continue to use
     * the query_string expression with wildcard tokens.
     */
    public void testContainsOnTextFieldStillEmitsQueryString() throws IOException, SigmaError, CompositeSigmaErrors {
        // fieldA1 is NOT in fieldTypes, so it is treated as text/keyword
        Map<String, String> fieldTypes = Map.of("attributes.message", "wildcard");
        OSQueryBackend queryBackend = new OSQueryBackend(testFieldMapping, false, true, fieldTypes);

        List<Object> queries = queryBackend.convertRule(SigmaRule.fromYaml(
                "            title: Test Text Field Unaffected\n" +
                "            id: 39f919f3-980b-4e6f-a975-8af7e507ef2d\n" +
                "            status: test\n" +
                "            level: high\n" +
                "            description: Text field must keep query_string form\n" +
                "            author: Test\n" +
                "            date: 2024/01/01\n" +
                "            logsource:\n" +
                "                category: test_category\n" +
                "                product: test_product\n" +
                "            detection:\n" +
                "                sel:\n" +
                "                    fieldA1|contains: value\n" +
                "                condition: sel", false));

        // Must keep the classic query_string form
        Assert.assertEquals(org.opensearch.index.query.QueryBuilders.queryStringQuery("mappedA: *value*"), queries.get(0));
    }

    /**
     * Backward-compatibility: the 3-arg constructor
     * exactly as before — no wildcard DSL emitted for any field.
     */
    public void testLegacyConstructorUnaffected() throws IOException, SigmaError, CompositeSigmaErrors {
        OSQueryBackend queryBackend = testBackend(); // 3-arg — no fieldTypes map

        List<Object> queries = queryBackend.convertRule(SigmaRule.fromYaml(
                "            title: Test Legacy\n" +
                "            id: 39f919f3-980b-4e6f-a975-8af7e507ef2e\n" +
                "            status: test\n" +
                "            level: high\n" +
                "            description: Legacy constructor must not emit wildcard DSL\n" +
                "            author: Test\n" +
                "            date: 2024/01/01\n" +
                "            logsource:\n" +
                "                category: test_category\n" +
                "                product: test_product\n" +
                "            detection:\n" +
                "                sel:\n" +
                "                    fieldA1|contains: value\n" +
                "                condition: sel", false));

        Assert.assertEquals("mappedA: *value*", queries.get(0).toString());
    }

    /**
     * Plain literal (no wildcard modifier) on a wildcard-typed field must also
     * emit native wildcard DSL.  This is the real production case:
     *   attributes.message: "hopefully it worked"
     * SA was previously emitting query_string with the value mangled to
     * "hopefully_ws_it_ws_worked" (spaces replaced by _ws_), which returned 0 hits
     * because WildcardFieldMapper has no inverted index.
     */
    public void testPlainLiteralOnWildcardTypedFieldEmitsWildcardDSL() throws IOException, SigmaError, CompositeSigmaErrors {
        Map<String, String> fieldTypes = Map.of("attributes.message", "wildcard");
        OSQueryBackend queryBackend = new OSQueryBackend(testFieldMapping, false, true, fieldTypes);

        List<Object> queries = queryBackend.convertRule(SigmaRule.fromYaml(
                "            title: Test Plain Literal Wildcard Field\n" +
                "            id: 48724ee3-18d9-494d-868b-5fa104ab3ef0\n" +
                "            status: test\n" +
                "            level: high\n" +
                "            description: Plain string match on wildcard-typed field\n" +
                "            author: Test\n" +
                "            date: 2024/01/01\n" +
                "            logsource:\n" +
                "                category: test_category\n" +
                "                product: test_product\n" +
                "            detection:\n" +
                "                sel:\n" +
                "                    attributes.message: 'hopefully it worked'\n" +
                "                condition: sel", false));

        // Must produce native wildcard DSL with the literal value — no _ws_ mangling
        Assert.assertEquals(org.opensearch.index.query.QueryBuilders.wildcardQuery("attributes.message", "hopefully it worked"), queries.get(0));
    }

    private OSQueryBackend testBackend() throws IOException {
        return new OSQueryBackend(testFieldMapping, false, true);
    }

    public void testWildcardCompoundQuery() throws Exception {
        OSQueryBackend backend = new OSQueryBackend(Map.of(), false, true, Map.of("message", "wildcard"));
        List<Object> queries = backend.convertRule(SigmaRule.fromYaml("title: Compound\nid: 39f919f3-980b-4e6f-a975-8af7e507ef2b\nstatus: test\nlevel: high\ndescription: Test\nauthor: Test\nlogsource:\n  category: test\n"
            + "detection:\n  sel:\n    message|contains: ['foo', 'bar']\n    code: 4624\n  condition: sel\n", false));
        assertTrue("Compound wildcard query must be structured DSL", queries.get(0) instanceof org.opensearch.index.query.QueryBuilder);
        org.opensearch.index.query.BoolQueryBuilder query = (org.opensearch.index.query.BoolQueryBuilder) queries.get(0);
        assertEquals(2, query.must().size());
        assertTrue(query.toString().contains("\"wildcard\""));
        assertTrue(query.toString().contains("\"query_string\""));
    }

    private Object wildcardQuery(String detection) throws Exception {
        return new OSQueryBackend(Map.of("Message", "message"), false, true, Map.of("message", "wildcard"))
            .convertRule(SigmaRule.fromYaml("title: Wildcard regression\nid: 39f919f3-980b-4e6f-a975-8af7e507ef2b\n"
                + "status: test\nlevel: high\ndescription: Test\nauthor: Test\nlogsource:\n  category: test\ndetection:\n"
                + detection, false)).get(0);
    }

    public void testWildcardNegationExcludesMissingFields() throws Exception {
        assertEquals(org.opensearch.index.query.QueryBuilders.boolQuery()
            .mustNot(org.opensearch.index.query.QueryBuilders.wildcardQuery("message", "*foo*"))
            .filter(org.opensearch.index.query.QueryBuilders.existsQuery("message")),
            wildcardQuery("  sel:\n    Message|contains: foo\n  condition: not sel\n"));
    }

    public void testWildcardDeMorgansAndDoubleNegation() throws Exception {
        org.opensearch.index.query.BoolQueryBuilder negated = (org.opensearch.index.query.BoolQueryBuilder)
            wildcardQuery("  sel:\n    Message|contains|all: ['foo', 'bar']\n  condition: not sel\n");
        assertEquals(2, negated.should().size());
        assertEquals("1", negated.minimumShouldMatch());
        assertEquals(org.opensearch.index.query.QueryBuilders.wildcardQuery("message", "foo"),
            wildcardQuery("  sel:\n    Message: foo\n  condition: not (not sel)\n"));
    }

    public void testWildcardEscapedLiteralsAndJsonCharacters() throws Exception {
        assertEquals(org.opensearch.index.query.QueryBuilders.wildcardQuery("message", "*C:\\\\Windows\\*\\?\"*"),
            wildcardQuery("  sel:\n    Message|contains: 'C:\\Windows\\*\\?\"'\n  condition: sel\n"));
    }

    public void testWildcardNullAndRegex() throws Exception {
        assertEquals(org.opensearch.index.query.QueryBuilders.boolQuery().mustNot(org.opensearch.index.query.QueryBuilders.existsQuery("message")),
            wildcardQuery("  sel:\n    Message: null\n  condition: sel\n"));
        assertEquals(org.opensearch.index.query.QueryBuilders.existsQuery("message"),
            wildcardQuery("  sel:\n    Message: null\n  condition: not sel\n"));
        assertEquals(org.opensearch.index.query.QueryBuilders.regexpQuery("message", "foo.*bar"),
            wildcardQuery("  sel:\n    Message|re: 'foo.*bar'\n  condition: sel\n"));
    }

    public void testWildcardMultipleConditions() throws Exception {
        List<Object> queries = new OSQueryBackend(Map.of(), false, true, Map.of("message", "wildcard"))
            .convertRule(SigmaRule.fromYaml("title: Multiple conditions\nid: 39f919f3-980b-4e6f-a975-8af7e507ef2b\n"
                + "status: test\nlevel: high\ndescription: Test\nauthor: Test\nlogsource:\n  category: test\n"
                + "detection:\n  one:\n    message: foo\n  two:\n    message: bar\n  condition: ['one', 'two']\n", false));
        assertEquals(List.of(org.opensearch.index.query.QueryBuilders.wildcardQuery("message", "foo"),
            org.opensearch.index.query.QueryBuilders.wildcardQuery("message", "bar")), queries);
    }

    public void testTypedNumericAndIpModifiersDoNotRequireWildcardSibling() throws Exception {
        assertEquals(org.opensearch.index.query.QueryBuilders.rangeQuery("count").gte("10"),
            typedQuery("  sel:\n    Count|gte: 10\n  condition: sel\n", Map.of("count", "long")));
        assertEquals(org.opensearch.index.query.QueryBuilders.termQuery("source.ip", "192.168.0.0/16"),
            typedQuery("  sel:\n    SourceIp|cidr: '192.168.0.0/16'\n  condition: sel\n", Map.of("source.ip", "ip")));
    }

    public void testNumericComparisonsWithWildcardSiblingUseNativeRanges() throws Exception {
        for (String modifier : List.of("lt", "lte", "gt", "gte")) {
            RangeQueryBuilder range = org.opensearch.index.query.QueryBuilders.rangeQuery("count");
            switch (modifier) {
                case "lt": range.lt("10"); break;
                case "lte": range.lte("10"); break;
                case "gt": range.gt("10"); break;
                case "gte": range.gte("10"); break;
                default: throw new AssertionError(modifier);
            }
            assertEquals(org.opensearch.index.query.QueryBuilders.boolQuery()
                .must(org.opensearch.index.query.QueryBuilders.wildcardQuery("message", "foo"))
                .must(range),
                typedQuery("  sel:\n    Message: foo\n    Count|" + modifier + ": 10\n  condition: sel\n",
                    Map.of("message", "wildcard", "count", "long")));
        }
    }

    public void testWildcardCidrRejectsStringsButIpSiblingUsesNetworkQuery() throws Exception {
        SigmaValueError error = expectThrows(
            SigmaValueError.class,
            () -> wildcardQuery("  sel:\n    Message|cidr: '192.168.0.0/16'\n  condition: sel\n"));
        assertTrue(error.getMessage(), error.getMessage().contains("ip"));
        assertEquals(org.opensearch.index.query.QueryBuilders.boolQuery()
            .must(org.opensearch.index.query.QueryBuilders.wildcardQuery("message", "foo"))
            .must(org.opensearch.index.query.QueryBuilders.termQuery("source.ip", "192.168.0.0/16")),
            typedQuery("  sel:\n    Message: foo\n    SourceIp|cidr: '192.168.0.0/16'\n  condition: sel\n",
                Map.of("message", "wildcard", "source.ip", "ip")));
    }

    private Object typedQuery(String detection, Map<String, String> types) throws Exception {
        return new OSQueryBackend(Map.of("Message", "message", "Count", "count", "SourceIp", "source.ip"), false, true, types)
            .convertRule(SigmaRule.fromYaml("title: Typed regression\nid: 39f919f3-980b-4e6f-a975-8af7e507ef2b\n"
                + "status: test\nlevel: high\ndescription: Test\nauthor: Test\nlogsource:\n  category: test\ndetection:\n"
                + detection, false)).get(0);
    }

    public void testWildcardStringModifierChainsPreservePatternsAndExpansions() throws Exception {
        Map<String, String> patterns = Map.of(
            "startswith", "abc*", "endswith", "*abc", "base64", "YWJj",
            "base64|contains", "*YWJj*", "wide", "a\u0000b\u0000c\u0000",
            "wide|base64", "YQBiAGMA", "re|contains", ".*abc.*");
        for (Map.Entry<String, String> pattern : patterns.entrySet()) {
            assertEquals(pattern.getKey(), pattern.getKey().startsWith("re")
                ? org.opensearch.index.query.QueryBuilders.regexpQuery("message", pattern.getValue())
                : org.opensearch.index.query.QueryBuilders.wildcardQuery("message", pattern.getValue()),
                wildcardQuery("  sel:\n    Message|" + pattern.getKey() + ": abc\n  condition: sel\n"));
        }
        assertEquals(org.opensearch.index.query.QueryBuilders.boolQuery().minimumShouldMatch(1)
            .should(org.opensearch.index.query.QueryBuilders.wildcardQuery("message", "*YWJj*"))
            .should(org.opensearch.index.query.QueryBuilders.wildcardQuery("message", "*FiY*"))
            .should(org.opensearch.index.query.QueryBuilders.wildcardQuery("message", "*hYm*")),
            wildcardQuery("  sel:\n    Message|base64offset|contains: abc\n  condition: sel\n"));
        assertEquals(org.opensearch.index.query.QueryBuilders.boolQuery().minimumShouldMatch(1)
            .should(org.opensearch.index.query.QueryBuilders.wildcardQuery("message", "-abc"))
            .should(org.opensearch.index.query.QueryBuilders.wildcardQuery("message", "/abc")),
            wildcardQuery("  sel:\n    Message|windash: '-abc'\n  condition: sel\n"));
        assertEquals(org.opensearch.index.query.QueryBuilders.boolQuery()
            .must(org.opensearch.index.query.QueryBuilders.wildcardQuery("message", "abc"))
            .must(org.opensearch.index.query.QueryBuilders.wildcardQuery("message", "def")),
            wildcardQuery("  sel:\n    Message|all: ['abc', 'def']\n  condition: sel\n"));
    }

    public void testTypedModifierNegationPreservesMissingFieldGuard() throws Exception {
        assertEquals(org.opensearch.index.query.QueryBuilders.boolQuery()
            .mustNot(org.opensearch.index.query.QueryBuilders.rangeQuery("count").lt("10"))
            .filter(org.opensearch.index.query.QueryBuilders.existsQuery("count")),
            typedQuery("  sel:\n    Count|lt: 10\n  condition: not sel\n", Map.of("count", "long")));
        assertEquals(org.opensearch.index.query.QueryBuilders.boolQuery()
            .mustNot(org.opensearch.index.query.QueryBuilders.termQuery("source.ip", "192.168.0.0/16"))
            .filter(org.opensearch.index.query.QueryBuilders.existsQuery("source.ip")),
            typedQuery("  sel:\n    SourceIp|cidr: '192.168.0.0/16'\n  condition: not sel\n", Map.of("source.ip", "ip")));
    }

    public void testWildcardComparisonsRejectNonNumericMappings() throws Exception {
        for (String type : List.of("wildcard", "keyword", "text", "ip", "boolean", "date")) {
            for (String modifier : List.of("lt", "lte", "gt", "gte")) {
                SigmaValueError error = expectThrows(
                    SigmaValueError.class,
                    () -> typedQuery("  sel:\n    Count|" + modifier + ": 10\n  condition: sel\n",
                        Map.of("message", "wildcard", "count", type)));
                assertTrue(error.getMessage(), error.getMessage().contains("numeric mapping"));
            }
        }
    }

    public void testWildcardModifierTypeAndOrderErrorsAreNotSilentlyCoerced() throws Exception {
        for (String key : List.of("contains", "startswith", "endswith", "base64", "base64offset", "wide", "windash", "re", "cidr")) {
            CompositeSigmaErrors error = expectThrows(CompositeSigmaErrors.class,
                () -> wildcardQuery("  sel:\n    Message|" + key + ": 42\n  condition: sel\n"));
            assertFalse(error.getErrors().isEmpty());
        }
        for (String key : List.of("contains|base64", "contains|base64offset", "contains|re")) {
            CompositeSigmaErrors error = expectThrows(CompositeSigmaErrors.class,
                () -> wildcardQuery("  sel:\n    Message|" + key + ": abc\n  condition: sel\n"));
            assertFalse(error.getErrors().isEmpty());
        }
        for (String key : List.of("utf16", "utf16le", "utf16be")) {
            CompositeSigmaErrors error = expectThrows(CompositeSigmaErrors.class,
                () -> wildcardQuery("  sel:\n    Message|" + key + ": abc\n  condition: sel\n"));
            // SigmaRule currently wraps the unknown-modifier error in a detection-definition error.
            assertTrue(error.getErrors().toString(), error.getErrors().stream()
                .anyMatch(cause -> cause.getMessage().contains("detection definitions")));
        }
    }

    public void testWildcardRegexRejectsJavaOnlyConstructs() throws Exception {
        for (String regex : List.of("^abc$", "(?=abc)abc", "(abc)\\1", "abc\\b", "[a-z&&[^x]]", "abc.*?", "abc@")) {
            SigmaValueError error = expectThrows(
                SigmaValueError.class,
                () -> wildcardQuery("  sel:\n    Message|re: '" + regex + "'\n  condition: sel\n"));
            assertTrue(error.getMessage(), error.getMessage().contains("Lucene"));
        }
    }

    public void testWildcardRegexPreservesSpacesAndLiteralWhitespaceMarker() throws Exception {
        for (String value : List.of("foo bar", "foo_ws_bar", "foo bar_ws_baz", "foo[ ]bar", "foo\\* \\?bar_ws_")) {
            for (String modifier : List.of("re", "re|contains", "re|startswith", "re|endswith", "re|startswith|endswith")) {
                String expected = (modifier.contains("contains") || modifier.contains("endswith") ? ".*" : "")
                    + value + (modifier.contains("contains") || modifier.contains("startswith") ? ".*" : "");
                assertEquals(org.opensearch.index.query.QueryBuilders.regexpQuery("message", expected),
                    wildcardQuery("  sel:\n    Message|" + modifier + ": '" + value + "'\n  condition: sel\n"));
            }
        }
    }

    public void testRegexRawTrackingRetainsLegacyAccessorAndSetterOutput() throws Exception {
        org.opensearch.securityanalytics.rules.types.SigmaRegularExpression regex =
            new org.opensearch.securityanalytics.rules.types.SigmaRegularExpression("foo bar_ws_baz");
        assertEquals("foo_ws_bar_ws_baz", regex.getRegexp());
        assertEquals("foo bar_ws_baz", regex.getOriginal());
        regex.wrapPattern(true, false);
        regex.wrapPattern(false, true);
        regex.compile();
        assertEquals(".*foo_ws_bar_ws_baz.*", regex.getRegexp());
        assertEquals(regex.getRegexp(), regex.toString());
        assertEquals(".*foo bar_ws_baz.*", regex.getOriginal());
        regex.setRegexp(regex.getRegexp());
        assertEquals(".*foo_ws_bar_ws_baz.*", regex.getOriginal());
        regex.setRegexp("replacement value_ws_");
        assertEquals("replacement value_ws_", regex.getOriginal());
        assertEquals("replacement value_ws_", regex.getRegexp());
        regex.setRegexp("[invalid pattern");
        expectThrows(org.opensearch.securityanalytics.rules.exceptions.SigmaRegularExpressionError.class, regex::compile);
    }

    public void testWildcardWindashPreservesSpacesAndLiteralWhitespaceMarker() throws Exception {
        for (String value : List.of("foo bar", "foo_ws_bar", "foo bar_ws_baz")) {
            assertEquals(org.opensearch.index.query.QueryBuilders.boolQuery().minimumShouldMatch(1)
                .should(org.opensearch.index.query.QueryBuilders.wildcardQuery("message", value)),
                wildcardQuery("  sel:\n    Message|windash: '" + value + "'\n  condition: sel\n"));
            assertEquals(org.opensearch.index.query.QueryBuilders.boolQuery().minimumShouldMatch(1)
                .should(org.opensearch.index.query.QueryBuilders.wildcardQuery("message", "*" + value + " -flag*"))
                .should(org.opensearch.index.query.QueryBuilders.wildcardQuery("message", "*" + value + " /flag*")),
                wildcardQuery("  sel:\n    Message|windash|contains: '" + value + " -flag'\n  condition: sel\n"));
        }
    }

    public void testWildcardWindashMultipleFlagsKeepIndependentLiteralAndGlobSegments() throws Exception {
        org.opensearch.index.query.BoolQueryBuilder expected = org.opensearch.index.query.QueryBuilders.boolQuery().minimumShouldMatch(1);
        for (String first : List.of("-", "/")) {
            for (String second : List.of("-", "/")) {
                expected.should(org.opensearch.index.query.QueryBuilders.wildcardQuery("message",
                    "*pre* " + first + "one\\* _ws_ " + second + "two\\? ?end*"));
            }
        }
        assertEquals(expected, wildcardQuery(
            "  sel:\n    Message|windash|contains: 'pre* -one\\* _ws_ /two\\? ?end'\n  condition: sel\n"));
        assertEquals(expected, wildcardQuery(
            "  sel:\n    Message|contains|windash: 'pre* -one\\* _ws_ /two\\? ?end'\n  condition: sel\n"));
    }

    public void testRegexAndWindashLegacyWhitespaceOutputRemainsEncoded() throws Exception {
        String rule = "title: Legacy whitespace\nid: 39f919f3-980b-4e6f-a975-8af7e507ef2b\n"
            + "status: test\nlevel: high\ndescription: Test\nauthor: Test\nlogsource:\n  category: test\ndetection:\n";
        assertEquals("Message: /.*foo_ws_bar_ws_baz.*/", testBackend().convertRule(SigmaRule.fromYaml(rule
            + "  sel:\n    Message|re|contains: 'foo bar_ws_baz'\n  condition: sel\n", false)).get(0));
        assertEquals("(Message: *foo_ws_\\-flag*) OR (Message: *foo_ws_\\/flag*)",
            testBackend().convertRule(SigmaRule.fromYaml(rule
                + "  sel:\n    Message|windash|contains: 'foo -flag'\n  condition: sel\n", false)).get(0));
    }

    public void testRegexWrapsAlternationAndEscapedDollar() throws Exception {
        for (String modifier : List.of("contains", "startswith", "endswith", "startswith|endswith")) {
            String prefix = modifier.contains("contains") || modifier.contains("endswith") ? ".*" : "";
            String suffix = modifier.contains("contains") || modifier.contains("startswith") ? ".*" : "";
            for (String pattern : List.of("foo|bar", "foo.*|bar", "foo|bar.*", "foo\\$|bar\\$")) {
                assertEquals(org.opensearch.index.query.QueryBuilders.regexpQuery("message", prefix + "(" + pattern + ")" + suffix),
                    wildcardQuery("  sel:\n    Message|re|" + modifier + ": '" + pattern + "'\n  condition: sel\n"));
            }
        }
        assertEquals(org.opensearch.index.query.QueryBuilders.regexpQuery("message", "foo\\$.*"),
            wildcardQuery("  sel:\n    Message|re|startswith: 'foo\\$'\n  condition: sel\n"));
        assertEquals(org.opensearch.index.query.QueryBuilders.regexpQuery("message", ".*foo\\$.*"),
            wildcardQuery("  sel:\n    Message|re|contains: 'foo\\$'\n  condition: sel\n"));
        // Escaped pipes and character-class pipes are literals, not alternation branches.
        for (String pattern : List.of("foo\\|bar", "foo[|]bar", "(foo|bar)")) {
            assertEquals(org.opensearch.index.query.QueryBuilders.regexpQuery("message", ".*" + pattern + ".*"),
                wildcardQuery("  sel:\n    Message|re|contains: '" + pattern + "'\n  condition: sel\n"));
        }
    }

    public void testRegexQuantifiedEscapedPunctuationUsesTokenSemantics() throws Exception {
        for (String pattern : List.of("\\*+", "\\?+", "\\++", "\\}+", "[+]+", "a{2,3}", "\\*{2,3}")) {
            assertEquals(org.opensearch.index.query.QueryBuilders.regexpQuery("message", pattern),
                wildcardQuery("  sel:\n    Message|re: '" + pattern + "'\n  condition: sel\n"));
        }
        for (String pattern : List.of("\\*++", "\\?+?", "\\+++", "a{2,3}+", "a{2,3}?", "[+]+?", "a??", "a*+")) {
            expectThrows(SigmaValueError.class,
                () -> wildcardQuery("  sel:\n    Message|re: '" + pattern + "'\n  condition: sel\n"));
        }
    }

    public void testTypedOnlyFieldlessLeavesKeepLegacyQueryString() throws Exception {
        Map<String, String> types = Map.of("count", "long", "source.ip", "ip");
        for (String operator : List.of("and", "or")) {
            for (String fieldless : List.of("words", "not words")) {
                org.opensearch.index.query.BoolQueryBuilder expected = org.opensearch.index.query.QueryBuilders.boolQuery();
                org.opensearch.index.query.QueryBuilder range = org.opensearch.index.query.QueryBuilders.rangeQuery("count").gte("10");
                org.opensearch.index.query.QueryBuilder keyword = org.opensearch.index.query.QueryBuilders.queryStringQuery(
                    fieldless.startsWith("not") ? "NOT \"foo\"" : "\"foo\"");
                if (operator.equals("and")) {
                    expected.must(range).must(keyword);
                } else {
                    expected.should(range).should(keyword).minimumShouldMatch(1);
                }
                assertEquals(expected, typedQuery("  typed:\n    Count|gte: 10\n  words:\n    - foo\n  condition: typed "
                    + operator + " " + fieldless + "\n", types));
            }
        }
    }

    public void testYamlLongAndDoubleComparisonsPreservePrecision() throws Exception {
        for (String value : List.of("2147483648", "9223372036854775807", "-9223372036854775808", "1.2345678901234567")) {
            assertEquals(org.opensearch.index.query.QueryBuilders.rangeQuery("count").gte(value),
                typedQuery("  sel:\n    Count|gte: " + value + "\n  condition: sel\n", Map.of("count", "double")));
        }
    }

    public void testWildcardFieldlessSearchUsesNativeQueries() throws Exception {
        assertEquals(org.opensearch.index.query.QueryBuilders.boolQuery().minimumShouldMatch(1)
            .should(org.opensearch.index.query.QueryBuilders.wildcardQuery("message", "*foo*")),
            wildcardQuery("  sel:\n    - '*foo*'\n  condition: sel\n"));
    }
}