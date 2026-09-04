/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.securityanalytics.rules.backend;

import java.io.IOException;
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

    public void testConvertValueStrContainsWithWhitespace() throws IOException, SigmaError, CompositeSigmaErrors {
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
                        "                    fieldA1|contains: This is an example\n" +
                        "                condition: sel", false));
        String query = queries.get(0).toString();
        Assert.assertFalse("Query must not contain the _ws_ whitespace token: " + query, query.contains("_ws_"));
        // Multi-token contains: single contiguous wildcard term with interior spaces escaped (*text*),
        // case preserved (rule_analyzer has no lowercase filter), so it substring-matches the single token.
        Assert.assertEquals("mappedA: *This\\ is\\ an\\ example*", query);
    }

    public void testConvertValueStrWithWhitespaceQuoted() throws IOException, SigmaError, CompositeSigmaErrors {
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
                        "                    fieldA1: This is an example\n" +
                        "                condition: sel", false));
        String query = queries.get(0).toString();
        // Non-wildcard plain value: space is not in addEscaped, so query_string quotes it literally.
        // The analyzer handles tokenisation; no backslash escaping of space is needed or correct.
        Assert.assertFalse("Quoted query must not contain the _ws_ whitespace token: " + query, query.contains("_ws_"));
        Assert.assertEquals("mappedA: \"This is an example\"", query);
    }

    public void testConvertValueStrStartsWithWhitespace() throws IOException, SigmaError, CompositeSigmaErrors {
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
                        "                    fieldA1|startswith: \"hello world\"\n" +
                        "                condition: sel", false));
        String query = queries.get(0).toString();
        Assert.assertFalse("Query must not contain _ws_ token: " + query, query.contains("_ws_"));
        // startswith: contiguous wildcard term with escaped space and a trailing wildcard.
        Assert.assertEquals("mappedA: hello\\ world*", query);
    }

    public void testConvertValueStrEndsWithWhitespace() throws IOException, SigmaError, CompositeSigmaErrors {
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
                        "                    fieldA1|endswith: \"hello world\"\n" +
                        "                condition: sel", false));
        String query = queries.get(0).toString();
        Assert.assertFalse("Query must not contain _ws_ token: " + query, query.contains("_ws_"));
        // endswith: leading wildcard then the contiguous escaped-space term.
        Assert.assertEquals("mappedA: *hello\\ world", query);
    }

    public void testConvertValueStrContainsNoWhitespace() throws IOException, SigmaError, CompositeSigmaErrors {
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
                        "                    fieldA1|contains: \"example\"\n" +
                        "                condition: sel", false));
        // Single-word contains must stay on the wildcard path, unaffected by the phrase logic.
        Assert.assertEquals("mappedA: *example*", queries.get(0).toString());
    }

    public void testConvertValueStrStartsWithNoWhitespace() throws IOException, SigmaError, CompositeSigmaErrors {
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
                        "                    fieldA1|startswith: \"example\"\n" +
                        "                condition: sel", false));
        // Single-word startswith must stay on the wildcard path.
        Assert.assertEquals("mappedA: example*", queries.get(0).toString());
    }

    public void testConvertValueStrEndsWithNoWhitespace() throws IOException, SigmaError, CompositeSigmaErrors {
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
                        "                    fieldA1|endswith: \"example\"\n" +
                        "                condition: sel", false));
        // Single-word endswith must stay on the wildcard path.
        Assert.assertEquals("mappedA: *example", queries.get(0).toString());
    }

    public void testConvertValueStrContainsMixedSeparators() throws IOException, SigmaError, CompositeSigmaErrors {
        OSQueryBackend queryBackend = testBackend();
        List<Object> queries = queryBackend.convertRule(SigmaRule.fromYaml(
                "            title: Test\n" +
                        "            id: 39f919f3-980b-4e6f-a975-8af7e507ef2b\n" +
                        "            status: test\n" +
                        "            level: critical\n" +
                        "            description: mixed separators regression\n" +
                        "            author: Test\n" +
                        "            date: 2017/05/15\n" +
                        "            logsource:\n" +
                        "                category: test_category\n" +
                        "                product: test_product\n" +
                        "            detection:\n" +
                        "                sel:\n" +
                        "                    fieldA1|contains: GIS - AppSec Team - Project Vision\n" +
                        "                condition: sel", false));
        String query = queries.get(0).toString();
        // Mixed space/dash separators produce a single contiguous wildcard term: dashes are escaped by
        // the convert pipeline (\-) and interior spaces are escaped (\ ), so it substring-matches the
        // single keyword-analyzed token. No _ws_.
        Assert.assertFalse("Query must not contain _ws_ token: " + query, query.contains("_ws_"));
        Assert.assertEquals("mappedA: *GIS\\ \\-\\ AppSec\\ Team\\ \\-\\ Project\\ Vision*", query);
    }

    public void testConvertValueStrStartsWithMixedSeparators() throws IOException, SigmaError, CompositeSigmaErrors {
        OSQueryBackend queryBackend = testBackend();
        List<Object> queries = queryBackend.convertRule(SigmaRule.fromYaml(
                "            title: Test\n" +
                        "            id: 39f919f3-980b-4e6f-a975-8af7e507ef2b\n" +
                        "            status: test\n" +
                        "            level: critical\n" +
                        "            description: mixed separators regression\n" +
                        "            author: Test\n" +
                        "            date: 2017/05/15\n" +
                        "            logsource:\n" +
                        "                category: test_category\n" +
                        "                product: test_product\n" +
                        "            detection:\n" +
                        "                sel:\n" +
                        "                    fieldA1|startswith: GIS - AppSec Team\n" +
                        "                condition: sel", false));
        // startswith: contiguous wildcard term (escaped dashes/spaces) with a trailing wildcard.
        Assert.assertEquals("mappedA: GIS\\ \\-\\ AppSec\\ Team*", queries.get(0).toString());
    }

    public void testConvertValueStrEndsWithMixedSeparators() throws IOException, SigmaError, CompositeSigmaErrors {
        OSQueryBackend queryBackend = testBackend();
        List<Object> queries = queryBackend.convertRule(SigmaRule.fromYaml(
                "            title: Test\n" +
                        "            id: 39f919f3-980b-4e6f-a975-8af7e507ef2b\n" +
                        "            status: test\n" +
                        "            level: critical\n" +
                        "            description: mixed separators regression\n" +
                        "            author: Test\n" +
                        "            date: 2017/05/15\n" +
                        "            logsource:\n" +
                        "                category: test_category\n" +
                        "                product: test_product\n" +
                        "            detection:\n" +
                        "                sel:\n" +
                        "                    fieldA1|endswith: AppSec Team - Project Vision\n" +
                        "                condition: sel", false));
        // endswith: leading wildcard then the contiguous escaped term.
        Assert.assertEquals("mappedA: *AppSec\\ Team\\ \\-\\ Project\\ Vision", queries.get(0).toString());
    }

    public void testConvertValueStrContainsWhitespacePath() throws IOException, SigmaError, CompositeSigmaErrors {
        OSQueryBackend queryBackend = testBackend();
        List<Object> queries = queryBackend.convertRule(SigmaRule.fromYaml(
                "            title: Test\n" +
                        "            id: 39f919f3-980b-4e6f-a975-8af7e507ef2b\n" +
                        "            status: test\n" +
                        "            level: critical\n" +
                        "            description: whitespace path contains regression\n" +
                        "            author: Test\n" +
                        "            date: 2017/05/15\n" +
                        "            logsource:\n" +
                        "                category: test_category\n" +
                        "                product: test_product\n" +
                        "            detection:\n" +
                        "                sel:\n" +
                        "                    fieldA1|contains: 'C:\\Program Files\\nxlog\\nxlog.exe'\n" +
                        "                condition: sel", false));
        String query = queries.get(0).toString();
        // Path value with spaces: single contiguous wildcard term. ':' -> \:, each '\' -> \\, and the
        // interior space -> \ , so it parses and substring-matches the single keyword-analyzed token.
        Assert.assertFalse("Query must not contain _ws_ token: " + query, query.contains("_ws_"));
        Assert.assertEquals("mappedA: *C\\:\\\\Program\\ Files\\\\nxlog\\\\nxlog.exe*", query);
    }

    public void testConvertValueStrContainsQuoteInjection() throws IOException, SigmaError, CompositeSigmaErrors {
        OSQueryBackend queryBackend = testBackend();
        List<Object> queries = queryBackend.convertRule(SigmaRule.fromYaml(
                "            title: Test\n" +
                        "            id: 39f919f3-980b-4e6f-a975-8af7e507ef2b\n" +
                        "            status: test\n" +
                        "            level: critical\n" +
                        "            description: quote injection regression\n" +
                        "            author: Test\n" +
                        "            date: 2017/05/15\n" +
                        "            logsource:\n" +
                        "                category: test_category\n" +
                        "                product: test_product\n" +
                        "            detection:\n" +
                        "                sel:\n" +
                        "                    fieldA1|contains: 'say \"hello\" world'\n" +
                        "                condition: sel", false));
        String query = queries.get(0).toString();
        // A '\"' in the value must be escaped by the convert pipeline (\\\") and never left bare, so it
        // cannot break out of the query term and inject DSL. There is no quote wrapper at all.
        Assert.assertFalse("Query must not contain _ws_ token: " + query, query.contains("_ws_"));
        Assert.assertTrue("Double-quotes must be backslash-escaped: " + query, query.contains("\\\""));
        Assert.assertEquals("mappedA: *say\\ \\\"hello\\\"\\ world*", query);
    }

    public void testConvertPlainSpacedValueEmitsPhrase() throws IOException, SigmaError, CompositeSigmaErrors {
        OSQueryBackend queryBackend = testBackend();
        List<Object> queries = queryBackend.convertRule(SigmaRule.fromYaml(
                "            title: Test\n" +
                        "            id: a1b2c3d4-e5f6-7890-abcd-ef1234567890\n" +
                        "            status: test\n" +
                        "            level: critical\n" +
                        "            description: plain spaced value phrase-path documentation test\n" +
                        "            author: Test\n" +
                        "            date: 2024/01/01\n" +
                        "            logsource:\n" +
                        "                category: test_category\n" +
                        "                product: test_product\n" +
                        "            detection:\n" +
                        "                sel:\n" +
                        "                    fieldA1: 'This is a test'\n" +
                        "                condition: sel", false));
        String query = queries.get(0).toString();
        // Known limitation: plain spaced values emit a quoted phrase that won't match keyword-analyzed fields.
        // Test documents current behavior to catch silent regressions (PR #1789).
        Assert.assertFalse("Plain spaced query must not contain _ws_ token: " + query, query.contains("_ws_"));
        Assert.assertEquals("mappedA: \"This is a test\"", query);
    }

    public void testConvertValueStrContainsSlashSpace() throws IOException, SigmaError, CompositeSigmaErrors {
        OSQueryBackend queryBackend = testBackend();
        List<Object> queries = queryBackend.convertRule(SigmaRule.fromYaml(
                "            title: Test\n" +
                        "            id: 39f919f3-980b-4e6f-a975-8af7e507ef2b\n" +
                        "            status: test\n" +
                        "            level: critical\n" +
                        "            description: slash-space regression (must not collapse to *s*)\n" +
                        "            author: Test\n" +
                        "            date: 2017/05/15\n" +
                        "            logsource:\n" +
                        "                category: test_category\n" +
                        "                product: test_product\n" +
                        "            detection:\n" +
                        "                sel:\n" +
                        "                    fieldA1|contains: ' /s '\n" +
                        "                condition: sel", false));
        String query = queries.get(0).toString();
        // ' /s ' must produce the literal escaped substring term, NOT a lone *s* that matches every doc.
        Assert.assertFalse("Query must not contain _ws_ token: " + query, query.contains("_ws_"));
        Assert.assertEquals("mappedA: *\\ \\/s\\ *", query);
    }

    public void testConvertNotContainsWithWhitespace() throws IOException, SigmaError, CompositeSigmaErrors {
        OSQueryBackend queryBackend = testBackend();
        List<Object> queries = queryBackend.convertRule(SigmaRule.fromYaml(
                "            title: Test\n" +
                        "            id: 39f919f3-980b-4e6f-a975-8af7e507ef2b\n" +
                        "            status: test\n" +
                        "            level: critical\n" +
                        "            description: DeMorgan through the spaced contains path\n" +
                        "            author: Test\n" +
                        "            date: 2017/05/15\n" +
                        "            logsource:\n" +
                        "                category: test_category\n" +
                        "                product: test_product\n" +
                        "            detection:\n" +
                        "                sel:\n" +
                        "                    fieldA1|contains: This is an example\n" +
                        "                condition: not sel", false));
        String query = queries.get(0).toString();
        // applyDeMorgans=true must wrap the spaced escaped-wildcard term with NOT (+ _exists_ guard).
        Assert.assertFalse("Query must not contain _ws_ token: " + query, query.contains("_ws_"));
        Assert.assertEquals("(NOT mappedA: *This\\ is\\ an\\ example* AND _exists_: mappedA)", query);
    }

    public void testConvertValueStrContainsWildcardSingleWithWhitespace() throws IOException, SigmaError, CompositeSigmaErrors {
        OSQueryBackend queryBackend = testBackend();
        List<Object> queries = queryBackend.convertRule(SigmaRule.fromYaml(
                "            title: Test\n" +
                        "            id: 39f919f3-980b-4e6f-a975-8af7e507ef2b\n" +
                        "            status: test\n" +
                        "            level: critical\n" +
                        "            description: wildcard-single plus space must not emit a raw space\n" +
                        "            author: Test\n" +
                        "            date: 2017/05/15\n" +
                        "            logsource:\n" +
                        "                category: test_category\n" +
                        "                product: test_product\n" +
                        "            detection:\n" +
                        "                sel:\n" +
                        "                    fieldA1|contains: 'hello? world'\n" +
                        "                condition: sel", false));
        String query = queries.get(0).toString();
        // The '?' makes spacedPhraseShape fall through to the wildcard path; interior spaces must still
        // be escaped there so the term is not split into multiple terms. '?' stays a query wildcard.
        Assert.assertFalse("Query must not contain _ws_ token: " + query, query.contains("_ws_"));
        // The value term (everything after "mappedA: ") must not contain a raw (unescaped) space.
        String valueTerm = query.substring(query.indexOf(": ") + 2);
        Assert.assertFalse("Wildcard value term must not contain a raw space: " + query, valueTerm.contains(" ") && !valueTerm.contains("\\ "));
        Assert.assertEquals("mappedA: *hello?\\ world*", query);
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
        // 'regsvr32 ' (trailing space) → contains term *regsvr32\ *; ' /s ' → *\ \/s\ * (leading/trailing
        // spaces preserved and escaped, '/' escaped to \/). 'igfxCPL.cpl' has no space → wildcard path.
        // Exercises applyDeMorgans=true through the spaced contains path (the `not fp1_igfx` branch).
        Assert.assertEquals("((CommandLine: *.cpl) AND ((((NOT CommandLine: *\\\\System32\\\\* AND _exists_: CommandLine) AND " +
                "(NOT CommandLine: *%System%* AND _exists_: CommandLine))))) AND ((((NOT CommandLine: *regsvr32\\ * AND _exists_: CommandLine) OR " +
                "(NOT CommandLine: *\\ \\/s\\ * AND _exists_: CommandLine) OR (NOT CommandLine: *igfxCPL.cpl* AND _exists_: CommandLine))))", queries.get(0).toString());
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
        // c-useragent|startswith: 'Microsoft BITS/' — space must be backslash-escaped, '/' escaped,
        // trailing wildcard from startswith. c-useragent is not in testFieldMapping so passes through.
        String proxyQuery = queries.get(0).toString();
        Assert.assertFalse("Proxy rule query must not contain _ws_ token: " + proxyQuery,
                proxyQuery.contains("_ws_"));
        Assert.assertTrue("Proxy rule startswith query must contain escaped-space term: " + proxyQuery,
                proxyQuery.contains("Microsoft\\ BITS\\/"));
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

    public void testConvertUnboundWildcardWithWhitespace() throws IOException, SigmaError, CompositeSigmaErrors {
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
                        "                keywords:\n" +
                        "                     - 'select * '\n" +
                        "                     - '*evil*'\n" +
                        "                condition: keywords", false));
        String query = queries.get(0).toString();
        // Wildcard adjacent to whitespace must be quoted (literal '*'); no bare '*' term, no _ws_.
        Assert.assertEquals("(\"select * \") OR (*evil*)", query);
        Assert.assertFalse(query.contains("(select * )"));
        Assert.assertFalse(query.contains("_ws_"));
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

    public void testConvertValueRegexWithWhitespace() throws IOException, SigmaError, CompositeSigmaErrors {
        OSQueryBackend queryBackend = testBackend();
        List<Object> queries = queryBackend.convertRule(SigmaRule.fromYaml(
                "            title: Test\n" +
                        "            id: 39f919f3-980b-4e6f-a975-8af7e507ef2b\n" +
                        "            status: test\n" +
                        "            level: critical\n" +
                        "            description: Regex with whitespace test\n" +
                        "            author: Test\n" +
                        "            date: 2024/01/01\n" +
                        "            logsource:\n" +
                        "                category: test_category\n" +
                        "                product: test_product\n" +
                        "            detection:\n" +
                        "                sel:\n" +
                        "                    fieldA1|re: 'This is a pattern'\n" +
                        "                condition: sel", false));
        String query = queries.get(0).toString();
        // Regex terms bypass the analyzer pipeline; spaces are stored and emitted as literal
        // characters in Lucene regexp syntax (/.../). No _ws_ encoding and no backslash escaping
        // needed: space is not a metacharacter in Lucene regexp.
        Assert.assertFalse("Regex query must not contain the _ws_ whitespace token: " + query, query.contains("_ws_"));
        Assert.assertEquals("mappedA: /This is a pattern/", query);
    }

    public void testBucketLevelQueryContainsNoWsToken() throws IOException, SigmaError, CompositeSigmaErrors {
        OSQueryBackend queryBackend = testBackend();
        List<Object> queries = queryBackend.convertRule(SigmaRule.fromYaml(
                "            title: Test\n" +
                        "            id: 39f919f3-980b-4e6f-a975-8af7e507ef2b\n" +
                        "            status: test\n" +
                        "            level: critical\n" +
                        "            description: Bucket-level _ws_ leak check\n" +
                        "            author: Test\n" +
                        "            date: 2024/01/01\n" +
                        "            logsource:\n" +
                        "                category: test_category\n" +
                        "                product: test_product\n" +
                        "            detection:\n" +
                        "                sel:\n" +
                        "                    fieldA1|contains: this is a test\n" +
                        "                condition: sel", false));
        String query = queries.get(0).toString();
        // Bucket-level path runs queryStringQuery against the customer ingest index
        // which has NO rule_ws_filter. _ws_ must never appear in the generated query.
        Assert.assertFalse("Generated query must not contain _ws_ token for bucket-level path: " + query, query.contains("_ws_"));
    }

    private OSQueryBackend testBackend() throws IOException {
        return new OSQueryBackend(testFieldMapping, false, true);
    }
}