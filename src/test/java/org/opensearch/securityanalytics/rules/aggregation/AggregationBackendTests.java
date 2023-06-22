/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.securityanalytics.rules.aggregation;

import org.junit.Assert;
import org.opensearch.securityanalytics.rules.backend.OSQueryBackend;
import org.opensearch.securityanalytics.rules.exceptions.SigmaError;
import org.opensearch.securityanalytics.rules.objects.SigmaRule;
import org.opensearch.test.OpenSearchTestCase;

import java.io.IOException;
import java.util.List;

public class AggregationBackendTests extends OpenSearchTestCase {

    public void testCountAggregation() throws SigmaError, IOException {
        OSQueryBackend queryBackend = new OSQueryBackend("windows", true, true);
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
                "                condition: sel | count(*) > 1", true));

        String query = queries.get(0).toString();
        Assert.assertEquals("(fieldA: \"valueA\") AND (mappedB: \"valueB\") AND (fieldC: \"valueC\")", query);

        OSQueryBackend.AggregationQueries aggQueries = (OSQueryBackend.AggregationQueries) queries.get(1);
        String aggQuery = aggQueries.getAggQuery();
        String bucketTriggerQuery = aggQueries.getBucketTriggerQuery();

        Assert.assertEquals("{\"result_agg\":{\"terms\":{\"field\":\"_index\"}}}", aggQuery);
        Assert.assertEquals("{\"buckets_path\":{\"_cnt\":\"_count\"},\"parent_bucket_path\":\"result_agg\",\"script\":{\"source\":\"params._cnt > 1.0\",\"lang\":\"painless\"}}", bucketTriggerQuery);
    }

    public void testCountAggregationWithGroupBy() throws IOException, SigmaError {
        OSQueryBackend queryBackend = new OSQueryBackend("windows", true, true);
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
                "                condition: sel | count(*) by fieldB > 1", true));

        String query = queries.get(0).toString();
        Assert.assertEquals("(fieldA: \"valueA\") AND (mappedB: \"valueB\") AND (fieldC: \"valueC\")", query);

        OSQueryBackend.AggregationQueries aggQueries = (OSQueryBackend.AggregationQueries) queries.get(1);
        String aggQuery = aggQueries.getAggQuery();
        String bucketTriggerQuery = aggQueries.getBucketTriggerQuery();

        Assert.assertEquals("{\"result_agg\":{\"terms\":{\"field\":\"fieldB\"}}}", aggQuery);
        Assert.assertEquals("{\"buckets_path\":{\"_cnt\":\"_count\"},\"parent_bucket_path\":\"result_agg\",\"script\":{\"source\":\"params._cnt > 1.0\",\"lang\":\"painless\"}}", bucketTriggerQuery);
    }

    public void testSumAggregationWithGroupBy() throws IOException, SigmaError {
        OSQueryBackend queryBackend = new OSQueryBackend("windows", true, true);
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
                "                condition: sel | sum(fieldA) by fieldB > 110", true));

        String query = queries.get(0).toString();
        Assert.assertEquals("(fieldA: \"valueA\") AND (mappedB: \"valueB\") AND (fieldC: \"valueC\")", query);

        OSQueryBackend.AggregationQueries aggQueries = (OSQueryBackend.AggregationQueries) queries.get(1);
        String aggQuery = aggQueries.getAggQuery();
        String bucketTriggerQuery = aggQueries.getBucketTriggerQuery();


        // inputs.query.aggregations -> Query
        Assert.assertEquals("{\"result_agg\":{\"terms\":{\"field\":\"fieldB\"},\"aggs\":{\"fieldA\":{\"sum\":{\"field\":\"fieldA\"}}}}}", aggQuery);
        // triggers.bucket_level_trigger.condition -> Condition
        Assert.assertEquals("{\"buckets_path\":{\"fieldA\":\"fieldA\"},\"parent_bucket_path\":\"result_agg\",\"script\":{\"source\":\"params.fieldA > 110.0\",\"lang\":\"painless\"}}", bucketTriggerQuery);
    }

    public void testMinAggregationWithGroupBy() throws IOException, SigmaError {
        OSQueryBackend queryBackend = new OSQueryBackend("windows", true, true);
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
                        "                condition: sel | min(fieldA) by fieldB > 110", true));

        String query = queries.get(0).toString();
        Assert.assertEquals("(fieldA: \"valueA\") AND (mappedB: \"valueB\") AND (fieldC: \"valueC\")", query);

        OSQueryBackend.AggregationQueries aggQueries = (OSQueryBackend.AggregationQueries) queries.get(1);
        String aggQuery = aggQueries.getAggQuery();
        String bucketTriggerQuery = aggQueries.getBucketTriggerQuery();

        Assert.assertEquals("{\"result_agg\":{\"terms\":{\"field\":\"fieldB\"},\"aggs\":{\"fieldA\":{\"min\":{\"field\":\"fieldA\"}}}}}", aggQuery);
        Assert.assertEquals("{\"buckets_path\":{\"fieldA\":\"fieldA\"},\"parent_bucket_path\":\"result_agg\",\"script\":{\"source\":\"params.fieldA > 110.0\",\"lang\":\"painless\"}}", bucketTriggerQuery);
    }

    public void testMaxAggregationWithGroupBy() throws IOException, SigmaError {
        OSQueryBackend queryBackend = new OSQueryBackend("windows", true, true);
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
                        "                condition: sel | max(fieldA) by fieldB > 110", true));

        String query = queries.get(0).toString();
        Assert.assertEquals("(fieldA: \"valueA\") AND (mappedB: \"valueB\") AND (fieldC: \"valueC\")", query);

        OSQueryBackend.AggregationQueries aggQueries = (OSQueryBackend.AggregationQueries) queries.get(1);
        String aggQuery = aggQueries.getAggQuery();
        String bucketTriggerQuery = aggQueries.getBucketTriggerQuery();

        Assert.assertEquals("{\"result_agg\":{\"terms\":{\"field\":\"fieldB\"},\"aggs\":{\"fieldA\":{\"max\":{\"field\":\"fieldA\"}}}}}", aggQuery);
        Assert.assertEquals("{\"buckets_path\":{\"fieldA\":\"fieldA\"},\"parent_bucket_path\":\"result_agg\",\"script\":{\"source\":\"params.fieldA > 110.0\",\"lang\":\"painless\"}}", bucketTriggerQuery);
    }

    public void testAvgAggregationWithGroupBy() throws IOException, SigmaError {
        OSQueryBackend queryBackend = new OSQueryBackend("windows", true, true);
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
                        "                condition: sel | avg(fieldA) by fieldB > 110", true));

        String query = queries.get(0).toString();
        Assert.assertEquals("(fieldA: \"valueA\") AND (mappedB: \"valueB\") AND (fieldC: \"valueC\")", query);

        OSQueryBackend.AggregationQueries aggQueries = (OSQueryBackend.AggregationQueries) queries.get(1);
        String aggQuery = aggQueries.getAggQuery();
        String bucketTriggerQuery = aggQueries.getBucketTriggerQuery();

        Assert.assertEquals("{\"result_agg\":{\"terms\":{\"field\":\"fieldB\"},\"aggs\":{\"fieldA\":{\"avg\":{\"field\":\"fieldA\"}}}}}", aggQuery);
        Assert.assertEquals("{\"buckets_path\":{\"fieldA\":\"fieldA\"},\"parent_bucket_path\":\"result_agg\",\"script\":{\"source\":\"params.fieldA > 110.0\",\"lang\":\"painless\"}}", bucketTriggerQuery);
    }
}
