/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.securityanalytics.rules.aggregation;

import static java.util.stream.Collectors.toList;

import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;
import java.util.ServiceLoader;
import java.util.function.Function;
import java.util.stream.Collectors;
import java.util.stream.Stream;
import org.junit.Assert;
import org.opensearch.client.RestClient;
import org.opensearch.cluster.ClusterModule;
import org.opensearch.common.CheckedConsumer;
import org.opensearch.common.ParseField;
import org.opensearch.common.xcontent.ContextParser;
import org.opensearch.common.xcontent.LoggingDeprecationHandler;
import org.opensearch.common.xcontent.NamedXContentRegistry;
import org.opensearch.common.xcontent.XContentFactory;
import org.opensearch.common.xcontent.XContentParser;
import org.opensearch.common.xcontent.XContentParser.Token;
import org.opensearch.common.xcontent.XContentParserUtils;
import org.opensearch.common.xcontent.XContentType;
import org.opensearch.plugins.SearchPlugin.AggregationSpec;
import org.opensearch.plugins.spi.NamedXContentProvider;
import org.opensearch.search.aggregations.Aggregation;
import org.opensearch.search.aggregations.AggregatorFactories;
import org.opensearch.search.aggregations.BaseAggregationBuilder;
import org.opensearch.search.aggregations.bucket.adjacency.AdjacencyMatrixAggregationBuilder;
import org.opensearch.search.aggregations.bucket.adjacency.ParsedAdjacencyMatrix;
import org.opensearch.search.aggregations.bucket.composite.CompositeAggregationBuilder;
import org.opensearch.search.aggregations.bucket.composite.ParsedComposite;
import org.opensearch.search.aggregations.bucket.filter.FilterAggregationBuilder;
import org.opensearch.search.aggregations.bucket.filter.FiltersAggregationBuilder;
import org.opensearch.search.aggregations.bucket.filter.ParsedFilter;
import org.opensearch.search.aggregations.bucket.filter.ParsedFilters;
import org.opensearch.search.aggregations.bucket.global.GlobalAggregationBuilder;
import org.opensearch.search.aggregations.bucket.global.ParsedGlobal;
import org.opensearch.search.aggregations.bucket.histogram.AutoDateHistogramAggregationBuilder;
import org.opensearch.search.aggregations.bucket.histogram.DateHistogramAggregationBuilder;
import org.opensearch.search.aggregations.bucket.histogram.HistogramAggregationBuilder;
import org.opensearch.search.aggregations.bucket.histogram.ParsedAutoDateHistogram;
import org.opensearch.search.aggregations.bucket.histogram.ParsedDateHistogram;
import org.opensearch.search.aggregations.bucket.histogram.ParsedHistogram;
import org.opensearch.search.aggregations.bucket.histogram.ParsedVariableWidthHistogram;
import org.opensearch.search.aggregations.bucket.histogram.VariableWidthHistogramAggregationBuilder;
import org.opensearch.search.aggregations.bucket.missing.MissingAggregationBuilder;
import org.opensearch.search.aggregations.bucket.missing.ParsedMissing;
import org.opensearch.search.aggregations.bucket.nested.NestedAggregationBuilder;
import org.opensearch.search.aggregations.bucket.nested.ParsedNested;
import org.opensearch.search.aggregations.bucket.nested.ParsedReverseNested;
import org.opensearch.search.aggregations.bucket.nested.ReverseNestedAggregationBuilder;
import org.opensearch.search.aggregations.bucket.range.DateRangeAggregationBuilder;
import org.opensearch.search.aggregations.bucket.range.GeoDistanceAggregationBuilder;
import org.opensearch.search.aggregations.bucket.range.IpRangeAggregationBuilder;
import org.opensearch.search.aggregations.bucket.range.ParsedBinaryRange;
import org.opensearch.search.aggregations.bucket.range.ParsedDateRange;
import org.opensearch.search.aggregations.bucket.range.ParsedGeoDistance;
import org.opensearch.search.aggregations.bucket.range.ParsedRange;
import org.opensearch.search.aggregations.bucket.range.RangeAggregationBuilder;
import org.opensearch.search.aggregations.bucket.sampler.InternalSampler;
import org.opensearch.search.aggregations.bucket.sampler.ParsedSampler;
import org.opensearch.search.aggregations.bucket.terms.DoubleTerms;
import org.opensearch.search.aggregations.bucket.terms.LongRareTerms;
import org.opensearch.search.aggregations.bucket.terms.LongTerms;
import org.opensearch.search.aggregations.bucket.terms.MultiTermsAggregationBuilder;
import org.opensearch.search.aggregations.bucket.terms.ParsedDoubleTerms;
import org.opensearch.search.aggregations.bucket.terms.ParsedLongRareTerms;
import org.opensearch.search.aggregations.bucket.terms.ParsedLongTerms;
import org.opensearch.search.aggregations.bucket.terms.ParsedMultiTerms;
import org.opensearch.search.aggregations.bucket.terms.ParsedSignificantLongTerms;
import org.opensearch.search.aggregations.bucket.terms.ParsedSignificantStringTerms;
import org.opensearch.search.aggregations.bucket.terms.ParsedStringRareTerms;
import org.opensearch.search.aggregations.bucket.terms.ParsedStringTerms;
import org.opensearch.search.aggregations.bucket.terms.SignificantLongTerms;
import org.opensearch.search.aggregations.bucket.terms.SignificantStringTerms;
import org.opensearch.search.aggregations.bucket.terms.StringRareTerms;
import org.opensearch.search.aggregations.bucket.terms.StringTerms;
import org.opensearch.search.aggregations.metrics.AvgAggregationBuilder;
import org.opensearch.search.aggregations.metrics.CardinalityAggregationBuilder;
import org.opensearch.search.aggregations.metrics.ExtendedStatsAggregationBuilder;
import org.opensearch.search.aggregations.metrics.GeoCentroidAggregationBuilder;
import org.opensearch.search.aggregations.metrics.InternalAvg;
import org.opensearch.search.aggregations.metrics.InternalHDRPercentileRanks;
import org.opensearch.search.aggregations.metrics.InternalHDRPercentiles;
import org.opensearch.search.aggregations.metrics.InternalTDigestPercentileRanks;
import org.opensearch.search.aggregations.metrics.InternalTDigestPercentiles;
import org.opensearch.search.aggregations.metrics.InternalValueCount;
import org.opensearch.search.aggregations.metrics.MaxAggregationBuilder;
import org.opensearch.search.aggregations.metrics.MedianAbsoluteDeviationAggregationBuilder;
import org.opensearch.search.aggregations.metrics.MinAggregationBuilder;
import org.opensearch.search.aggregations.metrics.ParsedAvg;
import org.opensearch.search.aggregations.metrics.ParsedCardinality;
import org.opensearch.search.aggregations.metrics.ParsedExtendedStats;
import org.opensearch.search.aggregations.metrics.ParsedGeoCentroid;
import org.opensearch.search.aggregations.metrics.ParsedHDRPercentileRanks;
import org.opensearch.search.aggregations.metrics.ParsedHDRPercentiles;
import org.opensearch.search.aggregations.metrics.ParsedMax;
import org.opensearch.search.aggregations.metrics.ParsedMedianAbsoluteDeviation;
import org.opensearch.search.aggregations.metrics.ParsedMin;
import org.opensearch.search.aggregations.metrics.ParsedScriptedMetric;
import org.opensearch.search.aggregations.metrics.ParsedStats;
import org.opensearch.search.aggregations.metrics.ParsedSum;
import org.opensearch.search.aggregations.metrics.ParsedTDigestPercentileRanks;
import org.opensearch.search.aggregations.metrics.ParsedTDigestPercentiles;
import org.opensearch.search.aggregations.metrics.ParsedTopHits;
import org.opensearch.search.aggregations.metrics.ParsedValueCount;
import org.opensearch.search.aggregations.metrics.ParsedWeightedAvg;
import org.opensearch.search.aggregations.metrics.ScriptedMetricAggregationBuilder;
import org.opensearch.search.aggregations.metrics.StatsAggregationBuilder;
import org.opensearch.search.aggregations.metrics.SumAggregationBuilder;
import org.opensearch.search.aggregations.metrics.TopHitsAggregationBuilder;
import org.opensearch.search.aggregations.metrics.ValueCountAggregationBuilder;
import org.opensearch.search.aggregations.metrics.WeightedAvgAggregationBuilder;
import org.opensearch.search.aggregations.pipeline.DerivativePipelineAggregationBuilder;
import org.opensearch.search.aggregations.pipeline.ExtendedStatsBucketPipelineAggregationBuilder;
import org.opensearch.search.aggregations.pipeline.InternalBucketMetricValue;
import org.opensearch.search.aggregations.pipeline.InternalSimpleValue;
import org.opensearch.search.aggregations.pipeline.ParsedBucketMetricValue;
import org.opensearch.search.aggregations.pipeline.ParsedDerivative;
import org.opensearch.search.aggregations.pipeline.ParsedExtendedStatsBucket;
import org.opensearch.search.aggregations.pipeline.ParsedPercentilesBucket;
import org.opensearch.search.aggregations.pipeline.ParsedSimpleValue;
import org.opensearch.search.aggregations.pipeline.ParsedStatsBucket;
import org.opensearch.search.aggregations.pipeline.PercentilesBucketPipelineAggregationBuilder;
import org.opensearch.search.aggregations.pipeline.StatsBucketPipelineAggregationBuilder;
import org.opensearch.search.aggregations.support.ValuesSourceRegistry;
import org.opensearch.search.suggest.Suggest;
import org.opensearch.search.suggest.completion.CompletionSuggestion;
import org.opensearch.search.suggest.completion.CompletionSuggestionBuilder;
import org.opensearch.search.suggest.phrase.PhraseSuggestion;
import org.opensearch.search.suggest.phrase.PhraseSuggestionBuilder;
import org.opensearch.search.suggest.term.TermSuggestion;
import org.opensearch.search.suggest.term.TermSuggestionBuilder;
import org.opensearch.securityanalytics.rules.backend.OSQueryBackend;
import org.opensearch.securityanalytics.rules.exceptions.SigmaError;
import org.opensearch.securityanalytics.rules.objects.SigmaRule;
import org.opensearch.test.OpenSearchTestCase;

import java.io.IOException;
import java.util.List;

public class AggregationBackendTests extends OpenSearchTestCase {

    static List<NamedXContentRegistry.Entry> getDefaultNamedXContents() {
        AggregationSpec aggregationSpec = new AggregationSpec(AvgAggregationBuilder.NAME, AvgAggregationBuilder::new, AvgAggregationBuilder.PARSER)
            .addResultReader(InternalValueCount::new)
            .setAggregatorRegistrar(ValueCountAggregationBuilder::registerAggregators);

        List<NamedXContentRegistry.Entry> entries = Collections.emptyList();
        entries.add(new NamedXContentRegistry.Entry(BaseAggregationBuilder.class, aggregationSpec.getName(), (p, c) -> {
            String name = (String) c;
            return aggregationSpec.getParser().parse(p, name);
        }));
        return entries;
    }
    /**
     * Loads and returns the {@link NamedXContentRegistry.Entry} parsers provided by plugins.
     */
    static List<NamedXContentRegistry.Entry> getProvidedNamedXContents() {
        List<NamedXContentRegistry.Entry> entries = new ArrayList<>();
        for (NamedXContentProvider service : ServiceLoader.load(NamedXContentProvider.class)) {
            entries.addAll(service.getNamedXContentParsers());
        }
        return entries;
    }

    public void testCountAggregation() throws SigmaError, IOException {
        NamedXContentRegistry registry = new NamedXContentRegistry(
            getDefaultNamedXContents()
        );

        XContentParser xcp2 = XContentFactory.xContent(XContentType.JSON)
            .createParser(registry, LoggingDeprecationHandler.INSTANCE,  "{\"avg_cpu\":{\"avg\":{\"field\":\"products.base_price\"}}}");
        //XContentParserUtils.ensureExpectedToken(Token.START_OBJECT, xcp2.nextToken(), xcp2);
//        XContentParserUtils.ensureExpectedToken(Token.FIELD_NAME, xcp2.nextToken(), xcp2);
//        XContentParserUtils.ensureExpectedToken(Token.START_OBJECT, xcp2.nextToken(), xcp2);
        xcp2.nextToken();
        AggregatorFactories.Builder builder = AggregatorFactories.parseAggregators(xcp2);


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

        Assert.assertEquals("\"aggs\":{\"result_agg\":{\"terms\":{\"field\":\"_index\"}}}", aggQuery);
        Assert.assertEquals("{\"buckets_path\":{\"_cnt\":\"_cnt\"},\"parent_bucket_path\":\"result_agg\",\"script\":{\"source\":\"params._cnt > 1.0\",\"lang\":\"painless\"}}", bucketTriggerQuery);
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

        Assert.assertEquals("\"aggs\":{\"result_agg\":{\"terms\":{\"field\":\"fieldB\"}}}", aggQuery);
        Assert.assertEquals("{\"buckets_path\":{\"_cnt\":\"_cnt\"},\"parent_bucket_path\":\"result_agg\",\"script\":{\"source\":\"params._cnt > 1.0\",\"lang\":\"painless\"}}", bucketTriggerQuery);
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
        Assert.assertEquals("\"aggs\":{\"result_agg\":{\"terms\":{\"field\":\"fieldB\"},\"aggs\":{\"fieldA\":{\"sum\":{\"field\":\"fieldA\"}}}}}", aggQuery);
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

        Assert.assertEquals("\"aggs\":{\"result_agg\":{\"terms\":{\"field\":\"fieldB\"},\"aggs\":{\"fieldA\":{\"min\":{\"field\":\"fieldA\"}}}}}", aggQuery);
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

        Assert.assertEquals("\"aggs\":{\"result_agg\":{\"terms\":{\"field\":\"fieldB\"},\"aggs\":{\"fieldA\":{\"max\":{\"field\":\"fieldA\"}}}}}", aggQuery);
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

        Assert.assertEquals("\"aggs\":{\"result_agg\":{\"terms\":{\"field\":\"fieldB\"},\"aggs\":{\"fieldA\":{\"avg\":{\"field\":\"fieldA\"}}}}}", aggQuery);
        Assert.assertEquals("{\"buckets_path\":{\"fieldA\":\"fieldA\"},\"parent_bucket_path\":\"result_agg\",\"script\":{\"source\":\"params.fieldA > 110.0\",\"lang\":\"painless\"}}", bucketTriggerQuery);
    }
}
