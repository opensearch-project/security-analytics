/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.securityanalytics.rules.backend;

import java.util.Locale;
import org.apache.commons.lang3.NotImplementedException;
import org.opensearch.search.aggregations.AggregationBuilder;
import org.opensearch.search.aggregations.bucket.terms.TermsAggregationBuilder;
import org.opensearch.search.aggregations.metrics.AvgAggregationBuilder;
import org.opensearch.search.aggregations.metrics.MaxAggregationBuilder;
import org.opensearch.search.aggregations.metrics.MedianAbsoluteDeviationAggregationBuilder;
import org.opensearch.search.aggregations.metrics.MinAggregationBuilder;
import org.opensearch.search.aggregations.metrics.SumAggregationBuilder;
import org.opensearch.search.aggregations.metrics.ValueCountAggregationBuilder;

public final class AggregationBuilders {

    /**
     * Finds the builder aggregation based on the forwarded function
     *
     * @param aggregationFunction Aggregation function
     * @param name                Name of the aggregation
     * @return Aggregation builder
     */
    public static AggregationBuilder getAggregationBuilderByFunction(String aggregationFunction, String name) {
        AggregationBuilder aggregationBuilder;
        switch (aggregationFunction.toLowerCase(Locale.ROOT)) {
            case AvgAggregationBuilder.NAME:
                aggregationBuilder = new AvgAggregationBuilder(name).field(name);
                break;
            case MaxAggregationBuilder.NAME:
                aggregationBuilder = new MaxAggregationBuilder(name).field(name);
                break;
            case MedianAbsoluteDeviationAggregationBuilder.NAME:
                aggregationBuilder = new MedianAbsoluteDeviationAggregationBuilder(name).field(name);
                break;
            case MinAggregationBuilder.NAME:
                aggregationBuilder = new MinAggregationBuilder(name).field(name);
                break;
            case SumAggregationBuilder.NAME:
                aggregationBuilder = new SumAggregationBuilder(name).field(name);
                break;
            case TermsAggregationBuilder.NAME:
                aggregationBuilder = new TermsAggregationBuilder(name).field(name);
                break;
            case "count":
                aggregationBuilder = new ValueCountAggregationBuilder(name.replace(".", "_")).field(name);
                break;
            default:
                throw new NotImplementedException(String.format(Locale.getDefault(), "Aggregation %s not supported by the backend", aggregationFunction));
        }
        return aggregationBuilder;
    }
}
