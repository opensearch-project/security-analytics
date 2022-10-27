package org.opensearch.securityanalytics.rules.backend;

import org.opensearch.search.aggregations.AggregationBuilder;
import org.opensearch.search.aggregations.bucket.histogram.AutoDateHistogramAggregationBuilder;
import org.opensearch.search.aggregations.bucket.histogram.DateHistogramAggregationBuilder;
import org.opensearch.search.aggregations.bucket.histogram.HistogramAggregationBuilder;
import org.opensearch.search.aggregations.bucket.histogram.VariableWidthHistogramAggregationBuilder;
import org.opensearch.search.aggregations.bucket.range.DateRangeAggregationBuilder;
import org.opensearch.search.aggregations.bucket.range.GeoDistanceAggregationBuilder;
import org.opensearch.search.aggregations.bucket.range.IpRangeAggregationBuilder;
import org.opensearch.search.aggregations.bucket.range.RangeAggregationBuilder;
import org.opensearch.search.aggregations.bucket.sampler.DiversifiedAggregationBuilder;
import org.opensearch.search.aggregations.bucket.terms.RareTermsAggregationBuilder;
import org.opensearch.search.aggregations.bucket.terms.SignificantTermsAggregationBuilder;
import org.opensearch.search.aggregations.bucket.terms.TermsAggregationBuilder;
import org.opensearch.search.aggregations.metrics.AvgAggregationBuilder;
import org.opensearch.search.aggregations.metrics.CardinalityAggregationBuilder;
import org.opensearch.search.aggregations.metrics.ExtendedStatsAggregationBuilder;
import org.opensearch.search.aggregations.metrics.GeoCentroidAggregationBuilder;
import org.opensearch.search.aggregations.metrics.MaxAggregationBuilder;
import org.opensearch.search.aggregations.metrics.MedianAbsoluteDeviationAggregationBuilder;
import org.opensearch.search.aggregations.metrics.MinAggregationBuilder;
import org.opensearch.search.aggregations.metrics.PercentileRanksAggregationBuilder;
import org.opensearch.search.aggregations.metrics.PercentilesAggregationBuilder;
import org.opensearch.search.aggregations.metrics.StatsAggregationBuilder;
import org.opensearch.search.aggregations.metrics.SumAggregationBuilder;
import org.opensearch.search.aggregations.metrics.ValueCountAggregationBuilder;
public final class AggregationBuilders {

    /**
     * Finds the builder aggregation based on the forwarded function
     *
     * @param aggregationFunction - aggregation function
     * @param name - name of the aggregation
     * @return
     */
    public static AggregationBuilder getAggregationBuilderByFunction(String aggregationFunction, String name){
        AggregationBuilder aggregationBuilder;
        switch (aggregationFunction){
            case AutoDateHistogramAggregationBuilder.NAME:
                aggregationBuilder = new AutoDateHistogramAggregationBuilder(name).field(name);
                break;
            case AvgAggregationBuilder.NAME:
                aggregationBuilder = new AvgAggregationBuilder(name).field(name);
                break;
            case CardinalityAggregationBuilder.NAME:
                aggregationBuilder = new CardinalityAggregationBuilder(name).field(name);
                break;
            case DateHistogramAggregationBuilder.NAME:
                aggregationBuilder = new DateHistogramAggregationBuilder(name).field(name);
                break;
            case DateRangeAggregationBuilder.NAME:
                aggregationBuilder = new DateRangeAggregationBuilder(name).field(name);
                break;
            case DiversifiedAggregationBuilder.NAME:
                aggregationBuilder = new DiversifiedAggregationBuilder(name).field(name);
                break;
            case ExtendedStatsAggregationBuilder.NAME:
                aggregationBuilder = new ExtendedStatsAggregationBuilder(name).field(name);
                break;
            case GeoCentroidAggregationBuilder.NAME:
                aggregationBuilder = new GeoCentroidAggregationBuilder(name).field(name);
                break;
                // TODO ?
            case GeoDistanceAggregationBuilder.NAME:
                aggregationBuilder = new GeoDistanceAggregationBuilder(name, null).field(name);
                break;
            case HistogramAggregationBuilder.NAME:
                aggregationBuilder = new HistogramAggregationBuilder(name).field(name);
                break;
            case IpRangeAggregationBuilder.NAME:
                aggregationBuilder = new IpRangeAggregationBuilder(name).field(name);
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
                // TODO - do we need this?
            case PercentileRanksAggregationBuilder.NAME:
                aggregationBuilder = new PercentileRanksAggregationBuilder(name, null).field(name);
                break;
            case PercentilesAggregationBuilder.NAME:
                aggregationBuilder = new PercentilesAggregationBuilder(name).field(name);
                break;
            case RangeAggregationBuilder.NAME:
                aggregationBuilder = new RangeAggregationBuilder(name).field(name);
                break;
            case RareTermsAggregationBuilder.NAME:
                aggregationBuilder = new RareTermsAggregationBuilder(name).field(name);
                break;
            case SignificantTermsAggregationBuilder.NAME:
                aggregationBuilder = new SignificantTermsAggregationBuilder(name).field(name);
                break;
            case StatsAggregationBuilder.NAME:
                aggregationBuilder = new StatsAggregationBuilder(name).field(name);
                break;
            case SumAggregationBuilder.NAME:
                aggregationBuilder = new SumAggregationBuilder(name).field(name);
                break;
            case TermsAggregationBuilder.NAME:
                aggregationBuilder = new TermsAggregationBuilder(name).field(name);
                break;
            case ValueCountAggregationBuilder.NAME:
                aggregationBuilder = new ValueCountAggregationBuilder(name).field(name);
                break;
            case VariableWidthHistogramAggregationBuilder.NAME:
                aggregationBuilder = new VariableWidthHistogramAggregationBuilder(name).field(name);
                break;
            default: return null;
        }
        return aggregationBuilder;
    }
}
