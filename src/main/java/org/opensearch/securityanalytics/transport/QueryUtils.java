/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.securityanalytics.transport;

import org.apache.lucene.search.BooleanClause;
import org.opensearch.index.query.BoostingQueryBuilder;
import org.opensearch.index.query.GeoShapeQueryBuilder;
import org.opensearch.index.query.InnerHitBuilder;
import org.opensearch.index.query.MoreLikeThisQueryBuilder;
import org.opensearch.index.query.NestedQueryBuilder;
import org.opensearch.index.query.QueryBuilder;
import org.opensearch.index.query.QueryBuilderVisitor;
import org.opensearch.index.query.TermsQueryBuilder;
import org.opensearch.index.query.WrapperQueryBuilder;
import org.opensearch.index.query.functionscore.FunctionScoreQueryBuilder;
import org.opensearch.index.query.functionscore.ScriptScoreQueryBuilder;
import org.opensearch.search.aggregations.AggregationBuilder;
import org.opensearch.search.aggregations.AggregatorFactories;
import org.opensearch.search.aggregations.bucket.adjacency.AdjacencyMatrixAggregationBuilder;
import org.opensearch.search.aggregations.bucket.filter.FilterAggregationBuilder;
import org.opensearch.search.aggregations.bucket.filter.FiltersAggregationBuilder;
import org.opensearch.search.aggregations.bucket.filter.FiltersAggregator;
import org.opensearch.search.aggregations.bucket.terms.SignificantTermsAggregationBuilder;
import org.opensearch.search.aggregations.bucket.terms.SignificantTextAggregationBuilder;
import org.opensearch.search.aggregations.metrics.TopHitsAggregationBuilder;
import org.opensearch.search.builder.SearchSourceBuilder;
import org.opensearch.search.collapse.CollapseBuilder;
import org.opensearch.search.fetch.subphase.highlight.HighlightBuilder;
import org.opensearch.search.rescore.QueryRescorerBuilder;
import org.opensearch.search.rescore.RescorerBuilder;
import org.opensearch.search.sort.FieldSortBuilder;
import org.opensearch.search.sort.GeoDistanceSortBuilder;
import org.opensearch.search.sort.NestedSortBuilder;
import org.opensearch.search.sort.ScriptSortBuilder;
import org.opensearch.search.sort.SortBuilder;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.IdentityHashMap;
import java.util.List;
import java.util.Set;

/**
 * Utility methods for inspecting query trees for security-sensitive patterns.
 * Uses the framework's QueryBuilderVisitor to traverse all sub-queries generically,
 * ensuring complete coverage of all query types including future additions.
 */
public class QueryUtils {

    /** Queries matched by name, because their classes live in modules that are not on this plugin's classpath. */
    private static final Set<String> FETCHING_QUERY_NAMES = Set.of("percolate", "has_child", "has_parent");

    private QueryUtils() {}

    /**
     * Checks if a query tree contains any TermsQueryBuilder with a termsLookup
     * (i.e., a cross-index terms lookup that could be used to probe data in unauthorized indices).
     * Uses QueryBuilder.visit() for complete traversal of all query types.
     */
    public static boolean containsTermsLookup(QueryBuilder query) {
        if (query == null) {
            return false;
        }

        TermsLookupDetector detector = new TermsLookupDetector();
        query.visit(detector);
        return detector.found;
    }

    /**
     * Checks if a query tree reads documents other than the ones it searches while it is rewritten. It refuses a terms
     * lookup, a more like this query with like or unlike documents, a geo shape query with an indexed shape, a wrapper
     * query (its inner query is not visible before the rewrite), and percolate, has_child and has_parent queries. Every
     * child is checked, including function score filters and the queries of boosting, script score and nested inner
     * hits.
     *
     * @param query the query to check, or null
     * @return true when the query reads other documents
     */
    public static boolean containsDocumentFetch(QueryBuilder query) {
        return new DocumentFetchScanner().query(query);
    }

    /**
     * Checks every query a search source carries: the query, the post filter, the aggregations and their sub
     * aggregations (filter, filters, adjacency matrix, significant terms and text background filters, top hits sorts
     * and highlight), the rescore queries, the nested filters of the sorts, the highlight queries and the inner hits of
     * a collapse. A source with suggestions is refused as a whole, because a phrase suggester can collate with a query
     * template.
     *
     * @param source the search source to check, or null
     * @return true when some part of the source reads other documents
     */
    public static boolean sourceContainsDocumentFetch(SearchSourceBuilder source) {
        return new DocumentFetchScanner().source(source);
    }

    private static class TermsLookupDetector implements QueryBuilderVisitor {
        boolean found = false;

        @Override
        public void accept(QueryBuilder qb) {
            if (qb instanceof TermsQueryBuilder) {
                if (((TermsQueryBuilder) qb).termsLookup() != null) {
                    found = true;
                }
            }
        }

        @Override
        public QueryBuilderVisitor getChildVisitor(BooleanClause.Occur occur) {
            return this;
        }
    }

    /** Walks every query in a tree or a search source. Each query is checked once. */
    private static final class DocumentFetchScanner {
        private final Set<Object> seen = Collections.newSetFromMap(new IdentityHashMap<>());

        boolean query(QueryBuilder qb) {
            if (qb == null || !seen.add(qb)) {
                return false;
            }
            if (fetches(qb)) {
                return true;
            }
            // Core hands some children to the visitor without visiting them, so each child is walked on its own.
            List<QueryBuilder> children = new ArrayList<>();
            qb.visit(new QueryBuilderVisitor() {
                @Override
                public void accept(QueryBuilder child) {
                    if (child != qb) {
                        children.add(child);
                    }
                }

                @Override
                public QueryBuilderVisitor getChildVisitor(BooleanClause.Occur occur) {
                    return this;
                }
            });
            if (qb instanceof FunctionScoreQueryBuilder functionScore) {
                children.add(functionScore.query());
                for (FunctionScoreQueryBuilder.FilterFunctionBuilder function : functionScore.filterFunctionBuilders()) {
                    children.add(function.getFilter());
                }
            } else if (qb instanceof BoostingQueryBuilder boosting) {
                children.add(boosting.positiveQuery());
                children.add(boosting.negativeQuery());
            } else if (qb instanceof ScriptScoreQueryBuilder scriptScore) {
                children.add(scriptScore.query());
            } else if (qb instanceof NestedQueryBuilder nested && innerHit(nested.innerHit())) {
                return true;
            }
            for (QueryBuilder child : children) {
                if (query(child)) {
                    return true;
                }
            }
            return false;
        }

        boolean source(SearchSourceBuilder source) {
            if (source == null) {
                return false;
            }
            if (source.suggest() != null) {
                return true;
            }
            if (query(source.query()) || query(source.postFilter())) {
                return true;
            }
            AggregatorFactories.Builder aggregations = source.aggregations();
            if (aggregations != null && aggregations(aggregations.getAggregatorFactories())) {
                return true;
            }
            if (source.rescores() != null) {
                for (RescorerBuilder<?> rescorer : source.rescores()) {
                    if (rescorer instanceof QueryRescorerBuilder queryRescorer && query(queryRescorer.getRescoreQuery())) {
                        return true;
                    }
                }
            }
            return sorts(source.sorts()) || highlight(source.highlighter()) || collapse(source.collapse());
        }

        private boolean aggregations(Collection<AggregationBuilder> aggregations) {
            if (aggregations == null) {
                return false;
            }
            for (AggregationBuilder aggregation : aggregations) {
                if (aggregation instanceof FilterAggregationBuilder filter && query(filter.getFilter())) {
                    return true;
                }
                if (aggregation instanceof FiltersAggregationBuilder filters) {
                    for (FiltersAggregator.KeyedFilter keyed : filters.filters()) {
                        if (query(keyed.filter())) {
                            return true;
                        }
                    }
                }
                if (aggregation instanceof AdjacencyMatrixAggregationBuilder matrix) {
                    for (QueryBuilder filter : matrix.filters().values()) {
                        if (query(filter)) {
                            return true;
                        }
                    }
                }
                if (aggregation instanceof SignificantTermsAggregationBuilder terms && query(terms.backgroundFilter())) {
                    return true;
                }
                if (aggregation instanceof SignificantTextAggregationBuilder text && query(text.backgroundFilter())) {
                    return true;
                }
                if (aggregation instanceof TopHitsAggregationBuilder topHits && (sorts(topHits.sorts()) || highlight(topHits.highlighter()))) {
                    return true;
                }
                if (aggregations(aggregation.getSubAggregations())) {
                    return true;
                }
            }
            return false;
        }

        private boolean sorts(List<SortBuilder<?>> sorts) {
            if (sorts == null) {
                return false;
            }
            for (SortBuilder<?> sort : sorts) {
                QueryBuilder nestedFilter = null;
                NestedSortBuilder nestedSort = null;
                if (sort instanceof FieldSortBuilder field) {
                    nestedFilter = field.getNestedFilter();
                    nestedSort = field.getNestedSort();
                } else if (sort instanceof GeoDistanceSortBuilder geo) {
                    nestedFilter = geo.getNestedFilter();
                    nestedSort = geo.getNestedSort();
                } else if (sort instanceof ScriptSortBuilder script) {
                    nestedFilter = script.getNestedFilter();
                    nestedSort = script.getNestedSort();
                }
                if (query(nestedFilter)) {
                    return true;
                }
                for (NestedSortBuilder level = nestedSort; level != null; level = level.getNestedSort()) {
                    if (query(level.getFilter())) {
                        return true;
                    }
                }
            }
            return false;
        }

        private boolean highlight(HighlightBuilder highlight) {
            if (highlight == null) {
                return false;
            }
            if (query(highlight.highlightQuery())) {
                return true;
            }
            for (HighlightBuilder.Field field : highlight.fields()) {
                if (query(field.highlightQuery())) {
                    return true;
                }
            }
            return false;
        }

        private boolean collapse(CollapseBuilder collapse) {
            if (collapse == null || collapse.getInnerHits() == null) {
                return false;
            }
            for (InnerHitBuilder innerHit : collapse.getInnerHits()) {
                if (innerHit(innerHit)) {
                    return true;
                }
            }
            return false;
        }

        private boolean innerHit(InnerHitBuilder innerHit) {
            if (innerHit == null) {
                return false;
            }
            return sorts(innerHit.getSorts()) || highlight(innerHit.getHighlightBuilder()) || collapse(innerHit.getInnerCollapseBuilder());
        }

        private static boolean fetches(QueryBuilder qb) {
            if (qb instanceof TermsQueryBuilder terms) {
                return terms.termsLookup() != null;
            }
            if (qb instanceof MoreLikeThisQueryBuilder mlt) {
                return mlt.likeItems().length > 0 || mlt.unlikeItems().length > 0;
            }
            if (qb instanceof GeoShapeQueryBuilder geoShape) {
                return geoShape.indexedShapeId() != null;
            }
            return qb instanceof WrapperQueryBuilder || FETCHING_QUERY_NAMES.contains(qb.getWriteableName());
        }
    }
}
