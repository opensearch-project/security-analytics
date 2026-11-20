/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.securityanalytics.transport;

import org.opensearch.index.query.BoolQueryBuilder;
import org.opensearch.index.query.GeoShapeQueryBuilder;
import org.opensearch.index.query.MatchAllQueryBuilder;
import org.opensearch.index.query.MoreLikeThisQueryBuilder;
import org.opensearch.index.query.NestedQueryBuilder;
import org.opensearch.index.query.TermsQueryBuilder;
import org.opensearch.index.query.WrapperQueryBuilder;
import org.opensearch.indices.TermsLookup;
import org.opensearch.index.query.BoostingQueryBuilder;
import org.opensearch.index.query.InnerHitBuilder;
import org.opensearch.index.query.functionscore.FunctionScoreQueryBuilder;
import org.opensearch.index.query.functionscore.ScoreFunctionBuilders;
import org.opensearch.index.query.functionscore.ScriptScoreQueryBuilder;
import org.opensearch.script.Script;
import org.opensearch.search.aggregations.AggregationBuilders;
import org.opensearch.search.aggregations.bucket.filter.FiltersAggregator;
import org.opensearch.search.builder.SearchSourceBuilder;
import org.opensearch.search.collapse.CollapseBuilder;
import org.opensearch.search.fetch.subphase.highlight.HighlightBuilder;
import org.opensearch.search.rescore.QueryRescorerBuilder;
import org.opensearch.search.sort.NestedSortBuilder;
import org.opensearch.search.sort.SortBuilders;
import org.opensearch.search.suggest.SuggestBuilder;
import org.opensearch.search.suggest.SuggestBuilders;
import java.util.Map;
import org.opensearch.test.OpenSearchTestCase;
import org.apache.lucene.search.join.ScoreMode;

/** Tests which queries read documents other than the ones they search while they are rewritten. */
public class QueryUtilsDocumentFetchTests extends OpenSearchTestCase {

    public void testAQueryThatOnlySearchesIsAllowed() {
        assertFalse(QueryUtils.containsDocumentFetch(null));
        assertFalse(QueryUtils.containsDocumentFetch(new MatchAllQueryBuilder()));
        assertFalse(QueryUtils.containsDocumentFetch(new TermsQueryBuilder("field", "a", "b")));
        assertFalse(QueryUtils.containsDocumentFetch(new MoreLikeThisQueryBuilder(new String[] { "field" }, new String[] { "text" }, null)));
        assertFalse(QueryUtils.containsDocumentFetch(new GeoShapeQueryBuilder("shape", new org.opensearch.geometry.Point(1, 1))));
    }

    public void testATermsLookupFetches() {
        assertTrue(QueryUtils.containsDocumentFetch(new TermsQueryBuilder("field", new TermsLookup("other", "1", "path"))));
    }

    public void testMoreLikeThisWithLikeOrUnlikeDocumentsFetches() {
        MoreLikeThisQueryBuilder.Item item = new MoreLikeThisQueryBuilder.Item("other", "1");
        assertTrue(QueryUtils.containsDocumentFetch(
                new MoreLikeThisQueryBuilder(new String[] { "field" }, null, new MoreLikeThisQueryBuilder.Item[] { item })));
        assertTrue(QueryUtils.containsDocumentFetch(
                new MoreLikeThisQueryBuilder(new String[] { "field" }, new String[] { "text" }, null)
                        .unlike(new MoreLikeThisQueryBuilder.Item[] { item })));
    }

    public void testAGeoShapeWithAnIndexedShapeFetches() {
        assertTrue(QueryUtils.containsDocumentFetch(new GeoShapeQueryBuilder("shape", "shape-id").indexedShapeIndex("other")));
    }

    public void testAWrapperQueryIsRefused() {
        assertTrue(QueryUtils.containsDocumentFetch(new WrapperQueryBuilder("{\"match_all\":{}}")));
    }

    public void testAFetchNestedInsideOtherQueriesIsFound() {
        TermsQueryBuilder lookup = new TermsQueryBuilder("field", new TermsLookup("other", "1", "path"));
        assertTrue(QueryUtils.containsDocumentFetch(
                new NestedQueryBuilder("rule", new BoolQueryBuilder().must(new MatchAllQueryBuilder()).filter(lookup), ScoreMode.Avg)));
    }

    public void testFetchesInsideFunctionScoreBoostingAndScriptScoreAreFound() {
        assertTrue(QueryUtils.containsDocumentFetch(new FunctionScoreQueryBuilder(new MatchAllQueryBuilder(),
                new FunctionScoreQueryBuilder.FilterFunctionBuilder[] {
                        new FunctionScoreQueryBuilder.FilterFunctionBuilder(lookup(), ScoreFunctionBuilders.weightFactorFunction(2)) })));
        assertTrue(QueryUtils.containsDocumentFetch(new BoolQueryBuilder().must(
                new BoostingQueryBuilder(new MatchAllQueryBuilder(), new BoolQueryBuilder().filter(lookup())))));
        assertTrue(QueryUtils.containsDocumentFetch(new BoolQueryBuilder().should(new ScriptScoreQueryBuilder(
                new BoolQueryBuilder().must(new BoolQueryBuilder().filter(lookup())), new Script("1")))));
        assertFalse(QueryUtils.containsDocumentFetch(new FunctionScoreQueryBuilder(new MatchAllQueryBuilder(),
                new FunctionScoreQueryBuilder.FilterFunctionBuilder[] {
                        new FunctionScoreQueryBuilder.FilterFunctionBuilder(new MatchAllQueryBuilder(),
                                ScoreFunctionBuilders.weightFactorFunction(2)) })));
    }

    public void testANestedInnerHitHighlightQueryIsFound() {
        InnerHitBuilder innerHit = new InnerHitBuilder().setHighlightBuilder(new HighlightBuilder().highlightQuery(lookup()));
        assertTrue(QueryUtils.containsDocumentFetch(new NestedQueryBuilder("rule", new MatchAllQueryBuilder(), ScoreMode.Avg).innerHit(innerHit)));
    }

    public void testAPlainSourceIsAllowed() {
        assertFalse(QueryUtils.sourceContainsDocumentFetch(null));
        assertFalse(QueryUtils.sourceContainsDocumentFetch(new SearchSourceBuilder().query(new MatchAllQueryBuilder())
                .postFilter(new MatchAllQueryBuilder())
                .aggregation(AggregationBuilders.filter("f", new MatchAllQueryBuilder()).subAggregation(AggregationBuilders.terms("t").field("x")))
                .sort(SortBuilders.fieldSort("x"))
                .highlighter(new HighlightBuilder().field("x"))));
    }

    public void testEachPartOfASourceIsChecked() {
        assertTrue("post filter", QueryUtils.sourceContainsDocumentFetch(new SearchSourceBuilder().postFilter(lookup())));
        assertTrue("filter aggregation", QueryUtils.sourceContainsDocumentFetch(
                new SearchSourceBuilder().aggregation(AggregationBuilders.filter("f", lookup()))));
        assertTrue("filters aggregation", QueryUtils.sourceContainsDocumentFetch(new SearchSourceBuilder().aggregation(
                AggregationBuilders.filters("f", new FiltersAggregator.KeyedFilter("k", lookup())))));
        assertTrue("adjacency matrix", QueryUtils.sourceContainsDocumentFetch(new SearchSourceBuilder().aggregation(
                AggregationBuilders.adjacencyMatrix("m", Map.of("k", lookup())))));
        assertTrue("significant terms background filter", QueryUtils.sourceContainsDocumentFetch(new SearchSourceBuilder().aggregation(
                AggregationBuilders.significantTerms("s").field("x").backgroundFilter(lookup()))));
        assertTrue("significant text background filter", QueryUtils.sourceContainsDocumentFetch(new SearchSourceBuilder().aggregation(
                AggregationBuilders.significantText("s", "x").backgroundFilter(lookup()))));
        assertTrue("nested sub aggregation", QueryUtils.sourceContainsDocumentFetch(new SearchSourceBuilder().aggregation(
                AggregationBuilders.terms("t").field("x").subAggregation(
                        AggregationBuilders.terms("u").field("y").subAggregation(AggregationBuilders.filter("f", lookup()))))));
        assertTrue("top hits sort", QueryUtils.sourceContainsDocumentFetch(new SearchSourceBuilder().aggregation(
                AggregationBuilders.topHits("h").sort(SortBuilders.fieldSort("x").setNestedSort(new NestedSortBuilder("rule").setFilter(lookup()))))));
        assertTrue("top hits highlight", QueryUtils.sourceContainsDocumentFetch(new SearchSourceBuilder().aggregation(
                AggregationBuilders.topHits("h").highlighter(new HighlightBuilder().highlightQuery(lookup())))));
        assertTrue("rescore", QueryUtils.sourceContainsDocumentFetch(new SearchSourceBuilder().addRescorer(new QueryRescorerBuilder(lookup()))));
        assertTrue("sort nested filter", QueryUtils.sourceContainsDocumentFetch(new SearchSourceBuilder().sort(
                SortBuilders.fieldSort("x").setNestedSort(new NestedSortBuilder("a").setNestedSort(new NestedSortBuilder("a.b").setFilter(lookup()))))));
        assertTrue("highlight query", QueryUtils.sourceContainsDocumentFetch(new SearchSourceBuilder().highlighter(
                new HighlightBuilder().highlightQuery(lookup()))));
        assertTrue("field highlight query", QueryUtils.sourceContainsDocumentFetch(new SearchSourceBuilder().highlighter(
                new HighlightBuilder().field(new HighlightBuilder.Field("x").highlightQuery(lookup())))));
        assertTrue("collapse inner hits", QueryUtils.sourceContainsDocumentFetch(new SearchSourceBuilder().collapse(
                new CollapseBuilder("x").setInnerHits(new InnerHitBuilder("i").setHighlightBuilder(new HighlightBuilder().highlightQuery(lookup()))))));
        assertTrue("suggestions are refused", QueryUtils.sourceContainsDocumentFetch(new SearchSourceBuilder().suggest(
                new SuggestBuilder().addSuggestion("s", SuggestBuilders.termSuggestion("x").text("y")))));
    }

    private static TermsQueryBuilder lookup() {
        return new TermsQueryBuilder("field", new TermsLookup("other", "1", "path"));
    }
}
