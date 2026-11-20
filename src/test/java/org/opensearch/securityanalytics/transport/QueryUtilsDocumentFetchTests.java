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
}
