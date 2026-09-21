/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.securityanalytics.transport;

import org.opensearch.index.query.BoolQueryBuilder;
import org.opensearch.index.query.BoostingQueryBuilder;
import org.opensearch.index.query.ConstantScoreQueryBuilder;
import org.opensearch.index.query.DisMaxQueryBuilder;
import org.opensearch.index.query.MatchAllQueryBuilder;
import org.opensearch.index.query.MatchQueryBuilder;
import org.opensearch.index.query.NestedQueryBuilder;
import org.opensearch.index.query.TermsQueryBuilder;
import org.opensearch.indices.TermsLookup;
import org.opensearch.test.OpenSearchTestCase;

public class QueryUtilsTests extends OpenSearchTestCase {

    public void testNullQuery() {
        assertFalse(QueryUtils.containsTermsLookup(null));
    }

    public void testMatchAllQuery() {
        assertFalse(QueryUtils.containsTermsLookup(new MatchAllQueryBuilder()));
    }

    public void testMatchQuery() {
        assertFalse(QueryUtils.containsTermsLookup(new MatchQueryBuilder("field", "value")));
    }

    public void testInlineTermsQuery() {
        TermsQueryBuilder terms = new TermsQueryBuilder("field", "val1", "val2");
        assertFalse(QueryUtils.containsTermsLookup(terms));
    }

    public void testTermsLookupQuery() {
        TermsQueryBuilder terms = new TermsQueryBuilder("field", new TermsLookup("other-index", "doc1", "path"));
        assertTrue(QueryUtils.containsTermsLookup(terms));
    }

    public void testBoolWithTermsLookupInMust() {
        BoolQueryBuilder bool = new BoolQueryBuilder()
                .must(new MatchAllQueryBuilder())
                .must(new TermsQueryBuilder("field", new TermsLookup("secret-index", "id1", "data")));
        assertTrue(QueryUtils.containsTermsLookup(bool));
    }

    public void testBoolWithTermsLookupInShould() {
        BoolQueryBuilder bool = new BoolQueryBuilder()
                .must(new MatchAllQueryBuilder())
                .should(new TermsQueryBuilder("field", new TermsLookup("secret-index", "id1", "data")));
        assertTrue(QueryUtils.containsTermsLookup(bool));
    }

    public void testBoolWithTermsLookupInFilter() {
        BoolQueryBuilder bool = new BoolQueryBuilder()
                .must(new MatchAllQueryBuilder())
                .filter(new TermsQueryBuilder("field", new TermsLookup("secret-index", "id1", "data")));
        assertTrue(QueryUtils.containsTermsLookup(bool));
    }

    public void testBoolWithTermsLookupInMustNot() {
        BoolQueryBuilder bool = new BoolQueryBuilder()
                .must(new MatchAllQueryBuilder())
                .mustNot(new TermsQueryBuilder("field", new TermsLookup("secret-index", "id1", "data")));
        assertTrue(QueryUtils.containsTermsLookup(bool));
    }

    public void testBoolWithoutTermsLookup() {
        BoolQueryBuilder bool = new BoolQueryBuilder()
                .must(new MatchAllQueryBuilder())
                .must(new TermsQueryBuilder("field", "val1", "val2"))
                .filter(new MatchQueryBuilder("status", "active"));
        assertFalse(QueryUtils.containsTermsLookup(bool));
    }

    public void testNestedBoolWithTermsLookup() {
        BoolQueryBuilder inner = new BoolQueryBuilder()
                .must(new TermsQueryBuilder("field", new TermsLookup("secret-index", "id1", "data")));
        BoolQueryBuilder outer = new BoolQueryBuilder()
                .must(new MatchAllQueryBuilder())
                .filter(inner);
        assertTrue(QueryUtils.containsTermsLookup(outer));
    }

    public void testConstantScoreWithTermsLookup() {
        ConstantScoreQueryBuilder constantScore = new ConstantScoreQueryBuilder(
                new TermsQueryBuilder("field", new TermsLookup("secret-index", "id1", "data")));
        assertTrue(QueryUtils.containsTermsLookup(constantScore));
    }

    public void testConstantScoreWithoutTermsLookup() {
        ConstantScoreQueryBuilder constantScore = new ConstantScoreQueryBuilder(
                new MatchAllQueryBuilder());
        assertFalse(QueryUtils.containsTermsLookup(constantScore));
    }

    public void testBoostingWithTermsLookupInPositive() {
        BoostingQueryBuilder boosting = new BoostingQueryBuilder(
                new TermsQueryBuilder("field", new TermsLookup("secret-index", "id1", "data")),
                new MatchAllQueryBuilder()
        ).negativeBoost(0.5f);
        assertTrue(QueryUtils.containsTermsLookup(boosting));
    }

    public void testBoostingWithTermsLookupInNegative() {
        BoostingQueryBuilder boosting = new BoostingQueryBuilder(
                new MatchAllQueryBuilder(),
                new TermsQueryBuilder("field", new TermsLookup("secret-index", "id1", "data"))
        ).negativeBoost(0.5f);
        assertTrue(QueryUtils.containsTermsLookup(boosting));
    }

    public void testDisMaxWithTermsLookup() {
        DisMaxQueryBuilder disMax = new DisMaxQueryBuilder()
                .add(new MatchAllQueryBuilder())
                .add(new TermsQueryBuilder("field", new TermsLookup("secret-index", "id1", "data")));
        assertTrue(QueryUtils.containsTermsLookup(disMax));
    }

    public void testDisMaxWithoutTermsLookup() {
        DisMaxQueryBuilder disMax = new DisMaxQueryBuilder()
                .add(new MatchAllQueryBuilder())
                .add(new MatchQueryBuilder("field", "value"));
        assertFalse(QueryUtils.containsTermsLookup(disMax));
    }

    public void testNestedQueryWithTermsLookup() {
        NestedQueryBuilder nested = new NestedQueryBuilder("path",
                new TermsQueryBuilder("path.field", new TermsLookup("secret-index", "id1", "data")),
                org.apache.lucene.search.join.ScoreMode.Avg);
        assertTrue(QueryUtils.containsTermsLookup(nested));
    }

    public void testNestedQueryWithoutTermsLookup() {
        NestedQueryBuilder nested = new NestedQueryBuilder("path",
                new MatchQueryBuilder("path.field", "value"),
                org.apache.lucene.search.join.ScoreMode.Avg);
        assertFalse(QueryUtils.containsTermsLookup(nested));
    }

    public void testDeeplyNestedTermsLookup() {
        TermsQueryBuilder termsLookup = new TermsQueryBuilder("field",
                new TermsLookup("secret-index", "id1", "data"));

        BoolQueryBuilder level3 = new BoolQueryBuilder().must(termsLookup);
        ConstantScoreQueryBuilder level2 = new ConstantScoreQueryBuilder(level3);
        BoolQueryBuilder level1 = new BoolQueryBuilder().filter(level2);

        assertTrue(QueryUtils.containsTermsLookup(level1));
    }
}
