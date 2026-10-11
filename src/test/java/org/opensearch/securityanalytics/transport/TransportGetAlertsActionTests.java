/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package org.opensearch.securityanalytics.transport;

import java.io.IOException;
import java.time.Instant;
import java.time.ZoneId;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import org.apache.lucene.search.TotalHits;
import org.opensearch.action.search.SearchRequest;
import org.opensearch.action.search.SearchResponse;
import org.opensearch.action.search.ShardSearchFailure;
import org.opensearch.cluster.routing.Preference;
import org.opensearch.common.xcontent.XContentFactory;
import org.opensearch.common.xcontent.XContentHelper;
import org.opensearch.common.xcontent.XContentType;
import org.opensearch.common.xcontent.support.XContentMapValues;
import org.opensearch.commons.alerting.model.CronSchedule;
import org.opensearch.commons.alerting.model.Table;
import org.opensearch.commons.authuser.User;
import org.opensearch.core.common.bytes.BytesReference;
import org.opensearch.core.xcontent.NamedXContentRegistry;
import org.opensearch.core.xcontent.ToXContent;
import org.opensearch.core.xcontent.XContentBuilder;
import org.opensearch.index.query.BoolQueryBuilder;
import org.opensearch.index.query.NestedQueryBuilder;
import org.opensearch.index.query.QueryBuilder;
import org.opensearch.index.query.QueryBuilders;
import org.opensearch.index.query.TermsQueryBuilder;
import org.opensearch.search.SearchHit;
import org.opensearch.search.SearchHits;
import org.opensearch.search.aggregations.InternalAggregations;
import org.opensearch.search.fetch.subphase.FetchSourceContext;
import org.opensearch.search.internal.InternalSearchResponse;
import org.opensearch.search.profile.SearchProfileShardResults;
import org.opensearch.search.suggest.Suggest;
import org.opensearch.securityanalytics.action.GetAlertsRequest;
import org.opensearch.securityanalytics.alerts.AlertsService;
import org.opensearch.securityanalytics.alerts.DetectorMonitors;
import org.opensearch.securityanalytics.config.monitors.DetectorMonitorConfig;
import org.opensearch.securityanalytics.model.Detector;
import org.opensearch.test.OpenSearchTestCase;

public class TransportGetAlertsActionTests extends OpenSearchTestCase {

    /** A comma separated multi value filter is applied by AlertsService as a terms filter, with Alerting's filter at ALL. */
    public void testSingleValueFilter() {
        GetAlertsRequest multi = new GetAlertsRequest(null, null, new Table("asc", "start_time", null, 20, 0, ""), "1,2", "ACTIVE,COMPLETED",
                null, null);
        assertEquals("ALL", TransportGetAlertsAction.singleValueFilter(multi.getSeverityLevel(), multi.getSeverityLevels()));
        assertEquals("ALL", TransportGetAlertsAction.singleValueFilter(multi.getAlertState(), multi.getAlertStates()));
        assertEquals(List.of("1", "2"), multi.getSeverityLevels());
        assertEquals(List.of("ACTIVE", "COMPLETED"), multi.getAlertStates());

        // a single value is passed on to Alerting as before, including AUDIT
        GetAlertsRequest single = new GetAlertsRequest("detector_id", null, new Table("asc", "start_time", null, 20, 0, ""), "3", "AUDIT",
                null, null);
        assertEquals("3", TransportGetAlertsAction.singleValueFilter(single.getSeverityLevel(), single.getSeverityLevels()));
        assertEquals("AUDIT", TransportGetAlertsAction.singleValueFilter(single.getAlertState(), single.getAlertStates()));
        assertEquals(List.of(), single.getSeverityLevels());
        assertEquals(List.of(), single.getAlertStates());
    }

    public void testDetectorsSearchRequest_fetchesOnlyTheFieldsNeededForAlerts() {
        QueryBuilder query = QueryBuilders.matchAllQuery();
        SearchRequest request = TransportGetAlertsAction.detectorsSearchRequest(query);

        assertArrayEquals(new String[] { Detector.DETECTORS_INDEX }, request.indices());
        assertEquals(Preference.PRIMARY_FIRST.type(), request.preference());
        assertEquals(10000, request.source().size());
        assertSame(query, request.source().query());
        FetchSourceContext fetchSource = request.source().fetchSource();
        assertTrue(fetchSource.fetchSource());
        assertArrayEquals(new String[] { "detector.detector_type", "detector.monitor_id", "detector.bucket_monitor_id_rule_id" },
                fetchSource.includes());
        assertArrayEquals(new String[0], fetchSource.excludes());
    }

    /**
     * The backend role filter of {@link TransportSearchDetectorAction} is a query clause: it still applies to the
     * source filtered search and leaves the source filtering untouched.
     */
    public void testDetectorsSearchRequest_backendRoleFilterStillApplies() {
        QueryBuilder query = QueryBuilders.matchAllQuery();
        SearchRequest request = TransportGetAlertsAction.detectorsSearchRequest(query);
        SecureTransportAction secureTransportAction = new SecureTransportAction() {
        };
        User user = new User("user", List.of("backend_role_a", "backend_role_b"), List.of(), List.of());
        secureTransportAction.addFilter(user, request.source(), "detector.user.backend_roles.keyword");

        BoolQueryBuilder filtered = (BoolQueryBuilder) request.source().query();
        assertEquals(List.of(query), filtered.must());
        assertEquals(1, filtered.filter().size());
        NestedQueryBuilder nested = (NestedQueryBuilder) filtered.filter().get(0);
        assertEquals("detector", nested.path());
        TermsQueryBuilder backendRoles = (TermsQueryBuilder) nested.query();
        assertEquals("detector.user.backend_roles.keyword", backendRoles.fieldName());
        assertEquals(List.of("backend_role_a", "backend_role_b"), backendRoles.values());

        assertArrayEquals(DetectorMonitors.SOURCE_INCLUDES, request.source().fetchSource().includes());
        assertArrayEquals(new String[0], request.source().fetchSource().excludes());
    }

    /**
     * Parsing the source filtered detector docs gives the same monitors as the full detectors, with and without a
     * chained findings monitor, and with the fields resource sharing adds to the doc.
     */
    public void testParseDetectors_sourceFilteredDocs() throws IOException {
        List<Detector> detectors = List.of(
                detector("d1", "windows", List.of("doc", "bucket"), Map.of("-1", "doc", "rule_1", "bucket")),
                detector("d2", "network", List.of("doc", "bucket", "chained"),
                        Map.of("-1", "doc", "rule_1", "bucket", TransportIndexDetectorAction.CHAINED_FINDINGS_MONITOR_STRING, "chained")),
                detector("d3", "dns", List.of(), Map.of())
        );
        List<SearchHit> hits = new ArrayList<>();
        for (Detector detector : detectors) {
            Map<String, Object> source = new HashMap<>(XContentHelper.convertToMap(BytesReference.bytes(
                    detector.toXContentWithUser(XContentFactory.jsonBuilder(), new ToXContent.MapParams(Map.of("with_type", "true")))),
                    false, XContentType.JSON).v2());
            source.put("all_shared_principals", List.of("user:a", "role:b"));
            // what the search returns: the doc filtered by the search request's source includes
            Map<String, Object> filtered = XContentMapValues.filter(source, DetectorMonitors.SOURCE_INCLUDES, new String[0]);
            assertFalse(filtered.toString(), ((Map<?, ?>) filtered.get("detector")).containsKey("name"));
            hits.add(hit(detector.getId(), filtered));
        }
        // a doc that only has some of the fields, and an unfiltered doc
        hits.add(hit("d4", Map.of("detector", Map.of("detector_type", "s3", "monitor_id", List.of("m4")))));
        Detector full = detector("d5", "cloudtrail", List.of("m5"), Map.of("-1", "m5"));
        hits.add(hit("d5", XContentHelper.convertToMap(BytesReference.bytes(
                full.toXContentWithUser(XContentFactory.jsonBuilder(), new ToXContent.MapParams(Map.of("with_type", "true")))),
                false, XContentType.JSON).v2()));

        List<DetectorMonitors> parsed = TransportGetAlertsAction.parseDetectors(searchResponse(hits), NamedXContentRegistry.EMPTY);

        assertEquals(5, parsed.size());
        for (int i = 0; i < detectors.size(); i++) {
            Detector detector = detectors.get(i);
            assertEquals(DetectorMonitors.of(detector), parsed.get(i));
            assertEquals(AlertsService.getAlertingMonitorToDetectorMapping(detector),
                    AlertsService.getAlertingMonitorToDetectorMapping(parsed.get(i)));
        }
        assertEquals(Map.of("doc", "d2", "chained", "d2"), AlertsService.getAlertingMonitorToDetectorMapping(parsed.get(1)));
        assertEquals(new DetectorMonitors("d4", "s3", List.of("m4"), Map.of()), parsed.get(3));
        assertEquals(DetectorMonitors.of(full), parsed.get(4));
    }

    private static SearchHit hit(String id, Map<String, Object> source) throws IOException {
        XContentBuilder builder = XContentFactory.jsonBuilder().map(source);
        SearchHit hit = new SearchHit(0, id, Collections.emptyMap(), Collections.emptyMap());
        hit.sourceRef(BytesReference.bytes(builder));
        return hit;
    }

    private static SearchResponse searchResponse(List<SearchHit> hits) {
        return new SearchResponse(new InternalSearchResponse(
                new SearchHits(hits.toArray(new SearchHit[0]), new TotalHits(hits.size(), TotalHits.Relation.EQUAL_TO), 1.0f),
                InternalAggregations.from(Collections.emptyList()),
                new Suggest(Collections.emptyList()),
                new SearchProfileShardResults(Collections.emptyMap()), false, false, 0),
                "", 1, 1, 0, 0,
                ShardSearchFailure.EMPTY_ARRAY, SearchResponse.Clusters.EMPTY);
    }

    private static Detector detector(String id, String logType, List<String> monitorIds, Map<String, String> ruleIdMonitorIdMap) {
        return new Detector(
                id,
                0L,
                "test-detector-" + id,
                true,
                new CronSchedule("31 * * * *", ZoneId.of("Asia/Kolkata"), Instant.ofEpochSecond(1538164858L)),
                Instant.now(),
                Instant.now(),
                logType,
                new User("owner", List.of("backend_role"), List.of("role"), List.of()),
                List.of(),
                List.of(),
                monitorIds,
                DetectorMonitorConfig.getRuleIndex(logType),
                DetectorMonitorConfig.getAlertsIndex(logType),
                DetectorMonitorConfig.getAlertsHistoryIndex(logType),
                DetectorMonitorConfig.getAlertsHistoryIndexPattern(logType),
                DetectorMonitorConfig.getFindingsIndex(logType),
                DetectorMonitorConfig.getFindingsIndexPattern(logType),
                ruleIdMonitorIdMap,
                List.of("workflow_" + id),
                false
        );
    }
}
