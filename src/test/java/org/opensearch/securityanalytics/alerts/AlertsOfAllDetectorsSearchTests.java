/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package org.opensearch.securityanalytics.alerts;

import java.io.IOException;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicReference;
import java.util.stream.Collectors;
import java.util.stream.IntStream;
import org.apache.lucene.search.TotalHits;
import org.opensearch.OpenSearchException;
import org.opensearch.action.search.SearchPhaseExecutionException;
import org.opensearch.action.search.SearchRequest;
import org.opensearch.action.search.SearchResponse;
import org.opensearch.action.search.ShardSearchFailure;
import org.opensearch.action.support.IndicesOptions;
import org.opensearch.common.regex.Regex;
import org.opensearch.common.settings.Settings;
import org.opensearch.common.util.concurrent.ThreadContext;
import org.opensearch.common.xcontent.XContentFactory;
import org.opensearch.commons.alerting.model.Alert;
import org.opensearch.commons.alerting.model.Table;
import org.opensearch.core.action.ActionListener;
import org.opensearch.core.common.bytes.BytesReference;
import org.opensearch.core.rest.RestStatus;
import org.opensearch.core.xcontent.ToXContent;
import org.opensearch.index.IndexSettings;
import org.opensearch.index.query.BoolQueryBuilder;
import org.opensearch.index.query.Operator;
import org.opensearch.index.query.QueryBuilder;
import org.opensearch.index.query.QueryBuilders;
import org.opensearch.index.query.TermsQueryBuilder;
import org.opensearch.search.SearchHit;
import org.opensearch.search.SearchHits;
import org.opensearch.search.aggregations.InternalAggregations;
import org.opensearch.search.builder.SearchSourceBuilder;
import org.opensearch.search.internal.InternalSearchResponse;
import org.opensearch.search.profile.SearchProfileShardResults;
import org.opensearch.search.sort.FieldSortBuilder;
import org.opensearch.search.sort.SortBuilder;
import org.opensearch.search.sort.SortBuilders;
import org.opensearch.search.sort.SortOrder;
import org.opensearch.search.suggest.Suggest;
import org.opensearch.securityanalytics.action.AlertDto;
import org.opensearch.securityanalytics.action.GetAlertsRequest;
import org.opensearch.securityanalytics.action.GetAlertsResponse;
import org.opensearch.securityanalytics.config.monitors.DetectorMonitorConfig;
import org.opensearch.securityanalytics.threatIntel.iocscan.dao.ThreatIntelAlertService;
import org.opensearch.securityanalytics.transport.TransportIndexDetectorAction;
import org.opensearch.securityanalytics.util.CorrelationIndices;
import org.opensearch.test.OpenSearchTestCase;
import org.opensearch.threadpool.ThreadPool;
import org.opensearch.transport.client.Client;
import org.opensearch.transport.client.node.NodeClient;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

/**
 * The single search of the alerts of all detectors (no detector id and no detector type).
 */
public class AlertsOfAllDetectorsSearchTests extends OpenSearchTestCase {

    private static final String ALL = GetAlertsRequest.ALL;

    private static SearchRequest searchRequest(List<String> logTypes, List<String> monitorIds, Table table, String severityLevel,
                                               String alertState, List<String> severityLevels, List<String> alertStates,
                                               Instant startTime, Instant endTime) {
        return AlertsService.allDetectorsAlertsSearchRequest(logTypes, monitorIds, table, severityLevel, alertState, severityLevels,
                alertStates, startTime, endTime);
    }

    private static BoolQueryBuilder query(SearchRequest request) {
        return (BoolQueryBuilder) request.source().query();
    }

    private static QueryBuilder notAudit() {
        return QueryBuilders.boolQuery().mustNot(QueryBuilders.termsQuery("state", "AUDIT"));
    }

    private static List<SortBuilder<?>> tieBreakers() {
        return List.of(
                SortBuilders.fieldSort("_index").order(SortOrder.ASC),
                SortBuilders.fieldSort("monitor_id").order(SortOrder.ASC).unmappedType("keyword"),
                SortBuilders.fieldSort("_seq_no").order(SortOrder.ASC));
    }

    public void testSearchRequest_noFilters() {
        SearchRequest request = searchRequest(List.of("network", "windows"), List.of("m1", "m2"),
                new Table("asc", "start_time", null, 20, 0, null), ALL, ALL, List.of(), List.of(), null, null);

        assertArrayEquals(new String[] { ".opensearch-sap-network-alerts*", ".opensearch-sap-windows-alerts*" }, request.indices());
        assertEquals(IndicesOptions.lenientExpandOpen(), request.indicesOptions());
        assertTrue(request.indicesOptions().allowNoIndices());
        assertTrue(request.indicesOptions().ignoreUnavailable());

        SearchSourceBuilder source = request.source();
        assertEquals(0, source.from());
        assertEquals(20, source.size());
        assertEquals(Integer.valueOf(10000), source.trackTotalHitsUpTo());
        assertTrue(source.version());
        assertTrue(source.seqNoAndPrimaryTerm());

        // as Alerting: state ALL excludes AUDIT alerts, then the monitor ids
        BoolQueryBuilder expected = QueryBuilders.boolQuery()
                .filter(notAudit())
                .filter(QueryBuilders.termsQuery("monitor_id", List.of("m1", "m2")));
        assertEquals(expected, query(request));

        List<SortBuilder<?>> expectedSorts = new ArrayList<>();
        expectedSorts.add(SortBuilders.fieldSort("start_time").order(SortOrder.ASC).unmappedType("date"));
        expectedSorts.addAll(tieBreakers());
        assertEquals(expectedSorts, source.sorts());
    }

    public void testSearchRequest_singleValueFiltersTimeRangeAndSearchString() {
        Instant startTime = Instant.ofEpochMilli(1000L);
        Instant endTime = Instant.ofEpochMilli(2000L);
        SearchRequest request = searchRequest(List.of("windows"), List.of("m1"),
                new Table("desc", "severity", null, 5, 10, "windetector AND wintrig*"), "3", "ACTIVE", List.of(), List.of(),
                startTime, endTime);

        BoolQueryBuilder expected = QueryBuilders.boolQuery()
                .filter(QueryBuilders.rangeQuery("start_time").from(1000L).to(2000L))
                .filter(QueryBuilders.termQuery("severity", "3"))
                .filter(QueryBuilders.termQuery("state", "ACTIVE"))
                .filter(QueryBuilders.termsQuery("monitor_id", List.of("m1")))
                .must(QueryBuilders.queryStringQuery("windetector AND wintrig*")
                        .defaultOperator(Operator.AND)
                        .field("monitor_name")
                        .field("trigger_name"));
        assertEquals(expected, query(request));
        assertEquals(10, request.source().from());
        assertEquals(5, request.source().size());
    }

    public void testSearchRequest_multiValueFilters() {
        SearchRequest request = searchRequest(List.of("windows"), List.of("m1"), new Table("asc", "state", null, 20, 0, ""), ALL, ALL,
                List.of("1", "2"), List.of("ACTIVE", "ACKNOWLEDGED"), null, null);
        // AUDIT cannot be one of the multi value states, so no AUDIT exclusion is needed
        BoolQueryBuilder expected = QueryBuilders.boolQuery()
                .filter(QueryBuilders.termsQuery("severity", List.of("1", "2")))
                .filter(QueryBuilders.termsQuery("state", List.of("ACTIVE", "ACKNOWLEDGED")))
                .filter(QueryBuilders.termsQuery("monitor_id", List.of("m1")));
        assertEquals(expected, query(request));

        // a multi value severity filter with the single value state ALL
        request = searchRequest(List.of("windows"), List.of("m1"), new Table("asc", "state", null, 20, 0, ""), ALL, ALL,
                List.of("1", "2"), List.of(), null, null);
        expected = QueryBuilders.boolQuery()
                .filter(QueryBuilders.termsQuery("severity", List.of("1", "2")))
                .filter(notAudit())
                .filter(QueryBuilders.termsQuery("monitor_id", List.of("m1")));
        assertEquals(expected, query(request));
    }

    /** Like Alerting, the single value alertState AUDIT returns AUDIT alerts */
    public void testSearchRequest_singleValueAuditState() {
        SearchRequest request = searchRequest(List.of("windows"), List.of("m1"), new Table("asc", "state", null, 20, 0, ""), ALL, "AUDIT",
                List.of(), List.of(), null, null);
        BoolQueryBuilder expected = QueryBuilders.boolQuery()
                .filter(QueryBuilders.termQuery("state", "AUDIT"))
                .filter(QueryBuilders.termsQuery("monitor_id", List.of("m1")));
        assertEquals(expected, query(request));
    }

    public void testSearchRequest_blankSearchStringIsIgnored() {
        for (String searchString : Arrays.asList(null, "", "  ")) {
            SearchRequest request = searchRequest(List.of("windows"), List.of("m1"), new Table("asc", "state", null, 20, 0, searchString),
                    ALL, ALL, List.of(), List.of(), null, null);
            assertTrue(query(request).must().isEmpty());
        }
    }

    public void testSearchRequest_sortOnEverySortableFieldWithTieBreakers() {
        for (String sortString : GetAlertsRequest.SORTABLE_FIELDS) {
            for (String sortOrder : List.of("asc", "desc", "DESC")) {
                for (String missing : Arrays.asList(null, "", "_first", "_last")) {
                    SearchRequest request = searchRequest(List.of("windows"), List.of("m1"),
                            new Table(sortOrder, sortString, missing, 20, 0, null), ALL, ALL, List.of(), List.of(), null, null);
                    List<SortBuilder<?>> sorts = request.source().sorts();

                    FieldSortBuilder primary = SortBuilders.fieldSort(sortString)
                            .order(SortOrder.fromString(sortOrder))
                            .unmappedType(sortString.equals("start_time") ? "date" : "keyword");
                    if (missing != null && missing.isEmpty() == false) {
                        primary.missing(missing);
                    }
                    List<SortBuilder<?>> expected = new ArrayList<>();
                    expected.add(primary);
                    if (sortString.equals("start_time") == false) {
                        expected.add(SortBuilders.fieldSort("start_time").order(SortOrder.DESC).unmappedType("date"));
                    }
                    expected.addAll(tieBreakers());
                    assertEquals(sortString + " " + sortOrder + " " + missing, expected, sorts);
                    // every field sort is valid on indices that do not map the field
                    for (SortBuilder<?> sort : sorts) {
                        FieldSortBuilder fieldSort = (FieldSortBuilder) sort;
                        if (fieldSort.getFieldName().startsWith("_") == false) {
                            assertNotNull(fieldSort.getFieldName(), fieldSort.unmappedType());
                        }
                    }
                }
            }
        }
    }

    public void testSearchRequest_pagingAndTotalOnly() {
        SearchRequest request = searchRequest(List.of("windows"), List.of("m1"), new Table("asc", "start_time", null, 0, 0, null), ALL, ALL,
                List.of(), List.of(), null, null);
        assertEquals(0, request.source().size());
        assertEquals(Integer.valueOf(10000), request.source().trackTotalHitsUpTo());
        request = searchRequest(List.of("windows"), List.of("m1"), new Table("asc", "start_time", null, 10, 9990, null), ALL, ALL,
                List.of(), List.of(), null, null);
        assertEquals(9990, request.source().from());
        assertEquals(10, request.source().size());
    }

    /** Only the log types' alert indices are searched: never the correlation or threat intel alert indices. */
    public void testSearchRequest_indicesExcludeCorrelationAndThreatIntelAlerts() {
        List<String> logTypes = List.of("windows", "network", "others_application", "cloudtrail");
        SearchRequest request = searchRequest(logTypes, List.of("m1"), new Table("asc", "start_time", null, 20, 0, null), ALL, ALL,
                List.of(), List.of(), null, null);
        assertEquals(logTypes.stream().map(DetectorMonitorConfig::getAllAlertsIndicesPattern).collect(Collectors.toList()),
                List.of(request.indices()));
        List<String> excluded = List.of(CorrelationIndices.CORRELATION_ALERT_INDEX, ThreatIntelAlertService.THREAT_INTEL_ALERT_ALIAS_NAME,
                ThreatIntelAlertService.THREAT_INTEL_ALERT_ALIAS_NAME + "-history-2026.01.01-1", ".opendistro-alerting-alerts",
                ".opendistro-alerting-alert-history-2026.01.01-1");
        for (String index : request.indices()) {
            assertFalse(index, index.equals(".opensearch-sap-*-alerts*"));
            for (String excludedIndex : excluded) {
                assertFalse(index + " matches " + excludedIndex, Regex.simpleMatch(index, excludedIndex));
            }
        }
        // the active and history alert indices of the log types are searched
        assertTrue(Regex.simpleMatch(request.indices(), DetectorMonitorConfig.getAlertsIndex("windows")));
        assertTrue(Regex.simpleMatch(request.indices(), DetectorMonitorConfig.getAlertsHistoryIndex("network") + "-2026.01.01-1"));
    }

    public void testMonitorIdsQuery_splitBeyondMaxTermsCount() {
        assertEquals((int) IndexSettings.MAX_TERMS_COUNT_SETTING.getDefault(Settings.EMPTY), AlertsService.MAX_TERMS_COUNT);
        assertEquals(65536, AlertsService.MAX_TERMS_COUNT);

        List<String> atLimit = monitorIds(AlertsService.MAX_TERMS_COUNT);
        assertEquals(QueryBuilders.termsQuery("monitor_id", atLimit), AlertsService.monitorIdsQuery(atLimit));

        List<String> beyondLimit = monitorIds(2 * AlertsService.MAX_TERMS_COUNT + 1);
        BoolQueryBuilder anyOf = (BoolQueryBuilder) AlertsService.monitorIdsQuery(beyondLimit);
        assertEquals("1", anyOf.minimumShouldMatch());
        assertTrue(anyOf.filter().isEmpty());
        assertTrue(anyOf.must().isEmpty());
        assertEquals(3, anyOf.should().size());
        List<Object> allIds = new ArrayList<>();
        for (QueryBuilder should : anyOf.should()) {
            TermsQueryBuilder terms = (TermsQueryBuilder) should;
            assertEquals("monitor_id", terms.fieldName());
            assertTrue(terms.values().size() <= AlertsService.MAX_TERMS_COUNT);
            allIds.addAll(terms.values());
        }
        assertEquals(beyondLimit, allIds);
    }

    private static List<String> monitorIds(int count) {
        return IntStream.range(0, count).mapToObj(i -> "m" + i).collect(Collectors.toList());
    }

    /** Detectors without detector type (whose alert indices are unknown) are skipped instead of failing the request. */
    public void testGroupByLogType_skipsDetectorsWithoutDetectorTypeOrMonitors() {
        AlertsService.LogTypeMonitors grouped = AlertsService.groupByLogType(List.of(
                new DetectorMonitors("no_type", null, List.of("m0"), Map.of()),
                new DetectorMonitors("blank_type", " ", List.of("m00"), Map.of()),
                new DetectorMonitors("d1", "Windows", List.of("m1"), Map.of()),
                new DetectorMonitors("no_monitors", "dns", List.of(), Map.of()),
                new DetectorMonitors("d2", "network", List.of("m2", "bucket", "chained"),
                        Map.of("-1", "m2", "rule", "bucket", TransportIndexDetectorAction.CHAINED_FINDINGS_MONITOR_STRING, "chained")),
                new DetectorMonitors("d3", "windows", List.of("m3"), Map.of())));
        assertEquals(List.of("network", "windows"), List.copyOf(grouped.monitorIdsByLogType.keySet()));
        assertEquals(List.of("m2", "chained"), grouped.monitorIdsByLogType.get("network"));
        assertEquals(List.of("m1", "m3"), grouped.monitorIdsByLogType.get("windows"));
        assertEquals(Map.of("m1", "d1", "m2", "d2", "chained", "d2", "m3", "d3"), grouped.monitorToDetectorMapping);
        assertEquals(List.of("m2", "chained", "m1", "m3"), grouped.monitorIds());
    }

    public void testGetAlertsOfAllDetectors_noMonitorsOrNoDetectorType_returnsEmptyWithoutSearching() {
        NodeClient client = mock(NodeClient.class);
        AlertsService alertsService = new AlertsService(client);
        for (List<DetectorMonitors> detectors : List.of(
                List.<DetectorMonitors>of(),
                List.of(new DetectorMonitors("d1", "windows", List.of(), Map.of())),
                List.of(new DetectorMonitors("d1", null, List.of("m1"), Map.of()), new DetectorMonitors("d2", "", List.of("m2"), Map.of())),
                List.of(new DetectorMonitors("d1", "windows", List.of("bucket"),
                        Map.of("rule", "bucket", TransportIndexDetectorAction.CHAINED_FINDINGS_MONITOR_STRING, "missing_chained"))))) {
            AtomicReference<GetAlertsResponse> response = new AtomicReference<>();
            alertsService.getAlertsOfAllDetectors(detectors, new Table("asc", "start_time", null, 20, 0, null), ALL, ALL, List.of(),
                    List.of(), null, null, ActionListener.wrap(response::set, e -> fail(e.getMessage())));
            assertNotNull(detectors.toString(), response.get());
            assertEquals(0, (int) response.get().getTotalAlerts());
            assertTrue(response.get().getAlerts().isEmpty());
        }
        verifyNoInteractions(client);
    }

    public void testGetAlertsOfAllDetectors_singleSearchInStashedContext() throws IOException {
        ThreadContext threadContext = new ThreadContext(Settings.EMPTY);
        threadContext.putHeader("caller_header", "caller");
        Client client = clientWithThreadContext(threadContext);
        List<SearchRequest> requests = new ArrayList<>();
        AtomicReference<String> headerDuringSearch = new AtomicReference<>("not searched");
        SearchResponse searchResponse = searchResponse(List.of(
                hit(AlertingServiceTests.alert("a1", "m3", 3L), 7L),
                hit(AlertingServiceTests.alert("a2", "m1", 2L), 1L),
                hit(AlertingServiceTests.alert("a3", "chained", 1L), 2L)), 1234L);
        doAnswer(invocation -> {
            requests.add(invocation.getArgument(0));
            headerDuringSearch.set(threadContext.getHeader("caller_header"));
            ActionListener<SearchResponse> listener = invocation.getArgument(1);
            listener.onResponse(searchResponse);
            return null;
        }).when(client).search(any(SearchRequest.class), any(ActionListener.class));

        AtomicReference<GetAlertsResponse> response = new AtomicReference<>();
        AtomicReference<String> headerInListener = new AtomicReference<>();
        new AlertsService(client).getAlertsOfAllDetectors(
                List.of(
                        new DetectorMonitors("windows_detector", "Windows", List.of("m1"), Map.of()),
                        new DetectorMonitors("no_type", null, List.of("m9"), Map.of()),
                        new DetectorMonitors("dns_detector", "dns", List.of(), Map.of()),
                        new DetectorMonitors("network_detector", "network", List.of("m2", "bucket", "chained"),
                                Map.of("-1", "m2", "rule", "bucket", TransportIndexDetectorAction.CHAINED_FINDINGS_MONITOR_STRING, "chained")),
                        new DetectorMonitors("windows_detector_2", "windows", List.of("m3"), Map.of())),
                new Table("desc", "monitor_name.keyword", null, 3, 6, "netdetector"), "2", ALL, List.of(), List.of("ACTIVE", "COMPLETED"),
                null, null,
                ActionListener.wrap(r -> {
                    headerInListener.set(threadContext.getHeader("caller_header"));
                    response.set(r);
                }, e -> fail(e.toString())));

        // one search, run by the plugin: the caller's context is stashed during the search and restored afterwards
        assertEquals(1, requests.size());
        assertNull(headerDuringSearch.get());
        assertEquals("caller", headerInListener.get());
        assertEquals("caller", threadContext.getHeader("caller_header"));

        SearchRequest request = requests.get(0);
        assertArrayEquals(new String[] { ".opensearch-sap-network-alerts*", ".opensearch-sap-windows-alerts*" }, request.indices());
        assertEquals(6, request.source().from());
        assertEquals(3, request.source().size());
        TermsQueryBuilder monitorFilter = (TermsQueryBuilder) query(request).filter().stream()
                .filter(f -> f instanceof TermsQueryBuilder && ((TermsQueryBuilder) f).fieldName().equals("monitor_id"))
                .findFirst().orElseThrow();
        assertEquals(List.of("m2", "chained", "m1", "m3"), monitorFilter.values());
        assertEquals(SortBuilders.fieldSort("monitor_name.keyword").order(SortOrder.DESC).unmappedType("keyword"),
                request.source().sorts().get(0));

        // the hits, in the search's order, mapped to their detectors; the total is the search's
        assertEquals(List.of("a1", "a2", "a3"), response.get().getAlerts().stream().map(AlertDto::getId).collect(Collectors.toList()));
        assertEquals(List.of("windows_detector_2", "windows_detector", "network_detector"),
                response.get().getAlerts().stream().map(AlertDto::getDetectorId).collect(Collectors.toList()));
        assertEquals(List.of(7L, 1L, 2L), response.get().getAlerts().stream().map(AlertDto::getVersion).collect(Collectors.toList()));
        assertEquals(1234, (int) response.get().getTotalAlerts());
    }

    public void testGetAlertsOfAllDetectors_searchClientErrorKeepsItsStatus() {
        ThreadContext threadContext = new ThreadContext(Settings.EMPTY);
        Client client = clientWithThreadContext(threadContext);
        doAnswer(invocation -> {
            ActionListener<SearchResponse> listener = invocation.getArgument(1);
            listener.onFailure(new SearchPhaseExecutionException("query", "all shards failed", new ShardSearchFailure[] {
                    new ShardSearchFailure(new IllegalArgumentException("Result window is too large")) }));
            return null;
        }).when(client).search(any(SearchRequest.class), any(ActionListener.class));
        AtomicReference<Exception> failure = new AtomicReference<>();
        new AlertsService(client).getAlertsOfAllDetectors(List.of(new DetectorMonitors("d1", "windows", List.of("m1"), Map.of())),
                new Table("asc", "start_time", null, 10, 9995, null), ALL, ALL, List.of(), List.of(), null, null,
                ActionListener.wrap(r -> fail("expected failure"), failure::set));
        assertEquals(RestStatus.BAD_REQUEST, ((OpenSearchException) failure.get()).status());
        assertTrue(failure.get().getMessage(), failure.get().getMessage().contains("Result window is too large"));
    }

    private static Client clientWithThreadContext(ThreadContext threadContext) {
        Client client = mock(Client.class);
        ThreadPool threadPool = mock(ThreadPool.class);
        when(threadPool.getThreadContext()).thenReturn(threadContext);
        when(client.threadPool()).thenReturn(threadPool);
        return client;
    }

    private static SearchHit hit(Alert alert, long version) throws IOException {
        SearchHit hit = new SearchHit(0, alert.getId(), Collections.emptyMap(), Collections.emptyMap());
        hit.sourceRef(BytesReference.bytes(alert.toXContent(XContentFactory.jsonBuilder(), ToXContent.EMPTY_PARAMS)));
        hit.version(version);
        return hit;
    }

    private static SearchResponse searchResponse(List<SearchHit> hits, long total) {
        return new SearchResponse(new InternalSearchResponse(
                new SearchHits(hits.toArray(new SearchHit[0]), new TotalHits(total, TotalHits.Relation.EQUAL_TO), 1.0f),
                InternalAggregations.from(Collections.emptyList()),
                new Suggest(Collections.emptyList()),
                new SearchProfileShardResults(Collections.emptyMap()), false, false, 0),
                "", 1, 1, 0, 0,
                ShardSearchFailure.EMPTY_ARRAY, SearchResponse.Clusters.EMPTY);
    }
}
