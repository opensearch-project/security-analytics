/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package org.opensearch.securityanalytics.alerts;

import java.io.IOException;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicReference;
import java.util.stream.Collectors;
import org.apache.lucene.search.TotalHits;
import org.apache.lucene.util.BytesRef;
import org.opensearch.OpenSearchException;
import org.opensearch.OpenSearchStatusException;
import org.opensearch.action.search.SearchPhaseExecutionException;
import org.opensearch.action.search.SearchRequest;
import org.opensearch.action.search.SearchResponse;
import org.opensearch.action.search.ShardSearchFailure;
import org.opensearch.action.support.IndicesOptions;
import org.opensearch.common.settings.Settings;
import org.opensearch.common.util.concurrent.ThreadContext;
import org.opensearch.common.xcontent.XContentFactory;
import org.opensearch.commons.alerting.model.Alert;
import org.opensearch.commons.alerting.model.Table;
import org.opensearch.core.action.ActionListener;
import org.opensearch.core.common.bytes.BytesReference;
import org.opensearch.core.rest.RestStatus;
import org.opensearch.core.xcontent.ToXContent;
import org.opensearch.index.query.BoolQueryBuilder;
import org.opensearch.index.query.QueryBuilders;
import org.opensearch.search.DocValueFormat;
import org.opensearch.search.SearchHit;
import org.opensearch.search.SearchHits;
import org.opensearch.search.aggregations.InternalAggregations;
import org.opensearch.search.builder.SearchSourceBuilder;
import org.opensearch.search.internal.InternalSearchResponse;
import org.opensearch.search.internal.SearchContext;
import org.opensearch.search.profile.SearchProfileShardResults;
import org.opensearch.search.sort.SortBuilder;
import org.opensearch.search.sort.SortBuilders;
import org.opensearch.search.sort.SortOrder;
import org.opensearch.search.suggest.Suggest;
import org.opensearch.securityanalytics.action.AlertDto;
import org.opensearch.securityanalytics.action.GetAlertsPageRequest;
import org.opensearch.securityanalytics.action.GetAlertsPageResponse;
import org.opensearch.securityanalytics.action.GetAlertsRequest;
import org.opensearch.securityanalytics.action.GetDetectorAction;
import org.opensearch.securityanalytics.action.GetDetectorRequest;
import org.opensearch.securityanalytics.action.GetDetectorResponse;
import org.opensearch.securityanalytics.model.Detector;
import org.opensearch.test.OpenSearchTestCase;
import org.opensearch.threadpool.ThreadPool;
import org.opensearch.transport.client.Client;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Cursor paging of alerts ({@link GetAlertsPageRequest}) in {@link AlertsService}.
 */
public class AlertsPageTests extends OpenSearchTestCase {

    private static final String ALL = GetAlertsRequest.ALL;
    private static final GetAlertsPageRequest.Direction NEXT = GetAlertsPageRequest.Direction.NEXT;
    private static final GetAlertsPageRequest.Direction PREV = GetAlertsPageRequest.Direction.PREV;

    private static GetAlertsPageRequest request(Table table, String searchAfter, GetAlertsPageRequest.Direction direction) {
        return new GetAlertsPageRequest(null, null, table, ALL, ALL, List.of(), List.of(), null, null, searchAfter, direction);
    }

    private static String cursor(Table table, Object... sortValues) {
        return AlertsCursor.encode(table, sortValues);
    }

    private static List<SortBuilder<?>> tieBreakers() {
        return List.of(
                SortBuilders.fieldSort("_index").order(SortOrder.ASC),
                SortBuilders.fieldSort("monitor_id").order(SortOrder.ASC).unmappedType("keyword"),
                SortBuilders.fieldSort("_seq_no").order(SortOrder.ASC));
    }

    private static List<SortBuilder<?>> reversedTieBreakers() {
        return List.of(
                SortBuilders.fieldSort("_index").order(SortOrder.DESC),
                SortBuilders.fieldSort("monitor_id").order(SortOrder.DESC).unmappedType("keyword").missing("_first"),
                SortBuilders.fieldSort("_seq_no").order(SortOrder.DESC));
    }

    public void testSearchRequest_offsetPage() {
        Table table = new Table("asc", "start_time", null, 20, 40, null);
        SearchRequest request = AlertsService.alertsPageSearchRequest(List.of("network", "windows"), List.of("m1", "m2"),
                request(table, null, NEXT), null);

        assertArrayEquals(new String[] { ".opensearch-sap-network-alerts*", ".opensearch-sap-windows-alerts*" }, request.indices());
        assertEquals(IndicesOptions.lenientExpandOpen(), request.indicesOptions());
        SearchSourceBuilder source = request.source();
        assertEquals(40, source.from());
        assertEquals(20, source.size());
        assertNull(source.searchAfter());
        // the exact total: trackTotalHits(true)
        assertEquals(Integer.valueOf(SearchContext.TRACK_TOTAL_HITS_ACCURATE), source.trackTotalHitsUpTo());
        assertTrue(source.version());
        assertTrue(source.seqNoAndPrimaryTerm());
        // the same query and sort as the alerts of all detectors in offset paging
        SearchRequest offsetRequest = AlertsService.allDetectorsAlertsSearchRequest(List.of("network", "windows"), List.of("m1", "m2"),
                table, ALL, ALL, List.of(), List.of(), null, null);
        assertEquals(offsetRequest.source().query(), source.query());
        assertEquals(offsetRequest.source().sorts(), source.sorts());
    }

    public void testSearchRequest_filtersAlwaysApply() {
        Table table = new Table("desc", "severity", null, 10, 0, "windetector");
        Instant from = Instant.ofEpochMilli(1000);
        Instant to = Instant.ofEpochMilli(2000);
        String searchAfter = cursor(table, "1", 5L, "index", "m1", 3L);
        GetAlertsPageRequest pageRequest = new GetAlertsPageRequest(null, null, table, ALL, ALL, List.of("1", "2"),
                List.of("ACTIVE"), from, to, searchAfter, NEXT);
        SearchRequest request = AlertsService.alertsPageSearchRequest(List.of("windows"), List.of("m1"), pageRequest,
                pageRequest.getCursor());
        BoolQueryBuilder expected = AlertsService.alertsQuery(List.of("m1"), "windetector", ALL, ALL, List.of("1", "2"),
                List.of("ACTIVE"), from, to);
        assertEquals(expected, request.source().query());
        assertTrue(expected.filter().contains(QueryBuilders.termsQuery("monitor_id", List.of("m1"))));
        assertTrue(expected.filter().contains(QueryBuilders.termsQuery("severity", List.of("1", "2"))));
        assertTrue(expected.filter().contains(QueryBuilders.termsQuery("state", List.of("ACTIVE"))));
        assertTrue(expected.filter().contains(QueryBuilders.rangeQuery("start_time").from(1000L).to(2000L)));
        assertEquals(1, expected.must().size());

        // without multi value states, AUDIT alerts are excluded as by Alerting
        GetAlertsPageRequest noStates = request(table, searchAfter, PREV);
        BoolQueryBuilder noStatesQuery = (BoolQueryBuilder) AlertsService.alertsPageSearchRequest(List.of("windows"), List.of("m1"),
                noStates, noStates.getCursor()).source().query();
        assertTrue(noStatesQuery.filter().contains(QueryBuilders.boolQuery().mustNot(QueryBuilders.termsQuery("state", "AUDIT"))));
    }

    public void testSearchRequest_next() {
        Table table = new Table("desc", "severity", null, 10, 0, null);
        String searchAfter = cursor(table, "3", 5L, "index", "m1", 3L);
        GetAlertsPageRequest pageRequest = request(table, searchAfter, NEXT);
        SearchSourceBuilder source = AlertsService.alertsPageSearchRequest(List.of("windows"), List.of("m1"), pageRequest,
                pageRequest.getCursor()).source();
        assertEquals(-1, source.from());
        // one more alert than the page tells whether there is a next page
        assertEquals(11, source.size());
        assertArrayEquals(new Object[] { "3", 5L, "index", "m1", 3L }, source.searchAfter());
        assertEquals(Integer.valueOf(SearchContext.TRACK_TOTAL_HITS_ACCURATE), source.trackTotalHitsUpTo());
        List<SortBuilder<?>> expectedSorts = new ArrayList<>();
        expectedSorts.add(SortBuilders.fieldSort("severity").order(SortOrder.DESC).unmappedType("keyword"));
        expectedSorts.add(SortBuilders.fieldSort("start_time").order(SortOrder.DESC).unmappedType("date"));
        expectedSorts.addAll(tieBreakers());
        assertEquals(expectedSorts, source.sorts());
    }

    public void testSearchRequest_prevReversesTheSort() {
        Table table = new Table("desc", "severity", null, 10, 0, null);
        String searchAfter = cursor(table, "3", 5L, "index", "m1", 3L);
        GetAlertsPageRequest pageRequest = request(table, searchAfter, PREV);
        SearchSourceBuilder source = AlertsService.alertsPageSearchRequest(List.of("windows"), List.of("m1"), pageRequest,
                pageRequest.getCursor()).source();
        assertEquals(11, source.size());
        assertArrayEquals(new Object[] { "3", 5L, "index", "m1", 3L }, source.searchAfter());
        List<SortBuilder<?>> expectedSorts = new ArrayList<>();
        // every order reversed, missing values first instead of last
        expectedSorts.add(SortBuilders.fieldSort("severity").order(SortOrder.ASC).unmappedType("keyword").missing("_first"));
        expectedSorts.add(SortBuilders.fieldSort("start_time").order(SortOrder.ASC).unmappedType("date").missing("_first"));
        expectedSorts.addAll(reversedTieBreakers());
        assertEquals(expectedSorts, source.sorts());

        // start_time asc reversed, without a separate start time tie-breaker
        Table startTime = new Table("asc", "start_time", null, 10, 0, null);
        GetAlertsPageRequest startTimeRequest = request(startTime, cursor(startTime, 5L, "index", "m1", 3L), PREV);
        expectedSorts = new ArrayList<>();
        expectedSorts.add(SortBuilders.fieldSort("start_time").order(SortOrder.DESC).unmappedType("date").missing("_first"));
        expectedSorts.addAll(reversedTieBreakers());
        assertEquals(expectedSorts, AlertsService.alertsPageSearchRequest(List.of("windows"), List.of("m1"), startTimeRequest,
                startTimeRequest.getCursor()).source().sorts());
    }

    public void testSortBuilders_reverseMissing() {
        assertEquals(SortBuilders.fieldSort("state").order(SortOrder.ASC).unmappedType("keyword").missing("_last"),
                AlertsService.sortBuilders(new Table("desc", "state", "_first", 10, 0, null), true).get(0));
        assertEquals(SortBuilders.fieldSort("state").order(SortOrder.DESC).unmappedType("keyword").missing("_first"),
                AlertsService.sortBuilders(new Table("asc", "state", "_last", 10, 0, null), true).get(0));
        // a custom missing value sorts like any value
        assertEquals(SortBuilders.fieldSort("state").order(SortOrder.DESC).unmappedType("keyword").missing("ZZZ"),
                AlertsService.sortBuilders(new Table("asc", "state", "ZZZ", 10, 0, null), true).get(0));
        // not reversed: unchanged
        for (String sortString : GetAlertsRequest.SORTABLE_FIELDS) {
            for (String missing : new String[] { null, "_first", "_last", "ZZZ" }) {
                Table table = new Table("desc", sortString, missing, 10, 0, null);
                assertEquals(AlertsService.sortBuilders(table), AlertsService.sortBuilders(table, false));
            }
        }
    }

    public void testGetAlertsPage_firstPage() throws IOException {
        Table table = new Table("asc", "start_time", null, 2, 0, null);
        AtomicReference<SearchRequest> searched = new AtomicReference<>();
        Client client = clientSearching(searched, searchResponse(List.of(
                hit(alert("a1", "m1", 1L), 1L, 1L, "i", "m1", 1L),
                hit(alert("a2", "m1", 2L), 1L, 2L, "i", "m1", 2L)), 5));
        GetAlertsPageResponse response = getAlertsPage(client, request(table, null, NEXT));
        assertEquals(List.of("a1", "a2"), ids(response));
        assertEquals(List.of("d1", "d1"), response.getAlerts().stream().map(AlertDto::getDetectorId).collect(Collectors.toList()));
        assertEquals(5, response.getTotalAlerts());
        assertNull(response.getPrevCursor());
        assertArrayEquals(new Object[] { 2L, "i", "m1", 2L }, AlertsCursor.decode(response.getNextCursor(), table).getSortValues());
        assertEquals(0, searched.get().source().from());
    }

    public void testGetAlertsPage_offsetPages() throws IOException {
        // a middle page: alerts before and after it
        Table middle = new Table("asc", "start_time", null, 2, 2, null);
        GetAlertsPageResponse response = getAlertsPage(clientSearching(new AtomicReference<>(), searchResponse(List.of(
                hit(alert("a3", "m1", 3L), 1L, 3L, "i", "m1", 3L),
                hit(alert("a4", "m1", 4L), 1L, 4L, "i", "m1", 4L)), 5)), request(middle, null, NEXT));
        assertArrayEquals(new Object[] { 3L, "i", "m1", 3L }, AlertsCursor.decode(response.getPrevCursor(), middle).getSortValues());
        assertArrayEquals(new Object[] { 4L, "i", "m1", 4L }, AlertsCursor.decode(response.getNextCursor(), middle).getSortValues());

        // the last page
        Table last = new Table("asc", "start_time", null, 2, 4, null);
        response = getAlertsPage(clientSearching(new AtomicReference<>(), searchResponse(List.of(
                hit(alert("a5", "m1", 5L), 1L, 5L, "i", "m1", 5L)), 5)), request(last, null, NEXT));
        assertEquals(List.of("a5"), ids(response));
        assertNotNull(response.getPrevCursor());
        assertNull(response.getNextCursor());

        // size 0: the total only
        Table count = new Table("asc", "start_time", null, 0, 0, null);
        response = getAlertsPage(clientSearching(new AtomicReference<>(), searchResponse(List.of(), 12345)), request(count, null, NEXT));
        assertEquals(12345, response.getTotalAlerts());
        assertEquals(List.of(), response.getAlerts());
        assertNull(response.getPrevCursor());
        assertNull(response.getNextCursor());
    }

    public void testGetAlertsPage_next() throws IOException {
        Table table = new Table("asc", "start_time", null, 2, 0, null);
        String searchAfter = cursor(table, 2L, "i", "m1", 2L);
        // size + 1 hits: there is a next page
        GetAlertsPageResponse response = getAlertsPage(clientSearching(new AtomicReference<>(), searchResponse(List.of(
                hit(alert("a3", "m1", 3L), 1L, 3L, "i", "m1", 3L),
                hit(alert("a4", "m1", 4L), 1L, 4L, "i", "m1", 4L),
                hit(alert("a5", "m1", 5L), 1L, 5L, "i", "m1", 5L)), 5)), request(table, searchAfter, NEXT));
        assertEquals(List.of("a3", "a4"), ids(response));
        assertEquals(5, response.getTotalAlerts());
        assertArrayEquals(new Object[] { 3L, "i", "m1", 3L }, AlertsCursor.decode(response.getPrevCursor(), table).getSortValues());
        assertArrayEquals(new Object[] { 4L, "i", "m1", 4L }, AlertsCursor.decode(response.getNextCursor(), table).getSortValues());

        // the last page
        response = getAlertsPage(clientSearching(new AtomicReference<>(), searchResponse(List.of(
                hit(alert("a5", "m1", 5L), 1L, 5L, "i", "m1", 5L)), 5)), request(table, cursor(table, 4L, "i", "m1", 4L), NEXT));
        assertEquals(List.of("a5"), ids(response));
        assertNotNull(response.getPrevCursor());
        assertNull(response.getNextCursor());

        // past the last alert
        response = getAlertsPage(clientSearching(new AtomicReference<>(), searchResponse(List.of(), 5)),
                request(table, cursor(table, 5L, "i", "m1", 5L), NEXT));
        assertEquals(List.of(), ids(response));
        assertEquals(5, response.getTotalAlerts());
        assertNull(response.getPrevCursor());
        assertNull(response.getNextCursor());
    }

    public void testGetAlertsPage_prev() throws IOException {
        Table table = new Table("asc", "start_time", null, 2, 0, null);
        // in the reverse sort: the alerts before the cursor, closest first
        GetAlertsPageResponse response = getAlertsPage(clientSearching(new AtomicReference<>(), searchResponse(List.of(
                hit(alert("a4", "m1", 4L), 1L, 4L, "i", "m1", 4L),
                hit(alert("a3", "m1", 3L), 1L, 3L, "i", "m1", 3L),
                hit(alert("a2", "m1", 2L), 1L, 2L, "i", "m1", 2L)), 5)), request(table, cursor(table, 5L, "i", "m1", 5L), PREV));
        // reversed back into the requested order
        assertEquals(List.of("a3", "a4"), ids(response));
        assertArrayEquals(new Object[] { 3L, "i", "m1", 3L }, AlertsCursor.decode(response.getPrevCursor(), table).getSortValues());
        assertArrayEquals(new Object[] { 4L, "i", "m1", 4L }, AlertsCursor.decode(response.getNextCursor(), table).getSortValues());

        // the first page
        response = getAlertsPage(clientSearching(new AtomicReference<>(), searchResponse(List.of(
                hit(alert("a2", "m1", 2L), 1L, 2L, "i", "m1", 2L),
                hit(alert("a1", "m1", 1L), 1L, 1L, "i", "m1", 1L)), 5)), request(table, cursor(table, 3L, "i", "m1", 3L), PREV));
        assertEquals(List.of("a1", "a2"), ids(response));
        assertNull(response.getPrevCursor());
        assertArrayEquals(new Object[] { 2L, "i", "m1", 2L }, AlertsCursor.decode(response.getNextCursor(), table).getSortValues());
    }

    public void testGetAlertsPage_keywordSortValues() throws IOException {
        Table table = new Table("desc", "monitor_name.keyword", null, 1, 0, null);
        GetAlertsPageResponse response = getAlertsPage(clientSearching(new AtomicReference<>(), searchResponse(List.of(
                hit(alert("a1", "m1", 1L), 1L, new BytesRef("windetector"), 1L, new BytesRef("i"), new BytesRef("m1"), 1L),
                hit(alert("a2", "m1", 2L), 1L, null, 2L, new BytesRef("i"), null, 2L)), 5)),
                request(table, cursor(table, "x", 1L, "i", "m1", 1L), NEXT));
        assertArrayEquals(new Object[] { "windetector", 1L, "i", "m1", 1L },
                AlertsCursor.decode(response.getPrevCursor(), table).getSortValues());
        assertArrayEquals(new Object[] { "windetector", 1L, "i", "m1", 1L },
                AlertsCursor.decode(response.getNextCursor(), table).getSortValues());
    }

    public void testGetAlertsPage_noMonitorsReturnsEmptyWithoutSearching() {
        Client client = clientWithThreadContext(new ThreadContext(Settings.EMPTY));
        AtomicReference<GetAlertsPageResponse> response = new AtomicReference<>();
        new AlertsService(client).getAlertsPage(List.of(new DetectorMonitors("d1", "windows", List.of(), Map.of())),
                request(new Table("asc", "start_time", null, 20, 0, null), null, NEXT),
                ActionListener.wrap(response::set, e -> fail(e.toString())));
        assertEquals(0, response.get().getTotalAlerts());
        assertNull(response.get().getNextCursor());
        verify(client, never()).search(any(SearchRequest.class), any(ActionListener.class));
    }

    public void testGetAlertsPage_searchedInStashedContext() throws IOException {
        ThreadContext threadContext = new ThreadContext(Settings.EMPTY);
        threadContext.putHeader("caller_header", "caller");
        Client client = clientWithThreadContext(threadContext);
        AtomicReference<String> headerDuringSearch = new AtomicReference<>("not searched");
        SearchResponse searchResponse = searchResponse(List.of(), 0);
        doAnswer(invocation -> {
            headerDuringSearch.set(threadContext.getHeader("caller_header"));
            ActionListener<SearchResponse> listener = invocation.getArgument(1);
            listener.onResponse(searchResponse);
            return null;
        }).when(client).search(any(SearchRequest.class), any(ActionListener.class));
        AtomicReference<String> headerInListener = new AtomicReference<>();
        new AlertsService(client).getAlertsPage(List.of(new DetectorMonitors("d1", "windows", List.of("m1"), Map.of())),
                request(new Table("asc", "start_time", null, 20, 0, null), null, NEXT),
                ActionListener.wrap(r -> headerInListener.set(threadContext.getHeader("caller_header")), e -> fail(e.toString())));
        assertNull(headerDuringSearch.get());
        assertEquals("caller", headerInListener.get());
    }

    public void testGetAlertsPage_searchClientErrorKeepsItsStatus() {
        Client client = clientWithThreadContext(new ThreadContext(Settings.EMPTY));
        doAnswer(invocation -> {
            ActionListener<SearchResponse> listener = invocation.getArgument(1);
            listener.onFailure(new SearchPhaseExecutionException("query", "all shards failed", new ShardSearchFailure[] {
                    new ShardSearchFailure(new IllegalArgumentException("Failed to parse search_after value")) }));
            return null;
        }).when(client).search(any(SearchRequest.class), any(ActionListener.class));
        AtomicReference<Exception> failure = new AtomicReference<>();
        new AlertsService(client).getAlertsPage(List.of(new DetectorMonitors("d1", "windows", List.of("m1"), Map.of())),
                request(new Table("asc", "start_time", null, 20, 0, null), null, NEXT),
                ActionListener.wrap(r -> fail("expected failure"), failure::set));
        assertEquals(RestStatus.BAD_REQUEST, ((OpenSearchException) failure.get()).status());
        assertTrue(failure.get().getMessage(), failure.get().getMessage().contains("Failed to parse search_after value"));
    }

    /** A detector id is got as the caller with GetDetectorAction: its alerts are searched in its log type's indices. */
    public void testGetAlertsPageByDetectorId_searchesTheDetectorsAlerts() throws IOException {
        AtomicReference<SearchRequest> searched = new AtomicReference<>();
        Client client = clientSearching(searched, searchResponse(List.of(hit(alert("a1", "chained", 1L), 1L, 1L, "i", "chained", 1L)), 1));
        AtomicReference<GetDetectorRequest> getDetectorRequest = new AtomicReference<>();
        Detector detector = mock(Detector.class);
        when(detector.getId()).thenReturn("network_detector");
        when(detector.getDetectorType()).thenReturn("Network");
        when(detector.getMonitorIds()).thenReturn(List.of("doc", "bucket", "chained"));
        when(detector.getRuleIdMonitorIdMap()).thenReturn(Map.of("-1", "doc", "rule", "bucket",
                org.opensearch.securityanalytics.transport.TransportIndexDetectorAction.CHAINED_FINDINGS_MONITOR_STRING, "chained"));
        doAnswer(invocation -> {
            getDetectorRequest.set(invocation.getArgument(1));
            ActionListener<GetDetectorResponse> listener = invocation.getArgument(2);
            listener.onResponse(new GetDetectorResponse("network_detector", 1L, RestStatus.OK, detector));
            return null;
        }).when(client).execute(eq(GetDetectorAction.INSTANCE), any(GetDetectorRequest.class), any(ActionListener.class));

        AtomicReference<GetAlertsPageResponse> response = new AtomicReference<>();
        new AlertsService(client).getAlertsPageByDetectorId("network_detector",
                request(new Table("asc", "start_time", null, 20, 0, null), null, NEXT),
                ActionListener.wrap(response::set, e -> fail(e.toString())));
        assertEquals("network_detector", getDetectorRequest.get().getDetectorId());
        assertArrayEquals(new String[] { ".opensearch-sap-network-alerts*" }, searched.get().indices());
        BoolQueryBuilder query = (BoolQueryBuilder) searched.get().source().query();
        assertTrue(query.filter().contains(QueryBuilders.termsQuery("monitor_id", List.of("doc", "chained"))));
        assertEquals(List.of("a1"), ids(response.get()));
        assertEquals("network_detector", response.get().getAlerts().get(0).getDetectorId());
    }

    /** A detector the caller cannot access fails as GetDetectorAction fails, without searching alerts. */
    public void testGetAlertsPageByDetectorId_accessDenied() {
        Client client = clientWithThreadContext(new ThreadContext(Settings.EMPTY));
        doAnswer(invocation -> {
            ActionListener<GetDetectorResponse> listener = invocation.getArgument(2);
            listener.onFailure(new OpenSearchStatusException("Do not have permissions to resource", RestStatus.FORBIDDEN));
            return null;
        }).when(client).execute(eq(GetDetectorAction.INSTANCE), any(GetDetectorRequest.class), any(ActionListener.class));
        AtomicReference<Exception> failure = new AtomicReference<>();
        new AlertsService(client).getAlertsPageByDetectorId("d1", request(new Table("asc", "start_time", null, 20, 0, null), null, NEXT),
                ActionListener.wrap(r -> fail("expected failure"), failure::set));
        assertEquals(RestStatus.FORBIDDEN, ((OpenSearchStatusException) failure.get()).status());
        verify(client, never()).search(any(SearchRequest.class), any(ActionListener.class));
    }

    private static GetAlertsPageResponse getAlertsPage(Client client, GetAlertsPageRequest request) {
        assertNull(request.validate());
        AtomicReference<GetAlertsPageResponse> response = new AtomicReference<>();
        new AlertsService(client).getAlertsPage(List.of(new DetectorMonitors("d1", "windows", List.of("m1"), Map.of())), request,
                ActionListener.wrap(response::set, e -> {
                    throw new AssertionError(e);
                }));
        assertNotNull(response.get());
        return response.get();
    }

    private static List<String> ids(GetAlertsPageResponse response) {
        return response.getAlerts().stream().map(AlertDto::getId).collect(Collectors.toList());
    }

    private static Alert alert(String id, String monitorId, long startTime) {
        return AlertingServiceTests.alert(id, monitorId, startTime);
    }

    private static Client clientSearching(AtomicReference<SearchRequest> searched, SearchResponse searchResponse) {
        Client client = clientWithThreadContext(new ThreadContext(Settings.EMPTY));
        doAnswer(invocation -> {
            searched.set(invocation.getArgument(0));
            ActionListener<SearchResponse> listener = invocation.getArgument(1);
            listener.onResponse(searchResponse);
            return null;
        }).when(client).search(any(SearchRequest.class), any(ActionListener.class));
        return client;
    }

    private static Client clientWithThreadContext(ThreadContext threadContext) {
        Client client = mock(Client.class);
        ThreadPool threadPool = mock(ThreadPool.class);
        when(threadPool.getThreadContext()).thenReturn(threadContext);
        when(client.threadPool()).thenReturn(threadPool);
        return client;
    }

    private static SearchHit hit(Alert alert, long version, Object... sortValues) throws IOException {
        SearchHit hit = new SearchHit(0, alert.getId(), Collections.emptyMap(), Collections.emptyMap());
        hit.sourceRef(BytesReference.bytes(alert.toXContent(XContentFactory.jsonBuilder(), ToXContent.EMPTY_PARAMS)));
        hit.version(version);
        DocValueFormat[] formats = new DocValueFormat[sortValues.length];
        java.util.Arrays.fill(formats, DocValueFormat.RAW);
        hit.sortValues(sortValues, formats);
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
