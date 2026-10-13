/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package org.opensearch.securityanalytics.alerts;

import java.time.Instant;
import java.time.ZoneId;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.atomic.AtomicReference;
import java.util.stream.Collectors;
import org.opensearch.OpenSearchException;
import org.opensearch.OpenSearchStatusException;
import org.opensearch.action.search.SearchPhaseExecutionException;
import org.opensearch.action.search.ShardSearchFailure;
import org.opensearch.index.query.QueryBuilder;
import org.opensearch.index.query.TermsQueryBuilder;
import org.opensearch.action.ActionType;
import org.opensearch.core.action.ActionListener;
import org.opensearch.commons.alerting.model.Alert;
import org.opensearch.commons.alerting.model.CronSchedule;
import org.opensearch.commons.alerting.model.DataSources;
import org.opensearch.commons.alerting.model.DocumentLevelTrigger;
import org.opensearch.commons.alerting.model.Monitor;
import org.opensearch.commons.alerting.model.Table;
import org.opensearch.core.rest.RestStatus;
import org.opensearch.script.Script;
import org.opensearch.securityanalytics.action.AlertDto;
import org.opensearch.securityanalytics.action.GetAlertsResponse;
import org.opensearch.securityanalytics.action.GetDetectorAction;
import org.opensearch.securityanalytics.action.GetDetectorRequest;
import org.opensearch.securityanalytics.action.GetDetectorResponse;
import org.opensearch.securityanalytics.config.monitors.DetectorMonitorConfig;
import org.opensearch.securityanalytics.model.Detector;
import org.opensearch.securityanalytics.transport.TransportIndexDetectorAction;
import org.opensearch.test.OpenSearchTestCase;
import org.opensearch.transport.client.Client;
import org.opensearch.transport.client.node.NodeClient;


import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;

public class AlertingServiceTests extends OpenSearchTestCase {

    public void testGetAlerts_success() {
        AlertsService alertssService = spy(AlertsService.class);
        Client client = mock(Client.class);
        alertssService.setIndicesAdminClient(client);
        // Create fake GetDetectorResponse
        Detector detector = new Detector(
                "detector_id123",
                0L,
                "test-monitor",
                true,
                new CronSchedule("31 * * * *", ZoneId.of("Asia/Kolkata"), Instant.ofEpochSecond(1538164858L)),
                Instant.now(),
                Instant.now(),
                "others_application",
                null,
                List.of(),
                List.of(),
                List.of("monitor_id1", "monitor_id2"),
                DetectorMonitorConfig.getRuleIndex("others_application"),
                null,
                DetectorMonitorConfig.getAlertsIndex("others_application"),
                null,
                null,
                DetectorMonitorConfig.getFindingsIndex("others_application"),
                Collections.emptyMap(),
                Collections.emptyList(),
                false
        );
        GetDetectorResponse getDetectorResponse = new GetDetectorResponse("detector_id123", 1L, RestStatus.OK, detector);

        // Setup getDetector interceptor and return fake GetDetectorResponse by calling listener.onResponse
        doAnswer(invocation -> {
            ActionListener l = invocation.getArgument(2);
            l.onResponse(getDetectorResponse);
            return null;
        }).when(client).execute(eq(GetDetectorAction.INSTANCE), any(GetDetectorRequest.class), any(ActionListener.class));

        // Alerting GetAlertsResponse mock #1
        Alert alert1 = new Alert(
                "alert_id_1",
                new Monitor(
                        "monitor_id_1",
                        -3,
                        "monitor_name",
                        true,
                        new CronSchedule("31 * * * *", ZoneId.of("Asia/Kolkata"), Instant.ofEpochSecond(1538164858L)),
                        Instant.now(),
                        Instant.now(),
                        Monitor.MonitorType.DOC_LEVEL_MONITOR.getValue(),
                        null,
                        1,
                        List.of(),
                        List.of(),
                        Map.of(),
                        new DataSources(),
                        true,
                        null,
                        TransportIndexDetectorAction.PLUGIN_OWNER_FIELD,
                        null,
                        null
                ),
                new DocumentLevelTrigger("trigger_id_1", "my_trigger", "severity_low", List.of(), new Script("")),
                List.of("finding_id_1"),
                List.of("docId1"),
                Instant.now(),
                Instant.now(),
                Alert.State.COMPLETED,
                null,
                List.of(),
                List.of(),
                3,
                null,
                null,
                null
        );

        Alert alert2 = new Alert(
                "alert_id_1",
                new Monitor(
                        "monitor_id_1",
                        -3,
                        "monitor_name",
                        true,
                        new CronSchedule("31 * * * *", ZoneId.of("Asia/Kolkata"), Instant.ofEpochSecond(1538164858L)),
                        Instant.now(),
                        Instant.now(),
                        Monitor.MonitorType.DOC_LEVEL_MONITOR.getValue(),
                        null,
                        1,
                        List.of(),
                        List.of(),
                        Map.of(),
                        new DataSources(),
                        true,
                        null,
                        TransportIndexDetectorAction.PLUGIN_OWNER_FIELD,
                        null,
                        null
                ),
                new DocumentLevelTrigger("trigger_id_1", "my_trigger", "severity_low", List.of(), new Script("")),
                List.of("finding_id_1"),
                List.of("docId1"),
                Instant.now(),
                Instant.now(),
                Alert.State.COMPLETED,
                null,
                List.of(),
                List.of(),
                3,
                null,
                null,
                null
        );

        GetAlertsResponse getAlertsResponse = new GetAlertsResponse(
                List.of(new AlertDto(
                                detector.getId(),
                                alert1.getId(),
                                alert1.getVersion(),
                                alert1.getSchemaVersion(),
                                alert1.getTriggerId(),
                                alert1.getTriggerName(),
                                alert1.getFindingIds(),
                                alert1.getRelatedDocIds(),
                                alert1.getState(),
                                alert1.getStartTime(),
                                alert1.getEndTime(),
                                alert1.getLastNotificationTime(),
                                alert1.getAcknowledgedTime(),
                                alert1.getErrorMessage(),
                                alert1.getErrorHistory(),
                                alert1.getSeverity(),
                                alert1.getActionExecutionResults(),
                                alert1.getAggregationResultBucket()
                        ),
                        new AlertDto(
                                detector.getId(),
                                alert2.getId(),
                                alert2.getVersion(),
                                alert2.getSchemaVersion(),
                                alert2.getTriggerId(),
                                alert2.getTriggerName(),
                                alert2.getFindingIds(),
                                alert2.getRelatedDocIds(),
                                alert2.getState(),
                                alert2.getStartTime(),
                                alert2.getEndTime(),
                                alert2.getLastNotificationTime(),
                                alert2.getAcknowledgedTime(),
                                alert2.getErrorMessage(),
                                alert2.getErrorHistory(),
                                alert2.getSeverity(),
                                alert2.getActionExecutionResults(),
                                alert2.getAggregationResultBucket()
                        )
                ), 2
        );

        doAnswer(invocation -> {
            ActionListener l = invocation.getArgument(10);
            l.onResponse(getAlertsResponse);
            return null;
        }).when(alertssService).getAlertsByMonitorIds(any(), any(), anyString(), any(Table.class), anyString(), anyString(), any(), any(), any(), any(), any(ActionListener.class));

        // Call getFindingsByDetectorId
        Table table = new Table(
                "asc",
                "id",
                null,
                100,
                0,
                null
        );
        alertssService.getAlertsByDetectorId("detector_id123", table, "severity_low", Alert.State.COMPLETED.toString(), List.of(), List.of(), null, null,
          new ActionListener<>() {
            @Override
            public void onResponse(GetAlertsResponse getAlertsResponse) {
                assertEquals(2, (int)getAlertsResponse.getTotalAlerts());
                assertEquals(2, getAlertsResponse.getAlerts().size());
            }

            @Override
            public void onFailure(Exception e) {

            }
        });
    }

    public void testGetFindings_getFindingsByMonitorIdFailures() {

        AlertsService alertssService = spy(AlertsService.class);
        Client client = mock(Client.class);
        alertssService.setIndicesAdminClient(client);
        // Create fake GetDetectorResponse
        Detector detector = new Detector(
                "detector_id123",
                0L,
                "test-monitor",
                true,
                new CronSchedule("31 * * * *", ZoneId.of("Asia/Kolkata"), Instant.ofEpochSecond(1538164858L)),
                Instant.now(),
                Instant.now(),
                "others_application",
                null,
                List.of(),
                List.of(),
                List.of("monitor_id1", "monitor_id2"),
                DetectorMonitorConfig.getRuleIndex("others_application"),
                null,
                DetectorMonitorConfig.getAlertsIndex("others_application"),
                null,
                null,
                DetectorMonitorConfig.getFindingsIndex("others_application"),
                Collections.emptyMap(),
                Collections.emptyList(),
                false
        );
        GetDetectorResponse getDetectorResponse = new GetDetectorResponse("detector_id123", 1L, RestStatus.OK, detector);

        // Setup getDetector interceptor and return fake GetDetectorResponse by calling listener.onResponse
        doAnswer(invocation -> {
            ActionListener l = invocation.getArgument(2);
            l.onResponse(getDetectorResponse);
            return null;
        }).when(client).execute(eq(GetDetectorAction.INSTANCE), any(GetDetectorRequest.class), any(ActionListener.class));

        doAnswer(invocation -> {
            ActionListener l = invocation.getArgument(10);
            l.onFailure(new IllegalArgumentException("Error getting findings"));
            return null;
        }).when(alertssService).getAlertsByMonitorIds(any(), any(), anyString(), any(Table.class), anyString(), anyString(), any(), any(), any(), any(), any(ActionListener.class));

        // Call getFindingsByDetectorId
        Table table = new Table(
                "asc",
                "id",
                null,
                100,
                0,
                null
        );
        alertssService.getAlertsByDetectorId("detector_id123", table, "severity_low", Alert.State.COMPLETED.toString(), List.of(), List.of(), null, null,
          new ActionListener<>() {
            @Override
            public void onResponse(GetAlertsResponse getAlertsResponse) {
                fail("this test should've failed");
            }

            @Override
            public void onFailure(Exception e) {
                assertTrue(e.getMessage().contains("Error getting findings"));
            }
        });
    }

    public void testGetFindings_getDetectorFailure() {

        AlertsService alertssService = spy(AlertsService.class);
        Client client = mock(Client.class);
        alertssService.setIndicesAdminClient(client);

        // Setup getDetector interceptor and return fake expcetion by calling onFailure
        doAnswer(invocation -> {
            ActionListener l = invocation.getArgument(2);
            l.onFailure(new IllegalArgumentException("GetDetector failed"));
            return null;
        }).when(client).execute(eq(GetDetectorAction.INSTANCE), any(GetDetectorRequest.class), any(ActionListener.class));

        // Call getFindingsByDetectorId
        Table table = new Table(
                "asc",
                "id",
                null,
                100,
                0,
                null
        );
        alertssService.getAlertsByDetectorId("detector_id123", table, "severity_low", Alert.State.COMPLETED.toString(), List.of(), List.of(), null, null,
          new ActionListener<>() {
            @Override
            public void onResponse(GetAlertsResponse getAlertsResponse) {
                fail("this test should've failed");
            }

            @Override
            public void onFailure(Exception e) {
                assertTrue(e.getMessage().contains("GetDetector failed"));
            }
        });
    }

    public void testGetAlertsByMonitorIds_emptyMonitorIds_doesNotCallAlerting() {
        NodeClient client = mock(NodeClient.class);
        AlertsService alertsService = new AlertsService(client);
        Table table = new Table("asc", "start_time", null, 20, 0, null);

        for (List<String> monitorIds : java.util.Arrays.asList(null, List.<String>of())) {
            AtomicReference<GetAlertsResponse> response = new AtomicReference<>();
            AtomicReference<Exception> failure = new AtomicReference<>();
            alertsService.getAlertsByMonitorIds(
                    Map.of(),
                    monitorIds,
                    DetectorMonitorConfig.getAllAlertsIndicesPattern("windows"),
                    table,
                    "ALL",
                    "ALL",
                    List.of(),
                    List.of(),
                    null,
                    null,
                    ActionListener.wrap(response::set, failure::set)
            );
            assertNull(failure.get());
            assertNotNull("listener must be notified", response.get());
            assertEquals(0, (int) response.get().getTotalAlerts());
            assertTrue(response.get().getAlerts().isEmpty());
        }
        // Alerting must never be invoked: an empty monitor id list makes Alerting skip the monitor_id filter
        verifyNoInteractions(client);
    }

    public void testGetAlertsByMonitorIds_nonEmptyMonitorIds_sendsMonitorIdsToAlerting() {
        NodeClient client = mock(NodeClient.class);
        AlertsService alertsService = new AlertsService(client);
        AtomicReference<org.opensearch.commons.alerting.action.GetAlertsRequest> sentRequest = new AtomicReference<>();
        doAnswer(invocation -> {
            sentRequest.set(invocation.getArgument(1));
            ActionListener l = invocation.getArgument(2);
            l.onResponse(new org.opensearch.commons.alerting.action.GetAlertsResponse(List.of(), 0));
            return null;
        }).when(client).execute(any(ActionType.class), any(org.opensearch.commons.alerting.action.GetAlertsRequest.class), any(ActionListener.class));

        AtomicReference<GetAlertsResponse> response = new AtomicReference<>();
        alertsService.getAlertsByMonitorIds(
                Map.of("m1", "d1"),
                List.of("m1"),
                DetectorMonitorConfig.getAllAlertsIndicesPattern("windows"),
                new Table("asc", "start_time", null, 20, 0, null),
                "ALL",
                "ALL",
                List.of(),
                List.of(),
                null,
                null,
                ActionListener.wrap(response::set, e -> fail(e.getMessage()))
        );
        assertNotNull(response.get());
        assertNotNull(sentRequest.get());
        assertEquals(List.of("m1"), sentRequest.get().getMonitorIds());
        assertEquals(DetectorMonitorConfig.getAllAlertsIndicesPattern("windows"), sentRequest.get().getAlertIndex());
    }

    public void testGetAlertsByDetectorId_detectorWithoutMonitors_returnsEmptyWithoutCallingAlerting() {
        NodeClient client = mock(NodeClient.class);
        AlertsService alertsService = new AlertsService(client);
        Detector detector = detectorWithMonitors("detector_no_monitors", List.of(), Collections.emptyMap());
        GetDetectorResponse getDetectorResponse = new GetDetectorResponse(detector.getId(), 1L, RestStatus.OK, detector);
        doAnswer(invocation -> {
            ActionListener l = invocation.getArgument(2);
            l.onResponse(getDetectorResponse);
            return null;
        }).when(client).execute(eq(GetDetectorAction.INSTANCE), any(GetDetectorRequest.class), any(ActionListener.class));

        AtomicReference<GetAlertsResponse> response = new AtomicReference<>();
        AtomicReference<Exception> failure = new AtomicReference<>();
        alertsService.getAlertsByDetectorId(detector.getId(), new Table("asc", "start_time", null, 20, 0, null), "ALL", "ALL",
                List.of(), List.of(), null, null, ActionListener.wrap(response::set, failure::set));

        assertNull(failure.get());
        assertNotNull(response.get());
        assertEquals(0, (int) response.get().getTotalAlerts());
        assertTrue(response.get().getAlerts().isEmpty());
        // only the GetDetector call happens, Alerting's get alerts action is never executed
        verify(client, times(1)).execute(any(ActionType.class), any(), any(ActionListener.class));
        verify(client, never()).execute(any(ActionType.class), any(org.opensearch.commons.alerting.action.GetAlertsRequest.class), any(ActionListener.class));
    }

    public void testGetAlertsOfDetectorType_detectorsWithoutMonitors_returnsEmptyWithoutCallingAlerting() {
        NodeClient client = mock(NodeClient.class);
        AlertsService alertsService = new AlertsService(client);
        AtomicReference<GetAlertsResponse> response = new AtomicReference<>();
        alertsService.getAlertsOfDetectorType(
                monitorsOf(detectorWithMonitors("d1", List.of(), Collections.emptyMap()), detectorWithMonitors("d2", List.of(), Collections.emptyMap())),
                new Table("asc", "start_time", null, 20, 0, null),
                "ALL",
                "ALL",
                List.of(),
                List.of(),
                null,
                null,
                ActionListener.wrap(response::set, e -> fail(e.getMessage()))
        );
        assertNotNull(response.get());
        assertEquals(0, (int) response.get().getTotalAlerts());
        verifyNoInteractions(client);
    }

    public void testGetAlertsByAlertIds_emptyAlertIds_doesNotCallAlerting() {
        NodeClient client = mock(NodeClient.class);
        AlertsService alertsService = new AlertsService(client);
        Detector detector = detectorWithMonitors("d1", List.of("m1"), Collections.emptyMap());
        AtomicReference<org.opensearch.commons.alerting.action.GetAlertsResponse> response = new AtomicReference<>();
        alertsService.getAlerts(List.of(), detector, new Table("asc", "id", null, 10000, 0, null), null, null,
                ActionListener.wrap(response::set, e -> fail(e.getMessage())));
        assertNotNull(response.get());
        assertEquals(0, (int) response.get().getTotalAlerts());
        assertTrue(response.get().getAlerts().isEmpty());
        verifyNoInteractions(client);
    }

    private static List<DetectorMonitors> monitorsOf(Detector... detectors) {
        return java.util.Arrays.stream(detectors).map(DetectorMonitors::of).collect(Collectors.toList());
    }

    private static Detector detectorWithMonitors(String id, List<String> monitorIds, Map<String, String> ruleIdMonitorIdMap) {
        return new Detector(
                id,
                0L,
                "test-detector-" + id,
                true,
                new CronSchedule("31 * * * *", ZoneId.of("Asia/Kolkata"), Instant.ofEpochSecond(1538164858L)),
                Instant.now(),
                Instant.now(),
                "others_application",
                null,
                List.of(),
                List.of(),
                monitorIds,
                DetectorMonitorConfig.getRuleIndex("others_application"),
                null,
                DetectorMonitorConfig.getAlertsIndex("others_application"),
                null,
                null,
                DetectorMonitorConfig.getFindingsIndex("others_application"),
                ruleIdMonitorIdMap,
                Collections.emptyList(),
                false
        );
    }

    public void testGetAlertingMonitorToDetectorMapping() {
        // without chained findings monitor all monitors generate the detector's alerts
        Detector detector = detectorWithMonitors("d1", List.of("doc", "bucket"), Map.of("-1", "doc", "rule_1", "bucket"));
        assertEquals(List.of("doc", "bucket"), List.copyOf(AlertsService.getAlertingMonitorToDetectorMapping(detector).keySet()));
        assertEquals(Map.of("doc", "d1", "bucket", "d1"), AlertsService.getAlertingMonitorToDetectorMapping(detector));

        // with chained findings monitor only the chained findings monitor and the doc level monitor do
        detector = detectorWithMonitors("d2", List.of("doc", "bucket", "chained"),
                Map.of("-1", "doc", "rule_1", "bucket", TransportIndexDetectorAction.CHAINED_FINDINGS_MONITOR_STRING, "chained"));
        assertEquals(Map.of("doc", "d2", "chained", "d2"), AlertsService.getAlertingMonitorToDetectorMapping(detector));

        detector = detectorWithMonitors("d3", List.of("bucket", "chained"),
                Map.of("rule_1", "bucket", TransportIndexDetectorAction.CHAINED_FINDINGS_MONITOR_STRING, "chained"));
        assertEquals(Map.of("chained", "d3"), AlertsService.getAlertingMonitorToDetectorMapping(detector));

        assertTrue(AlertsService.getAlertingMonitorToDetectorMapping(detectorWithMonitors("d4", List.of(), Map.of())).isEmpty());
    }

    public void testGetAlertsOfDetectorType_usesSameMonitorsAsGetAlertsByDetectorId() {
        NodeClient client = mock(NodeClient.class);
        List<org.opensearch.commons.alerting.action.GetAlertsRequest> requests = stubAlerting(client, Map.of());
        AlertsService alertsService = new AlertsService(client);
        alertsService.getAlertsOfDetectorType(
                monitorsOf(
                        detectorWithMonitors("d1", List.of("doc", "bucket", "chained"),
                                Map.of("-1", "doc", "rule_1", "bucket", TransportIndexDetectorAction.CHAINED_FINDINGS_MONITOR_STRING, "chained")),
                        detectorWithMonitors("d2", List.of("m2"), Map.of())
                ),
                new Table("asc", "start_time", null, 20, 0, null),
                "ALL",
                "ALL",
                List.of(),
                List.of(),
                null,
                null,
                ActionListener.wrap(r -> {}, e -> fail(e.getMessage()))
        );
        assertEquals(1, requests.size());
        assertEquals(List.of("doc", "chained", "m2"), requests.get(0).getMonitorIds());
    }

    public void testGetAlertsOfDetectorType_singleAlertingCallWithRequestedPage() {
        NodeClient client = mock(NodeClient.class);
        List<org.opensearch.commons.alerting.action.GetAlertsRequest> requests = stubAlerting(client, Map.of(
                DetectorMonitorConfig.getAllAlertsIndicesPattern("others_application"),
                List.of(alert("a1", "m1", 1L), alert("a2", "m2", 2L), alert("a3", "m3", 3L),
                        alert("a4", "m1", 4L), alert("a5", "m1", 5L), alert("a6", "m3", 6L))));
        AlertsService alertsService = new AlertsService(client);
        Table table = new Table("asc", "start_time", null, 2, 4, "");

        AtomicReference<GetAlertsResponse> response = new AtomicReference<>();
        alertsService.getAlertsOfDetectorType(
                monitorsOf(
                        detectorWithMonitors("d1", List.of("m1", "m2"), Map.of()),
                        detectorWithMonitors("d2", List.of("m3"), Map.of()),
                        detectorWithMonitors("d3", List.of(), Map.of())
                ),
                table, "ALL", "ALL", List.of(), List.of(), null, null,
                ActionListener.wrap(response::set, e -> fail(e.getMessage())));

        assertEquals(1, requests.size());
        assertEquals(table, requests.get(0).getTable());
        assertEquals(List.of("m1", "m2", "m3"), requests.get(0).getMonitorIds());
        assertEquals(DetectorMonitorConfig.getAllAlertsIndicesPattern("others_application"), requests.get(0).getAlertIndex());
        // the page is the one returned by Alerting
        assertEquals(List.of("a5", "a6"), response.get().getAlerts().stream().map(AlertDto::getId).collect(Collectors.toList()));
        assertEquals(List.of("d1", "d2"), response.get().getAlerts().stream().map(AlertDto::getDetectorId).collect(Collectors.toList()));
        assertEquals(6, (int) response.get().getTotalAlerts());
    }

    public void testGetAlerts_multiValueFiltersAreTermsFilters() {
        NodeClient client = mock(NodeClient.class);
        List<org.opensearch.commons.alerting.action.GetAlertsRequest> requests = stubAlerting(client, Map.of());
        AlertsService alertsService = new AlertsService(client);
        alertsService.getAlertsByMonitorIds(Map.of("m1", "d1"), List.of("m1"), DetectorMonitorConfig.getAllAlertsIndicesPattern("windows"),
                new Table("asc", "start_time", null, 20, 0, ""), "ALL", "ALL", List.of("1", "2"), List.of("ACTIVE", "ACKNOWLEDGED"),
                Instant.ofEpochMilli(1000L), Instant.ofEpochMilli(2000L), ActionListener.wrap(r -> {}, e -> fail(e.getMessage())));

        assertEquals(1, requests.size());
        org.opensearch.commons.alerting.action.GetAlertsRequest request = requests.get(0);
        // Alerting's single value filters stay at ALL, which keeps Alerting's exclusion of AUDIT alerts
        assertEquals("ALL", request.getSeverityLevel());
        assertEquals("ALL", request.getAlertState());
        List<QueryBuilder> filters = request.getBoolQueryBuilder().filter();
        assertEquals(3, filters.size());
        TermsQueryBuilder severityFilter = (TermsQueryBuilder) filters.stream()
                .filter(f -> f instanceof TermsQueryBuilder && ((TermsQueryBuilder) f).fieldName().equals("severity")).findFirst().orElseThrow();
        assertEquals(List.of("1", "2"), severityFilter.values());
        TermsQueryBuilder stateFilter = (TermsQueryBuilder) filters.stream()
                .filter(f -> f instanceof TermsQueryBuilder && ((TermsQueryBuilder) f).fieldName().equals("state")).findFirst().orElseThrow();
        assertEquals(List.of("ACTIVE", "ACKNOWLEDGED"), stateFilter.values());

        // without multi value filters only the time range filter is added and the single value filters are passed on
        requests.clear();
        alertsService.getAlertsByMonitorIds(Map.of("m1", "d1"), List.of("m1"), DetectorMonitorConfig.getAllAlertsIndicesPattern("windows"),
                new Table("asc", "start_time", null, 20, 0, ""), "3", "COMPLETED", List.of(), List.of(),
                null, null, ActionListener.wrap(r -> {}, e -> fail(e.getMessage())));
        assertEquals("3", requests.get(0).getSeverityLevel());
        assertEquals("COMPLETED", requests.get(0).getAlertState());
        assertTrue(requests.get(0).getBoolQueryBuilder().filter().isEmpty());
    }

    public void testGetAlerts_searchRequestFailureKeepsClientErrorStatus() {
        NodeClient client = mock(NodeClient.class);
        SearchPhaseExecutionException searchFailure = new SearchPhaseExecutionException("query", "all shards failed",
                new ShardSearchFailure[] { new ShardSearchFailure(new IllegalArgumentException("Failed to parse query [(foo]")) });
        doAnswer(invocation -> {
            ActionListener l = invocation.getArgument(2);
            // the remote metadata sdk client wraps search failures in a 500
            l.onFailure(new OpenSearchStatusException("Failed to search indices", org.opensearch.core.rest.RestStatus.INTERNAL_SERVER_ERROR, searchFailure));
            return null;
        }).when(client).execute(any(ActionType.class), any(org.opensearch.commons.alerting.action.GetAlertsRequest.class), any(ActionListener.class));
        AlertsService alertsService = new AlertsService(client);

        AtomicReference<Exception> failure = new AtomicReference<>();
        alertsService.getAlertsOfDetectorType(monitorsOf(detectorWithMonitors("d1", List.of("m1"), Map.of())),
                new Table("asc", "start_time", null, 20, 0, ""), "ALL", "ALL", List.of(), List.of(), null, null,
                ActionListener.wrap(r -> fail("expected failure"), failure::set));
        assertNotNull(failure.get());
        assertEquals(RestStatus.BAD_REQUEST, ((OpenSearchException) failure.get()).status());
        assertEquals("Failed to parse query [(foo]", failure.get().getMessage());

        // server side failures are not turned into client errors
        Exception serverFailure = new OpenSearchStatusException("Failed to search indices", RestStatus.INTERNAL_SERVER_ERROR,
                new SearchPhaseExecutionException("query", "all shards failed",
                        new ShardSearchFailure[] { new ShardSearchFailure(new IllegalStateException("boom")) }));
        assertSame(serverFailure, AlertsService.unwrapSearchRequestFailure(serverFailure));
        Exception other = new IllegalStateException("other");
        assertSame(other, AlertsService.unwrapSearchRequestFailure(other));
    }

    /**
     * Not expected (detectors of a detector type all share its lowercased log type): detectors of several log types
     * are searched with the search of the alerts of all detectors, which supports the sortable fields only.
     */
    public void testGetAlertsOfDetectorType_severalLogTypesWithUnsupportedSortField_isClientErrorWithoutCallingAlerting() {
        NodeClient client = mock(NodeClient.class);
        AlertsService alertsService = new AlertsService(client);
        List<DetectorMonitors> detectors = monitorsOf(
                detectorWithMonitors("windows_detector", "windows", List.of("wm"), Map.of()),
                detectorWithMonitors("network_detector", "network", List.of("nm"), Map.of()));
        AtomicReference<Exception> failure = new AtomicReference<>();
        alertsService.getAlertsOfDetectorType(detectors, new Table("asc", "version", null, 20, 0, ""), "ALL", "ALL", List.of(), List.of(),
                null, null, ActionListener.wrap(r -> fail("expected failure"), failure::set));
        assertEquals(RestStatus.BAD_REQUEST, ((OpenSearchException) failure.get()).status());
        assertTrue(failure.get().getMessage(), failure.get().getMessage().contains("sortString [version] is not supported"));
        verifyNoInteractions(client);
    }

    public void testGetAlertsOfDetectorType_passesAnySortFieldToAlerting() {
        NodeClient client = mock(NodeClient.class);
        List<org.opensearch.commons.alerting.action.GetAlertsRequest> requests = stubAlerting(client, Map.of());
        AlertsService alertsService = new AlertsService(client);
        Table table = new Table("desc", "version", null, 20, 0, "");
        alertsService.getAlertsOfDetectorType(monitorsOf(detectorWithMonitors("d1", "windows", List.of("m1"), Map.of()),
                        detectorWithMonitors("d2", "windows", List.of("m2"), Map.of())), table, "ALL", "ALL", List.of(), List.of(), null, null,
                ActionListener.wrap(r -> {}, e -> fail(e.getMessage())));
        assertEquals(1, requests.size());
        assertEquals(table, requests.get(0).getTable());
    }

    /**
     * A detector stored with a mixed-case detector_type has the alert indices of the lowercased log type: detectors of
     * a detector type, whatever the case of their stored detector_type, are served by a single Alerting search.
     */
    public void testGetAlertsOfDetectorType_mixedCaseDetectorTypesCollapseToTheLowercasedLogType() {
        NodeClient client = mock(NodeClient.class);
        List<org.opensearch.commons.alerting.action.GetAlertsRequest> requests = stubAlerting(client, Map.of(
                DetectorMonitorConfig.getAllAlertsIndicesPattern("windows"),
                List.of(alert("w1", "m1", 2L), alert("w2", "m2", 1L), alert("w3", "m3", 0L))));
        AlertsService alertsService = new AlertsService(client);
        List<DetectorMonitors> detectors = List.of(
                new DetectorMonitors("d1", "Windows", List.of("m1"), Map.of()),
                new DetectorMonitors("d2", "windows", List.of("m2"), Map.of()),
                new DetectorMonitors("d3", "WINDOWS", List.of("m3"), Map.of()));
        assertEquals("windows", detectors.get(0).getDetectorType());

        AtomicReference<GetAlertsResponse> response = new AtomicReference<>();
        alertsService.getAlertsOfDetectorType(detectors, new Table("desc", "end_time", null, 20, 0, ""), "ALL", "ALL", List.of(), List.of(),
                null, null, ActionListener.wrap(response::set, e -> fail(e.getMessage())));
        assertEquals(1, requests.size());
        assertEquals(DetectorMonitorConfig.getAllAlertsIndicesPattern("windows"), requests.get(0).getAlertIndex());
        assertEquals(List.of("m1", "m2", "m3"), requests.get(0).getMonitorIds());
        assertEquals("end_time", requests.get(0).getTable().getSortString());
        assertEquals(List.of("w1", "w2", "w3"), response.get().getAlerts().stream().map(AlertDto::getId).collect(Collectors.toList()));
        assertEquals(List.of("d1", "d2", "d3"), response.get().getAlerts().stream().map(AlertDto::getDetectorId).collect(Collectors.toList()));
    }

    static Alert alert(String id, String monitorId, long startTime) {
        return alert(id, monitorId, startTime, "1", Alert.State.ACTIVE, "n");
    }

    static Alert alert(String id, String monitorId, long startTime, String severity, Alert.State state, String monitorName) {
        return new Alert(
                id,
                1L,
                5,
                monitorId,
                "",
                "",
                monitorName,
                1L,
                null,
                "trigger_id",
                "t",
                List.of(),
                List.of(),
                state,
                Instant.ofEpochMilli(startTime),
                null,
                null,
                null,
                null,
                List.of(),
                severity,
                List.of(),
                null,
                null,
                List.of(),
                null
        );
    }

    /**
     * Stubs Alerting's get alerts action: responds with the alerts configured for the request's alert index, limited
     * to the requested page, and records the requests.
     */
    private static List<org.opensearch.commons.alerting.action.GetAlertsRequest> stubAlerting(NodeClient client, Map<String, List<Alert>> alertsByIndex) {
        List<org.opensearch.commons.alerting.action.GetAlertsRequest> requests = new CopyOnWriteArrayList<>();
        doAnswer(invocation -> {
            org.opensearch.commons.alerting.action.GetAlertsRequest request = invocation.getArgument(1);
            requests.add(request);
            List<Alert> alerts = alertsByIndex.getOrDefault(request.getAlertIndex(), List.of());
            int from = Math.min(request.getTable().getStartIndex(), alerts.size());
            int to = Math.min(from + request.getTable().getSize(), alerts.size());
            ActionListener l = invocation.getArgument(2);
            l.onResponse(new org.opensearch.commons.alerting.action.GetAlertsResponse(alerts.subList(from, to), alerts.size()));
            return null;
        }).when(client).execute(any(ActionType.class), any(org.opensearch.commons.alerting.action.GetAlertsRequest.class), any(ActionListener.class));
        return requests;
    }

    static Detector detectorWithMonitors(String id, String logType, List<String> monitorIds, Map<String, String> ruleIdMonitorIdMap) {
        return new Detector(
                id,
                0L,
                "test-detector-" + id,
                true,
                new CronSchedule("31 * * * *", ZoneId.of("Asia/Kolkata"), Instant.ofEpochSecond(1538164858L)),
                Instant.now(),
                Instant.now(),
                logType,
                null,
                List.of(),
                List.of(),
                monitorIds,
                DetectorMonitorConfig.getRuleIndex(logType),
                null,
                DetectorMonitorConfig.getAlertsIndex(logType),
                null,
                null,
                DetectorMonitorConfig.getFindingsIndex(logType),
                ruleIdMonitorIdMap,
                Collections.emptyList(),
                false
        );
    }
}
