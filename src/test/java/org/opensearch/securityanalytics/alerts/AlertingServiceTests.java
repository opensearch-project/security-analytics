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
import java.util.concurrent.atomic.AtomicReference;
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
            ActionListener l = invocation.getArgument(8);
            l.onResponse(getAlertsResponse);
            return null;
        }).when(alertssService).getAlertsByMonitorIds(any(), any(), anyString(), any(Table.class), anyString(), anyString(), any(), any(), any(ActionListener.class));

        // Call getFindingsByDetectorId
        Table table = new Table(
                "asc",
                "id",
                null,
                100,
                0,
                null
        );
        alertssService.getAlertsByDetectorId("detector_id123", table, "severity_low", Alert.State.COMPLETED.toString(), null, null,
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
            ActionListener l = invocation.getArgument(8);
            l.onFailure(new IllegalArgumentException("Error getting findings"));
            return null;
        }).when(alertssService).getAlertsByMonitorIds(any(), any(), anyString(), any(Table.class), anyString(), anyString(), any(), any(), any(ActionListener.class));

        // Call getFindingsByDetectorId
        Table table = new Table(
                "asc",
                "id",
                null,
                100,
                0,
                null
        );
        alertssService.getAlertsByDetectorId("detector_id123", table, "severity_low", Alert.State.COMPLETED.toString(), null, null,
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
        alertssService.getAlertsByDetectorId("detector_id123", table, "severity_low", Alert.State.COMPLETED.toString(), null, null,
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
                null, null, ActionListener.wrap(response::set, failure::set));

        assertNull(failure.get());
        assertNotNull(response.get());
        assertEquals(0, (int) response.get().getTotalAlerts());
        assertTrue(response.get().getAlerts().isEmpty());
        // only the GetDetector call happens, Alerting's get alerts action is never executed
        verify(client, times(1)).execute(any(ActionType.class), any(), any(ActionListener.class));
        verify(client, never()).execute(any(ActionType.class), any(org.opensearch.commons.alerting.action.GetAlertsRequest.class), any(ActionListener.class));
    }

    public void testGetAlertsByDetectors_allDetectorsWithoutMonitors_returnsEmptyWithoutCallingAlerting() {
        NodeClient client = mock(NodeClient.class);
        AlertsService alertsService = new AlertsService(client);
        AtomicReference<GetAlertsResponse> response = new AtomicReference<>();
        alertsService.getAlerts(
                List.of(detectorWithMonitors("d1", List.of(), Collections.emptyMap()), detectorWithMonitors("d2", List.of(), Collections.emptyMap())),
                "others_application",
                new Table("asc", "start_time", null, 20, 0, null),
                "ALL",
                "ALL",
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

    public void testGetAlertsByDetectors_usesSameMonitorsAsGetAlertsByDetectorId() {
        NodeClient client = mock(NodeClient.class);
        AtomicReference<org.opensearch.commons.alerting.action.GetAlertsRequest> sentRequest = new AtomicReference<>();
        doAnswer(invocation -> {
            sentRequest.set(invocation.getArgument(1));
            ActionListener l = invocation.getArgument(2);
            l.onResponse(new org.opensearch.commons.alerting.action.GetAlertsResponse(List.of(), 0));
            return null;
        }).when(client).execute(any(ActionType.class), any(org.opensearch.commons.alerting.action.GetAlertsRequest.class), any(ActionListener.class));
        AlertsService alertsService = new AlertsService(client);
        alertsService.getAlerts(
                List.of(
                        detectorWithMonitors("d1", List.of("doc", "bucket", "chained"),
                                Map.of("-1", "doc", "rule_1", "bucket", TransportIndexDetectorAction.CHAINED_FINDINGS_MONITOR_STRING, "chained")),
                        detectorWithMonitors("d2", List.of("m2"), Map.of())
                ),
                "others_application",
                new Table("asc", "start_time", null, 20, 0, null),
                "ALL",
                "ALL",
                null,
                null,
                ActionListener.wrap(r -> {}, e -> fail(e.getMessage()))
        );
        assertEquals(List.of("doc", "chained", "m2"), sentRequest.get().getMonitorIds());
    }
}
