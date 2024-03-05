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
import org.opensearch.core.action.ActionListener;
import org.opensearch.client.Client;
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


import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.spy;

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
                        Monitor.MonitorType.DOC_LEVEL_MONITOR,
                        null,
                        1,
                        List.of(),
                        List.of(),
                        Map.of(),
                        new DataSources(),
                        TransportIndexDetectorAction.PLUGIN_OWNER_FIELD
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
                        Monitor.MonitorType.DOC_LEVEL_MONITOR,
                        null,
                        1,
                        List.of(),
                        List.of(),
                        Map.of(),
                        new DataSources(),
                        TransportIndexDetectorAction.PLUGIN_OWNER_FIELD
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
            ActionListener l = invocation.getArgument(6);
            l.onResponse(getAlertsResponse);
            return null;
        }).when(alertssService).getAlertsByMonitorIds(any(), any(), anyString(), any(Table.class), anyString(), anyString(), any(ActionListener.class));

        // Call getFindingsByDetectorId
        Table table = new Table(
                "asc",
                "id",
                null,
                100,
                0,
                null
        );
        alertssService.getAlertsByDetectorId("detector_id123", table, "severity_low", Alert.State.COMPLETED.toString(), new ActionListener<>() {
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
            ActionListener l = invocation.getArgument(6);
            l.onFailure(new IllegalArgumentException("Error getting findings"));
            return null;
        }).when(alertssService).getAlertsByMonitorIds(any(), any(), anyString(), any(Table.class), anyString(), anyString(), any(ActionListener.class));

        // Call getFindingsByDetectorId
        Table table = new Table(
                "asc",
                "id",
                null,
                100,
                0,
                null
        );
        alertssService.getAlertsByDetectorId("detector_id123", table, "severity_low", Alert.State.COMPLETED.toString(), new ActionListener<>() {
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
        alertssService.getAlertsByDetectorId("detector_id123", table, "severity_low", Alert.State.COMPLETED.toString(), new ActionListener<>() {
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
}