/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package org.opensearch.securityanalytics.findings;

import java.time.Instant;
import java.time.ZoneId;
import java.util.ArrayDeque;
import java.util.Collections;
import java.util.List;
import java.util.Queue;
import java.util.stream.Collectors;
import org.opensearch.action.ActionListener;
import org.opensearch.client.Client;
import org.opensearch.commons.alerting.model.CronSchedule;
import org.opensearch.commons.alerting.model.DocLevelQuery;
import org.opensearch.commons.alerting.model.Finding;
import org.opensearch.commons.alerting.model.FindingDocument;
import org.opensearch.commons.alerting.model.FindingWithDocs;
import org.opensearch.commons.alerting.model.Table;
import org.opensearch.rest.RestStatus;
import org.opensearch.securityanalytics.action.FindingDto;
import org.opensearch.securityanalytics.action.GetDetectorAction;
import org.opensearch.securityanalytics.action.GetDetectorRequest;
import org.opensearch.securityanalytics.action.GetDetectorResponse;
import org.opensearch.securityanalytics.action.GetFindingsResponse;
import org.opensearch.securityanalytics.config.monitors.DetectorMonitorConfig;
import org.opensearch.securityanalytics.model.Detector;
import org.opensearch.test.OpenSearchTestCase;


import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.spy;

public class FindingServiceTests extends OpenSearchTestCase {

    public void testGetFindings_success() {
        FindingsService findingsService = spy(FindingsService.class);
        Client client = mock(Client.class);
        findingsService.setIndicesAdminClient(client);
        // Create fake GetDetectorResponse
        Detector detector = new Detector(
                "detector_id123",
                0L,
                "test-monitor",
                true,
                new CronSchedule("31 * * * *", ZoneId.of("Asia/Kolkata"), Instant.ofEpochSecond(1538164858L)),
                Instant.now(),
                Instant.now(),
                Detector.DetectorType.OTHERS_APPLICATION,
                null,
                List.of(),
                List.of(),
                List.of("monitor_id1", "monitor_id2"),
                DetectorMonitorConfig.getRuleIndex(Detector.DetectorType.OTHERS_APPLICATION.getDetectorType()),
                null,
                DetectorMonitorConfig.getAlertsIndex(Detector.DetectorType.OTHERS_APPLICATION.getDetectorType()),
                null,
                null,
                DetectorMonitorConfig.getFindingsIndex(Detector.DetectorType.OTHERS_APPLICATION.getDetectorType()),
                Collections.emptyMap()
        );
        GetDetectorResponse getDetectorResponse = new GetDetectorResponse("detector_id123", 1L, RestStatus.OK, detector);

        // Setup getDetector interceptor and return fake GetDetectorResponse by calling listener.onResponse
        doAnswer(invocation -> {
            ActionListener l = invocation.getArgument(2);
            l.onResponse(getDetectorResponse);
            return null;
        }).when(client).execute(eq(GetDetectorAction.INSTANCE), any(GetDetectorRequest.class), any(ActionListener.class));

        // Alerting GetFindingsResponse mock #1
        Finding finding1 = new Finding(
                "1",
                List.of("doc1", "doc2", "doc3"),
                List.of("doc1", "doc2", "doc3"),
                "monitor_id1",
                "monitor_name1",
                "test_index1",
                List.of(new DocLevelQuery("1","myQuery","fieldA:valABC", List.of())),
                Instant.now()
        );
        FindingDocument findingDocument1 = new FindingDocument("test_index1", "doc1", true, "document 1 payload");
        FindingDocument findingDocument2 = new FindingDocument("test_index1", "doc2", true, "document 2 payload");
        FindingDocument findingDocument3 = new FindingDocument("test_index1", "doc3", true, "document 3 payload");

        // Alerting GetFindingsResponse mock #2
        Finding finding2 = new Finding(
                "1",
                List.of("doc21", "doc22"),
                List.of("doc21", "doc22"),
                "monitor_id2",
                "monitor_name2",
                "test_index2",
                List.of(new DocLevelQuery("1","myQuery","fieldA:valABC", List.of())),
                Instant.now()
        );
        FindingDocument findingDocument21 = new FindingDocument("test_index2", "doc21", true, "document 21 payload");
        FindingDocument findingDocument22 = new FindingDocument("test_index2", "doc22", true, "document 22 payload");

        GetFindingsResponse getFindingsResponse =
                new GetFindingsResponse(
                        2,
                        List.of(
                            new FindingDto(
                                detector.getId(),
                                finding1.getId(),
                                finding1.getRelatedDocIds(),
                                finding1.getIndex(),
                                finding1.getDocLevelQueries(),
                                finding1.getTimestamp(),
                                List.of(findingDocument1, findingDocument2, findingDocument3)
                            ),
                            new FindingDto(
                                    detector.getId(),
                                    finding2.getId(),
                                    finding2.getRelatedDocIds(),
                                    finding2.getIndex(),
                                    finding2.getDocLevelQueries(),
                                    finding2.getTimestamp(),
                                    List.of(findingDocument1, findingDocument2, findingDocument3)
                            )
                        )
                );
        doAnswer(invocation -> {
            ActionListener l = invocation.getArgument(4);
            l.onResponse(getFindingsResponse);
            return null;
        }).when(findingsService).getFindingsByMonitorIds(any(), any(), anyString(), any(Table.class), any(ActionListener.class));

        // Call getFindingsByDetectorId
        Table table = new Table(
            "asc",
            "id",
            null,
            100,
            0,
            null
        );
        findingsService.getFindingsByDetectorId("detector_id123", table, new ActionListener<>() {
            @Override
            public void onResponse(GetFindingsResponse getFindingsResponse) {
                assertEquals(2, (int)getFindingsResponse.getTotalFindings());
                assertEquals(2, getFindingsResponse.getFindings().size());
            }

            @Override
            public void onFailure(Exception e) {

            }
        });
    }

    public void testGetFindings_getFindingsByMonitorIdFailure() {

        FindingsService findingsService = spy(FindingsService.class);
        Client client = mock(Client.class);
        findingsService.setIndicesAdminClient(client);
        // Create fake GetDetectorResponse
        Detector detector = new Detector(
                "detector_id123",
                0L,
                "test-monitor",
                true,
                new CronSchedule("31 * * * *", ZoneId.of("Asia/Kolkata"), Instant.ofEpochSecond(1538164858L)),
                Instant.now(),
                Instant.now(),
                Detector.DetectorType.OTHERS_APPLICATION,
                null,
                List.of(),
                List.of(),
                List.of("monitor_id1", "monitor_id2"),
                DetectorMonitorConfig.getRuleIndex(Detector.DetectorType.OTHERS_APPLICATION.getDetectorType()),
                null,
                DetectorMonitorConfig.getAlertsIndex(Detector.DetectorType.OTHERS_APPLICATION.getDetectorType()),
                null,
                null,
                DetectorMonitorConfig.getFindingsIndex(Detector.DetectorType.OTHERS_APPLICATION.getDetectorType()),
                Collections.emptyMap()
        );
        GetDetectorResponse getDetectorResponse = new GetDetectorResponse("detector_id123", 1L, RestStatus.OK, detector);

        // Setup getDetector interceptor and return fake GetDetectorResponse by calling listener.onResponse
        doAnswer(invocation -> {
            ActionListener l = invocation.getArgument(2);
            l.onResponse(getDetectorResponse);
            return null;
        }).when(client).execute(eq(GetDetectorAction.INSTANCE), any(GetDetectorRequest.class), any(ActionListener.class));

        doAnswer(invocation -> {
            ActionListener l = invocation.getArgument(4);
            l.onFailure(new IllegalArgumentException("Error getting findings"));
            return null;
        }).when(findingsService).getFindingsByMonitorIds(any(), any(), anyString(), any(Table.class), any(ActionListener.class));

        // Call getFindingsByDetectorId
        Table table = new Table(
                "asc",
                "id",
                null,
                100,
                0,
                null
        );
        findingsService.getFindingsByDetectorId("detector_id123", table, new ActionListener<>() {
            @Override
            public void onResponse(GetFindingsResponse getFindingsResponse) {
                fail("this test should've failed");
            }

            @Override
            public void onFailure(Exception e) {
                assertTrue(e.getMessage().contains("Error getting findings"));
            }
        });
    }

    public void testGetFindings_getDetectorFailure() {

        FindingsService findingsService = spy(FindingsService.class);
        Client client = mock(Client.class);
        findingsService.setIndicesAdminClient(client);

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
        findingsService.getFindingsByDetectorId("detector_id123", table, new ActionListener<>() {
            @Override
            public void onResponse(GetFindingsResponse getFindingsResponse) {
                fail("this test should've failed");
            }

            @Override
            public void onFailure(Exception e) {
                assertTrue(e.getMessage().contains("GetDetector failed"));
            }
        });
    }
}
