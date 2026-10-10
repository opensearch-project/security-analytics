/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package org.opensearch.securityanalytics.resthandler;

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicReference;
import org.opensearch.commons.alerting.model.Table;
import org.opensearch.core.action.ActionListener;
import org.opensearch.securityanalytics.action.GetAlertsAction;
import org.opensearch.securityanalytics.action.GetAlertsRequest;
import org.opensearch.test.OpenSearchTestCase;
import org.opensearch.test.rest.FakeRestChannel;
import org.opensearch.test.rest.FakeRestRequest;
import org.opensearch.transport.client.node.NodeClient;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.mock;

public class RestGetAlertsActionTests extends OpenSearchTestCase {

    public void testDefaults() throws Exception {
        GetAlertsRequest request = parse(Map.of());
        assertNull(request.getDetectorId());
        assertNull(request.getLogType());
        assertEquals(new Table("asc", "start_time", null, 20, 0, ""), request.getTable());
        assertEquals("ALL", request.getSeverityLevel());
        assertEquals("ALL", request.getAlertState());
        assertEquals(List.of(), request.getSeverityLevels());
        assertEquals(List.of(), request.getAlertStates());
        assertNull(request.getStartTime());
        assertNull(request.getEndTime());
        assertNull(request.validate());
    }

    public void testMultiValueFilters() throws Exception {
        Map<String, String> params = new HashMap<>();
        params.put("severityLevels", " 1, 2,,");
        params.put("alertStates", "active,Acknowledged");
        GetAlertsRequest request = parse(params);
        assertEquals(List.of("1", "2"), request.getSeverityLevels());
        assertEquals(List.of("ACTIVE", "ACKNOWLEDGED"), request.getAlertStates());
        assertNull(request.validate());

        params.put("severityLevels", ",");
        params.put("alertStates", "");
        request = parse(params);
        assertEquals(List.of(), request.getSeverityLevels());
        assertEquals(List.of(), request.getAlertStates());
    }

    public void testTableParams() throws Exception {
        Map<String, String> params = new HashMap<>();
        params.put("detector_id", "d1");
        params.put("sortString", "monitor_name.keyword");
        params.put("sortOrder", "desc");
        params.put("size", "0");
        params.put("startIndex", "40");
        params.put("searchString", "my detector");
        params.put("startTime", "1000");
        params.put("endTime", "2000");
        GetAlertsRequest request = parse(params);
        assertEquals("d1", request.getDetectorId());
        assertEquals(new Table("desc", "monitor_name.keyword", null, 0, 40, "my detector"), request.getTable());
        assertEquals(1000L, request.getStartTime().toEpochMilli());
        assertEquals(2000L, request.getEndTime().toEpochMilli());
        assertNull(request.validate());
    }

    private GetAlertsRequest parse(Map<String, String> params) throws Exception {
        NodeClient client = mock(NodeClient.class);
        AtomicReference<GetAlertsRequest> captured = new AtomicReference<>();
        doAnswer(invocation -> {
            captured.set(invocation.getArgument(1));
            return null;
        }).when(client).execute(eq(GetAlertsAction.INSTANCE), any(GetAlertsRequest.class), any(ActionListener.class));

        FakeRestRequest restRequest = new FakeRestRequest.Builder(xContentRegistry()).withParams(new HashMap<>(params)).build();
        new RestGetAlertsAction().handleRequest(restRequest, new FakeRestChannel(restRequest, true, 1), client);
        assertNotNull("GetAlertsAction was not executed", captured.get());
        return captured.get();
    }
}
