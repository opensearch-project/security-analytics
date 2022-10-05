/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.securityanalytics.findings;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.opensearch.action.ActionListener;
import org.opensearch.action.support.GroupedActionListener;
import org.opensearch.client.Client;
import org.opensearch.commons.alerting.action.AlertingActions;
import org.opensearch.commons.alerting.action.GetFindingsRequest;
import org.opensearch.commons.alerting.model.FindingWithDocs;
import org.opensearch.commons.alerting.model.Table;
import org.opensearch.rest.RestStatus;
import org.opensearch.securityanalytics.action.GetDetectorAction;
import org.opensearch.securityanalytics.action.GetDetectorRequest;
import org.opensearch.securityanalytics.action.GetDetectorResponse;
import org.opensearch.securityanalytics.action.GetFindingsResponse;
import org.opensearch.securityanalytics.util.DetectorIndices;

public class FindingsService {

    private Client client;

    private final String DEFAULT_SORT_ORDER = "asc";
    private final String DEFAULT_SORT_STRING = "id";
    private final Integer DEFAULT_SIZE = 20;

    private static final Logger log = LogManager.getLogger(FindingsService.class);

    public FindingsService() {}

    public FindingsService(Client client) {
        this.client = client;
    }

    public void getFindingsByDetectorId(String detectorId, Table table, ActionListener<GetFindingsResponse> listener) {
        this.client.execute(GetDetectorAction.INSTANCE, new GetDetectorRequest(detectorId, -3L), new ActionListener<>() {

            @Override
            public void onResponse(GetDetectorResponse getDetectorResponse) {
                List<String> monitorIds = getDetectorResponse.getDetector().getMonitorIds();
                if (monitorIds.size() == 0) {
                    listener.onFailure(new IllegalArgumentException("Detector has 0 monitors"));
                }

                AtomicInteger numOfResponses = new AtomicInteger(0);
                List<GetFindingsResponse> responses = new ArrayList<>(monitorIds.size());


                ActionListener<GetFindingsResponse> multiGetFindingsListener = new GroupedActionListener<>(new ActionListener<>() {
                    @Override
                    public void onResponse(Collection<GetFindingsResponse> collection) {
                        // Assume all responses are equal and 200
                        RestStatus status = responses.get(0).getStatus();
                        Integer totalFindings = 0;
                        List<FindingWithDocs> findings = new ArrayList<>();
                        // Merge all findings into one response
                        for(GetFindingsResponse resp : responses) {
                            totalFindings += resp.getTotalFindings();
                            findings.addAll(resp.getFindings());
                        }
                        GetFindingsResponse masterResponse = new GetFindingsResponse(status, totalFindings, findings, detectorId);
                        listener.onResponse(masterResponse);
                    }

                    @Override
                    public void onFailure(Exception e) {
                        log.error("Failed to fetch findings for detector " + detectorId, e);
                        listener.onFailure(
                                new IllegalArgumentException("Failed to fetch findings for detector" + detectorId)
                        );
                    }
                }, monitorIds.size());
                // Execute GetFindingsAction for each monitor
                for(String monitorId : monitorIds) {
                    FindingsService.this.getFindingsByMonitorId(monitorId, table, multiGetFindingsListener);
                }
            }

            @Override
            public void onFailure(Exception e) {
                listener.onFailure(e);
            }
        });
    }

    public void getFindingsByMonitorId(
            String monitorId,
            Table table,
            ActionListener<GetFindingsResponse> listener
    ) {

        GetFindingsRequest req = new GetFindingsRequest(
                null,
                table,
                monitorId,
                null
        );

        client.execute(
                AlertingActions.GET_FINDINGS_ACTION_TYPE,
                req,
                new ActionListener<>() {
                    @Override
                    public void onResponse(
                            org.opensearch.commons.alerting.action.GetFindingsResponse getFindingsResponse
                    ) {
                        // Convert response to SA's GetFindingsResponse
                        listener.onResponse(new GetFindingsResponse(
                                getFindingsResponse.getStatus(),
                                getFindingsResponse.getTotalFindings(),
                                getFindingsResponse.getFindings(),
                                null
                        ));
                    }

                    @Override
                    public void onFailure(Exception e) {
                        listener.onFailure(e);
                    }
                }
        );
    }
}
