package org.opensearch.securityanalytics.findings;

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;
import org.opensearch.action.ActionListener;
import org.opensearch.client.AdminClient;
import org.opensearch.client.Client;
import org.opensearch.commons.alerting.action.AlertingActions;
import org.opensearch.commons.alerting.action.GetFindingsRequest;
import org.opensearch.commons.alerting.model.FindingWithDocs;
import org.opensearch.commons.alerting.model.Table;
import org.opensearch.rest.RestStatus;
import org.opensearch.rest.action.RestToXContentListener;
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

    public FindingsService() {}

    public FindingsService(Client client) {
        this.client = client;
    }

    public void getFindingsByDetectorId(String detectorId, ActionListener<GetFindingsResponse> listener) {
        this.client.execute(GetDetectorAction.INSTANCE, new GetDetectorRequest(detectorId, -3L), new ActionListener<>() {

            @Override
            public void onResponse(GetDetectorResponse getDetectorResponse) {
                List<String> monitorIds = getDetectorResponse.getDetector().getMonitorIds();
                if (monitorIds.size() == 0) {
                    listener.onFailure(new IllegalArgumentException("Detector has 0 monitors"));
                }

                AtomicInteger numOfResponses = new AtomicInteger(0);
                List<GetFindingsResponse> responses = new ArrayList<>(monitorIds.size());

                for(String monitorId : monitorIds) {
                    FindingsService.this.getFindingsByMonitorId(detectorId, monitorId, new ActionListener<GetFindingsResponse>() {
                        @Override
                        public void onResponse(GetFindingsResponse getFindingsResponse) {
                            int responseCount = numOfResponses.incrementAndGet();
                            responses.set(responseCount - 1, getFindingsResponse);
                            if (responseCount == monitorIds.size()) {
                                // Assume all response are 200
                                RestStatus status = responses.get(0).getStatus();
                                Integer totalFindings = 0;
                                List<FindingWithDocs> findings = new ArrayList<>();
                                for(GetFindingsResponse resp : responses) {
                                    totalFindings += resp.getTotalFindings();
                                    findings.addAll(resp.getFindings());
                                }
                                GetFindingsResponse masterResponse = new GetFindingsResponse(status, totalFindings, findings, detectorId);

                                listener.onResponse(masterResponse);
                            }
                        }

                        @Override
                        public void onFailure(Exception e) {
                            listener.onFailure(e);
                        }
                    });
                }
            }

            @Override
            public void onFailure(Exception e) {
                listener.onFailure(e);
            }
        });
    }

    public void getFindingsByMonitorId(
            String detectorId,
            String monitorId,
            ActionListener<GetFindingsResponse> listener
    ) {

        Table table = new Table(
                DEFAULT_SORT_ORDER,
                DEFAULT_SORT_STRING,
                null,
                DEFAULT_SIZE,
                0,
                ""
        );

        GetFindingsRequest req = new GetFindingsRequest(
                null,
                table,
                monitorId,
                null
        );

        client.execute(
                AlertingActions.GET_FINDINGS_ACTION_TYPE,
                req,
                new ActionListener<org.opensearch.commons.alerting.action.GetFindingsResponse>() {
                    @Override
                    public void onResponse(org.opensearch.commons.alerting.action.GetFindingsResponse getFindingsResponse) {
                        listener.onResponse(new GetFindingsResponse(
                                getFindingsResponse.getStatus(),
                                getFindingsResponse.getTotalFindings(),
                                getFindingsResponse.getFindings(),
                                detectorId
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
