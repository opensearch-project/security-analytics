package org.opensearch.securityanalytics.action;

import org.opensearch.action.ActionType;

public class GetDetectorAlertsAction extends ActionType<GetDetectorAlertsResponse> {

    public static final GetDetectorAlertsAction INSTANCE = new GetDetectorAlertsAction();
    public static final String NAME = "cluster:admin/opendistro/securityanalytics/detector/alerts/read";

    public GetDetectorAlertsAction() {
        super(NAME, GetDetectorAlertsResponse::new);
    }
}
