package org.opensearch.securityanalytics.transport;

import org.opensearch.action.ActionListener;
import org.opensearch.action.support.ActionFilters;
import org.opensearch.action.support.GroupedActionListener;
import org.opensearch.action.support.HandledTransportAction;
import org.opensearch.client.Client;
import org.opensearch.common.io.stream.Writeable;
import org.opensearch.commons.alerting.action.GetAlertsRequest;
import org.opensearch.commons.alerting.action.GetAlertsResponse;
import org.opensearch.commons.alerting.model.CronSchedule;
import org.opensearch.securityanalytics.AlertService;
import org.opensearch.securityanalytics.action.GetDetectorAlertsRequest;
import org.opensearch.securityanalytics.action.GetDetectorAlertsResponse;
import org.opensearch.securityanalytics.config.monitors.DetectorMonitorConfig;
import org.opensearch.securityanalytics.model.Detector;
import org.opensearch.tasks.Task;
import org.opensearch.transport.TransportService;

import java.time.Instant;
import java.time.ZoneId;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.List;

public class TransportGetDetectorAlertsAction extends HandledTransportAction<GetDetectorAlertsRequest, GetDetectorAlertsResponse> {

    private final Client client;
    private final AlertService alertService;

    protected TransportGetDetectorAlertsAction(
            String actionName,
            TransportService transportService,
            ActionFilters actionFilters,
            Writeable.Reader<GetDetectorAlertsRequest> getDetectorAlertsRequestReader,
            Client client) {
        super(actionName, transportService, actionFilters, getDetectorAlertsRequestReader);
        this.client = client;
        alertService = new AlertService(client);
    }

    @Override
    protected void doExecute(Task task,
                             GetDetectorAlertsRequest request,
                             ActionListener<GetDetectorAlertsResponse> actionListener) {
        //todo implement once getDetector is available
        Detector detector = new Detector(
                "123",
                0L,
                "test-monitor",
                true,
                new CronSchedule("31 * * * *", ZoneId.of("Asia/Kolkata"), Instant.ofEpochSecond(1538164858L)),
                Instant.now(),
                Instant.now(),
                Detector.DetectorType.APPLICATION,
                null,
                List.of(),
                "456",
                DetectorMonitorConfig.getRuleIndex(Detector.DetectorType.APPLICATION.getDetectorType()),
                DetectorMonitorConfig.getAlertIndex(Detector.DetectorType.APPLICATION.getDetectorType()),
                DetectorMonitorConfig.getFindingsIndex(Detector.DetectorType.APPLICATION.getDetectorType())
        );
        //todo change when detector supports list... detector.getMonitorIds()
        List<String> monitorIds = Collections.singletonList(detector.getMonitorId());

        ActionListener<GetAlertsResponse> alertsListener = new GroupedActionListener<>(new ActionListener<>() {
            @Override
            public void onResponse(Collection<GetAlertsResponse> collection) {
                actionListener.onResponse(new GetDetectorAlertsResponse(detector.getId(),
                        new ArrayList<>(collection)));
            }

            @Override
            public void onFailure(Exception e) {
                logger.error("Failed to fetch alerts for detector " + detector.getId(), e);
                actionListener.onFailure(e); //todo wrap
            }
        }, monitorIds.size()); //TODO support bulk api for alerts based on fetching for multiple monitor ids
        monitorIds.forEach(m -> {
                    //todo fetch by monitor id or index
                    GetAlertsRequest getAlertsRequest = new GetAlertsRequest(request.getTable(), request.getSeverityLevel(),
                            request.getAlertState(), m, DetectorMonitorConfig.getAlertIndex(detector.getDetectorType()));
                    alertService.getAlerts(getAlertsRequest, alertsListener);
                }
        );

    }
}
