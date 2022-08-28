/*
Copyright OpenSearch Contributors
SPDX-License-Identifier: Apache-2.0
 */

package org.opensearch.securityanalytics.transport;

import org.apache.logging.log4j.LogManager;
import org.opensearch.OpenSearchStatusException;
import org.opensearch.action.ActionListener;
import org.opensearch.action.get.GetRequest;
import org.opensearch.action.get.GetResponse;
import org.opensearch.client.Client;
import org.opensearch.cluster.service.ClusterService;
import org.opensearch.common.inject.Inject;
import org.opensearch.common.io.stream.Writeable;
import org.opensearch.common.settings.Settings;
import org.opensearch.common.xcontent.LoggingDeprecationHandler;
import org.opensearch.common.xcontent.NamedXContentRegistry;
import org.opensearch.common.xcontent.XContentHelper;
import org.opensearch.common.xcontent.XContentType;
import org.opensearch.rest.RestStatus;
import org.opensearch.tasks.Task;
import org.opensearch.transport.TransportService;
import org.opensearch.action.support.ActionFilters;
import org.opensearch.action.support.HandledTransportAction;
//import org.opensearch.action.GetMonitorAction;
//import org.opensearch.action.GetMonitorResponse;

import org.opensearch.securityanalytics.transport.GetMonitorRequest;
import org.opensearch.securityanalytics.transport.ScheduledJob;
//import org.opensearch.securityanalytics.transport.SecureTransportAction;

import org.opensearch.action.support.nodes.TransportNodesAction;
import org.opensearch.securityanalytics.mappings.MapperApplier;

import java.io.IOException;

public class TransportGetMonitorAction extends HandledTransportAction<GetMonitorRequest, GetMonitorResponse> {

    //private TransportService transportService;
    private Client client;
    private NamedXContentRegistry xContentRegistry;
    private ClusterService clusterService;
    private Settings settings;

    public TransportGetMonitorAction(
            String actionName,
            TransportService transportService,
            ActionFilters actionFilters,
            Writeable.Reader<GetMonitorRequest> getMonitorRequestReader) {
        super(actionName, transportService, actionFilters, getMonitorRequestReader);
    }
    //private SecureTransportAction secureTransportAction;

//    public TransportGetMonitorAction(
//        //TransportService transportService,
//        Client client,
//        //ActionFilters actionFilters,
//        NamedXContentRegistry xContentRegistry,
//        ClusterService clusterService,
//        Settings settings
//        //SecureTransportAction secureTransportAction
//    ) {
//        this.super();
//        //this.transportService = transportService;
//        this.client = client;
//        this.xContentRegistry = xContentRegistry;
//        this.clusterService = clusterService;
//        //this.secureTransportAction = secureTransportAction;
//    }

    //@Volatile override var
    Boolean filterByEnabled = false; //AlertingSettings.FILTER_BY_BACKEND_ROLES.get(settings)


    @Override
    public void doExecute(
            Task task,
            GetMonitorRequest getMonitorRequest,
            ActionListener<GetMonitorResponse> actionListener
    ){

        GetRequest getRequest = new GetRequest(ScheduledJob.SCHEDULED_JOBS_INDEX, getMonitorRequest.monitorId)
                .version(getMonitorRequest.version)
                .fetchSourceContext(getMonitorRequest.srcContext);

        MapperApplier mapperApplier = new MapperApplier(client);

        try {
            mapperApplier.createMappingAction("logIndex","ruleTopic");
            mapperApplier.updateMappingAction("logIndex", "field", "alias");
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }


}
