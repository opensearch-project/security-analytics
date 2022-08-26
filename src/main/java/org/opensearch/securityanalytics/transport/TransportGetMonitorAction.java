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

//private val log = LogManager.getLogger(TransportGetMonitorAction::class.java)
import org.opensearch.securityanalytics.mappings.MapperApplier;

import java.io.IOException;

public class TransportGetMonitorAction {

    //private TransportService transportService;
    private Client client;
    private NamedXContentRegistry xContentRegistry;
    private ClusterService clusterService;
    private Settings settings;
    //private SecureTransportAction secureTransportAction;

    void constructor(
        //TransportService transportService,
        Client client,
        //ActionFilters actionFilters,
        NamedXContentRegistry xContentRegistry,
        ClusterService clusterService,
        Settings settings
        //SecureTransportAction secureTransportAction
    ) {
        //this.transportService = transportService;
        this.client = client;
        this.xContentRegistry = xContentRegistry;
        this.clusterService = clusterService;
        //this.secureTransportAction = secureTransportAction;
    }

    //@Volatile override var
    Boolean filterByEnabled = false; //AlertingSettings.FILTER_BY_BACKEND_ROLES.get(settings)

    //override
    public void doExecute(
        Task task,
        GetMonitorRequest getMonitorRequest
        //ActionListener<GetMonitorResponse> actionListener
    ) throws IOException {
        //User user = secureTransportAction.readUserFromThreadContext(client);

        GetRequest getRequest = new GetRequest(ScheduledJob.SCHEDULED_JOBS_INDEX, getMonitorRequest.monitorId)
            .version(getMonitorRequest.version)
            .fetchSourceContext(getMonitorRequest.srcContext);

//        if (!secureTransportAction.validateUserBackendRoles(user, actionListener)) {
//            return;
//        }

        MapperApplier mapperApplier = new MapperApplier(client);

        mapperApplier.createMappingAction("logIndex","ruleTopic");
        mapperApplier.updateMappingAction("logIndex", "field", "alias");

//        this.client.threadPool().threadContext.stashContext().use {
//            client.get(
//                    getRequest,
//                    object : ActionListener<GetResponse> {
//                override fun onResponse(response: GetResponse) {
//                    if (!response.isExists) {
//                        actionListener.onFailure(
//                                AlertingException.wrap(OpenSearchStatusException("Monitor not found.", RestStatus.NOT_FOUND))
//                        )
//                        return
//                    }
//
//                }
//            )
//        }
    }
}
