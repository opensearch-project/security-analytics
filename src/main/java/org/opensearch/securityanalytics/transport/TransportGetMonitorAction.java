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
import org.opensearch.action.support.ActionFilters;
import org.opensearch.action.support.HandledTransportAction;
//import org.opensearch.alerting.action.GetMonitorAction;
//import org.opensearch.alerting.action.GetMonitorRequest;
//import org.opensearch.alerting.action.GetMonitorResponse;
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
import org.opensearch.transport.SecureTransportAction;

//private val log = LogManager.getLogger(TransportGetMonitorAction::class.java)

class TransportGetMonitorAction {
    void constructor(
            TransportService transportService,
            Client client,
            //ActionFilters actionFilters,
            NamedXContentRegistry xContentRegistry,
            ClusterService clusterService,
            Settings settings,
            SecureTransportAction : secureTransportAction
    ) {}

    //@Volatile override var
    Boolean filterByEnabled = false; //AlertingSettings.FILTER_BY_BACKEND_ROLES.get(settings)


    //override
    public void doExecute(
            Task task,
            //GetMonitorRequest getMonitorRequest,
            //ActionListener<GetMonitorResponse> actionListener
    ){
        User user = secureTransportAction.readUserFromThreadContext(client)

        val getRequest = GetRequest(ScheduledJob.SCHEDULED_JOBS_INDEX, getMonitorRequest.monitorId)
                .version(getMonitorRequest.version)
                .fetchSourceContext(getMonitorRequest.srcContext)

        if (!secureTransportAction.validateUserBackendRoles(user, actionListener)) {
            return
        }
    }
}
