/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.securityanalytics;

import java.time.Clock;
import java.util.Arrays;
import java.util.Collection;
import java.util.List;
import java.util.Map;
import java.util.Random;
import java.util.function.Supplier;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import org.opensearch.plugins.Plugin;
import org.opensearch.plugins.ActionPlugin;
import org.opensearch.action.ActionRequest;
import org.opensearch.action.ActionResponse;

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
import org.opensearch.securityanalytics.transport.GetMonitorAction;
import org.opensearch.securityanalytics.transport.TransportGetMonitorAction;
import org.opensearch.tasks.Task;

public class SecurityAnalyticsPlugin extends Plugin implements ActionPlugin {

    //    @Override
    //    public List getRestHandlers(final Settings settings,
    //                                final RestController restController,
    //                                final ClusterSettings clusterSettings,
    //                                final IndexScopedSettings indexScopedSettings,
    //                                final SettingsFilter settingsFilter,
    //                                final IndexNameExpressionResolver indexNameExpressionResolver,
    //                                final Supplier nodesInCluster) {
    //
    //        return singletonList(new RestHelloWorldAction());
    //    }
    @Override
    public List<ActionHandler<? extends ActionRequest, ? extends ActionResponse>> getActions() {
        return Arrays
                .asList(
                        new ActionHandler<>(GetMonitorAction.INSTANCE, TransportGetMonitorAction.class)
                );
    }
}