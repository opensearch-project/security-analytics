/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.securityanalytics;

import org.opensearch.action.ActionRequest;
import org.opensearch.action.ActionResponse;
import org.opensearch.cluster.metadata.IndexNameExpressionResolver;
import org.opensearch.cluster.node.DiscoveryNodes;
import org.opensearch.common.settings.ClusterSettings;
import org.opensearch.common.settings.IndexScopedSettings;
import org.opensearch.common.settings.Settings;
import org.opensearch.common.settings.SettingsFilter;
import org.opensearch.common.xcontent.NamedXContentRegistry;
import org.opensearch.plugins.ActionPlugin;
import org.opensearch.plugins.Plugin;
import org.opensearch.rest.RestController;
import org.opensearch.rest.RestHandler;
import org.opensearch.securityanalytics.alerting.action.ExecuteMonitorAction;
import org.opensearch.securityanalytics.alerting.action.IndexMonitorAction;
import org.opensearch.securityanalytics.alerting.model.*;
import org.opensearch.securityanalytics.alerting.resthandlers.RestExecuteMonitorAction;
import org.opensearch.securityanalytics.alerting.resthandlers.RestIndexMonitorAction;
import org.opensearch.securityanalytics.alerting.transport.TransportExecuteMonitorAction;
import org.opensearch.securityanalytics.alerting.transport.TransportIndexMonitorAction;

import java.util.List;
import java.util.function.Supplier;

public class SecurityAnalyticsPlugin extends Plugin implements ActionPlugin {

    @Override
    public List<RestHandler> getRestHandlers(
            final Settings settings,
            final RestController restController,
            final ClusterSettings clusterSettings,
            final IndexScopedSettings indexScopedSettings,
            final SettingsFilter settingsFilter,
            final IndexNameExpressionResolver indexNameExpressionResolver,
            final Supplier<DiscoveryNodes> nodesInCluster) {
        return List.of(new RestIndexMonitorAction(), new RestExecuteMonitorAction());
    }

    public SecurityAnalyticsPlugin() {

    }

    @Override
    public List<NamedXContentRegistry.Entry> getNamedXContent() {
        return List.of(
                Action.XCONTENT_REGISTRY,
                Action.ExecutionScope.XCONTENT_REGISTRY,
                Action.ExecutionScope.PerScope.XCONTENT_REGISTRY,
                Action.ExecutionPolicy.XCONTENT_REGISTRY,
                Input.XCONTENT_REGISTRY,
                Monitor.XCONTENT_REGISTRY,
                Query.XCONTENT_REGISTRY,
                Script.XCONTENT_REGISTRY,
                Throttle.XCONTENT_REGISTRY,
                Trigger.XCONTENT_REGISTRY
        );
    }


    public List<ActionHandler<? extends ActionRequest, ? extends ActionResponse>> getActions() {
        return List.of(
                new ActionPlugin.ActionHandler<>(ExecuteMonitorAction.INSTANCE, TransportExecuteMonitorAction.class),
                new ActionPlugin.ActionHandler<>(IndexMonitorAction.INSTANCE, TransportIndexMonitorAction.class));
    }
}