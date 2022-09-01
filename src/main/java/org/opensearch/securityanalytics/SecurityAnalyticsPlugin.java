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
import org.opensearch.plugins.ActionPlugin;
import org.opensearch.plugins.Plugin;
import org.opensearch.rest.RestController;
import org.opensearch.rest.RestHandler;
import org.opensearch.securityanalytics.mapper.action.mapping.TransportUpdateIndexMappingsAction;
import org.opensearch.securityanalytics.mapper.action.mapping.UpdateIndexMappingsAction;
import org.opensearch.securityanalytics.mapper.resthandler.RestUpdateIndexMappingsAction;

import java.util.List;
import java.util.function.Supplier;

public class SecurityAnalyticsPlugin extends Plugin implements ActionPlugin {

    public static final String PLUGINS_BASE_URI = "/_plugins";
    public static final String SAP_BASE_URI = PLUGINS_BASE_URI + "/_sap";
    public static final String MAPPER_BASE_URI = SAP_BASE_URI + "/mapper";

    @Override
    public List<ActionPlugin.ActionHandler<? extends ActionRequest, ? extends ActionResponse>> getActions() {
        return List.of(
                        new ActionPlugin.ActionHandler<>(UpdateIndexMappingsAction.INSTANCE, TransportUpdateIndexMappingsAction.class)
                );
    }


    public List<RestHandler> getRestHandlers(
            Settings settings,
            RestController restController,
            ClusterSettings clusterSettings,
            IndexScopedSettings indexScopedSettings,
            SettingsFilter settingsFilter,
            IndexNameExpressionResolver indexNameExpressionResolver,
            Supplier<DiscoveryNodes> nodesInCluster
    ){
        return List.of(
            new RestUpdateIndexMappingsAction()
        );
    }


}