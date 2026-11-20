/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package org.opensearch.securityanalytics.resources;

import org.opensearch.commons.client.PluginClient;
import org.opensearch.transport.client.Client;

/**
 * The security analytics plugin's client that runs transport actions as its system subject.
 */
public final class SecurityAnalyticsPluginClient extends PluginClient {

    /**
     * Wraps a client so its actions run as the plugin subject, which is assigned later.
     *
     * @param delegate the client whose actions this wraps
     */
    public SecurityAnalyticsPluginClient(Client delegate) {
        super(delegate);
    }
}
