/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package org.opensearch.securityanalytics.alerting.model;

import org.opensearch.common.xcontent.NamedXContentRegistry;
import org.opensearch.securityanalytics.model2.AbstractModel;
import org.opensearch.securityanalytics.model2.ToXContentModel;

import java.util.List;

public class Trigger extends AbstractModel {
    public static NamedXContentRegistry.Entry XCONTENT_REGISTRY = ToXContentModel.createRegistryEntry(Trigger.class);

    public String id;
    public String name;
    public String severity;
    public List<Action> actions;

    public Trigger() {
        // for serialization
    }

    public Trigger(final String id, final String name, final String severity, final List<Action> actions) {
        this.id = id;
        this.name = name;
        this.severity =severity;
        this.actions = actions;
    }
}
