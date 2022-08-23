/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package org.opensearch.securityanalytics.alerting.model;

import org.opensearch.common.xcontent.NamedXContentRegistry;
import org.opensearch.securityanalytics.model2.AbstractModel;
import org.opensearch.securityanalytics.model2.ToXContentModel;

import java.util.List;

public class Action extends AbstractModel {

    public static NamedXContentRegistry.Entry XCONTENT_REGISTRY = ToXContentModel.createRegistryEntry(Action.class);

    public String id;
    public String name;
    public String destination_id;
    public Script subject_template;
    public Script message_template;
    public boolean throttled_enabled;
    public Throttle throttle;
    public ExecutionPolicy action_execution_policy;

    //val throttleEnabled: Boolean,
    // val throttle: Throttle?,
    //val id: String = UUIDs.base64UUID(),
    //val actionExecutionPolicy: ActionExecutionPolicy? = null
    public Action() {
        // for serialization
    }

    public Action(final String id, final String name, final String destination_id, final Script subject_template, final Script message_template, final boolean throttled_enabled, final Throttle throttle, final ExecutionPolicy action_execution_policy) {
        this.id = id;
        this.name = name;
        this.destination_id = destination_id;
        this.subject_template = subject_template;
        this.message_template = message_template;
        this.throttled_enabled = throttled_enabled;
        this.throttle = throttle;
        this.action_execution_policy = action_execution_policy;
    }

    public static class ExecutionPolicy extends AbstractModel {

        public static NamedXContentRegistry.Entry XCONTENT_REGISTRY = ToXContentModel.createRegistryEntry(Action.ExecutionPolicy.class);

        public ExecutionScope action_execution_scope;

        public ExecutionPolicy() {
            // for serialization
        }

        public ExecutionPolicy(final ExecutionScope action_execution_scope) {
            this.action_execution_scope = action_execution_scope;
        }
    }

    public static class ExecutionScope extends AbstractModel {

        public static NamedXContentRegistry.Entry XCONTENT_REGISTRY = ToXContentModel.createRegistryEntry(ExecutionScope.class);

        public PerScope per_alert;

        public ExecutionScope() {
            // for serialization
        }

        public ExecutionScope(final PerScope per_alert) {
            this.per_alert = per_alert;
        }

        public static class PerScope extends AbstractModel {

            public static NamedXContentRegistry.Entry XCONTENT_REGISTRY = ToXContentModel.createRegistryEntry(PerScope.class);

            //public enum AlertCategory {DEDUPED, NEW, COMPLETE}

            public List<String> actionable_alerts;

            public PerScope() {
                // for serialization
            }

            public PerScope(final List<String> actionable_alerts) {
                this.actionable_alerts = actionable_alerts;
            }
        }
    }
}