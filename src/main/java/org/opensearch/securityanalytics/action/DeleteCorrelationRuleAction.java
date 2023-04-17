/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */

package org.opensearch.securityanalytics.action;

import org.opensearch.action.ActionType;
import org.opensearch.action.support.master.AcknowledgedResponse;

public class DeleteCorrelationRuleAction extends ActionType<AcknowledgedResponse> {

    public static final DeleteCorrelationRuleAction INSTANCE = new DeleteCorrelationRuleAction();
    public static final String NAME = "cluster:admin/index/correlation/rules/delete";

    private DeleteCorrelationRuleAction() {
        super(NAME, AcknowledgedResponse::new);
    }
}
