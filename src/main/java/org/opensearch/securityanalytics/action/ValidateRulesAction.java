/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.securityanalytics.action;

import org.opensearch.action.ActionType;
import org.opensearch.action.support.master.AcknowledgedResponse;

public class ValidateRulesAction extends ActionType<ValidateRulesResponse>{

    public static final String NAME = "cluster:admin/opendistro/securityanalytics/rules/validate";
    public static final ValidateRulesAction INSTANCE = new ValidateRulesAction();


    public ValidateRulesAction() {
        super(NAME, ValidateRulesResponse::new);
    }
}
