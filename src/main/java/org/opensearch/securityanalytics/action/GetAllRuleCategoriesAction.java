/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.securityanalytics.action;

import org.opensearch.action.ActionType;

public class GetAllRuleCategoriesAction extends ActionType<GetAllRuleCategoriesResponse> {

    public static final GetAllRuleCategoriesAction INSTANCE = new GetAllRuleCategoriesAction();
    public static final String NAME = "cluster:admin/opensearch/securityanalytics/rules/categories";

    public GetAllRuleCategoriesAction() {
        super(NAME, GetAllRuleCategoriesResponse::new);
    }
}