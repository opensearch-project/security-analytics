/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package org.opensearch.securityanalytics.threatIntel.action;

import org.opensearch.action.ActionType;
import org.opensearch.action.search.SearchResponse;

import static org.opensearch.securityanalytics.threatIntel.sacommons.IndexTIFSourceConfigAction.SEARCH_TIF_SOURCE_CONFIGS_ACTION_NAME;

/**
 * Search TIF Source Configs Action
 */
public class SASearchTIFSourceConfigsAction extends ActionType<SearchResponse> {

    public static final SASearchTIFSourceConfigsAction INSTANCE = new SASearchTIFSourceConfigsAction();

    public static final String NAME = SEARCH_TIF_SOURCE_CONFIGS_ACTION_NAME;
    private SASearchTIFSourceConfigsAction() {
        super(NAME, SearchResponse::new);
    }
}
