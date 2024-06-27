/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package org.opensearch.securityanalytics.threatIntel.sacommons;

public class IndexTIFSourceConfigAction {
    public static final String INDEX_TIF_SOURCE_CONFIG_ACTION_NAME = "cluster:admin/opensearch/securityanalytics/threatintel/sources/write";
    public static final String GET_TIF_SOURCE_CONFIG_ACTION_NAME = "cluster:admin/opensearch/securityanalytics/threatintel/sources/get";
    public static final String DELETE_TIF_SOURCE_CONFIG_ACTION_NAME = "cluster:admin/opensearch/securityanalytics/threatintel/sources/delete";
    public static final String SEARCH_TIF_SOURCE_CONFIGS_ACTION_NAME = "cluster:admin/opensearch/securityanalytics/threatintel/sources/search";
    public static final String REFRESH_TIF_SOURCE_CONFIG_ACTION_NAME = "cluster:admin/opensearch/securityanalytics/threatintel/sources/refresh";
}
