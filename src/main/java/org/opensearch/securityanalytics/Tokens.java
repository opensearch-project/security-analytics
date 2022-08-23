/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package org.opensearch.securityanalytics;

import java.util.Locale;

public class Tokens {

    private Tokens() {
        // do nothing
    }


    public static final String SAP_BASE_URI = "/_plugins/_security_analytics";
    public static final String SAP_MONITORS_BASE_URI = SAP_BASE_URI + "/monitors";
    public static final String ALERTING_BASE_URI = "/_plugins/_alerting";
    public static final String ALERTING_MONITORS_BASE_URI = ALERTING_BASE_URI + "/monitors";
    public static final String OPENSEARCH_ALERTING = "opensearch-alerting";
    public static final String OPENSEARCH_SECURITY_ANALYTICS = "opensearch-security-analytics";

    public static final String SAP_EXECUTE_MONITOR_ACTION = "sap_execute_monitor_action";


    public static final String MONITOR_ID = "monitorID";
    public static final String REQUEST_END = "requestEnd";
    public static final String DRY_RUN = "dryrun";

    public static final String ID = "id";
    public static final String NAME = "name";
    public static final String QUERY = "query";
    public static final String TAGS = "tags";

    public static final String DESCRIPTION = "description";
    public static final String INDICES = "indices";
    public static final String QUERIES = "queries";

    public static final String TYPE = "type";
    public static final String MONITOR_TYPE = "monitor_type";
    public static final String MONITOR = "monitor";
    public static final String ENABLED = "enabled";
    public static final String SCHEDULE = "schedule";
    public static final String INTERVAL = "interval";
    public static final String PERIOD = "period";
    public static final String UNIT = "unit";
    public static final String INPUTS = "inputs";
    public static final String VERSION = "version";

    public static final String _CREATE = "_create";
    public static final String _EXECUTE = "_execute";


    public static String executeMonitor(final String baseURI, final String monitorId) {
        return String.format(Locale.US, baseURI + "/%s/_execute", monitorId);
    }

    public static String indexMonitor(final String baseURI, final String monitorId) {
        return String.format(Locale.US, baseURI + "/%s/", monitorId);
    }

}
