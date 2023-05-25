package org.opensearch.securityanalytics.util;

public class BucketMonitorUtils {
    public static final String BUCKET_MONITOR_NAME_SUFFIX = "_bucket";
    public static final String DOC_MATCH_ALL_MONITOR_NAME_SUFFIX = "_chainedFindings";

    public static String generateBucketMonitorName(String baseName) {
        return baseName + BUCKET_MONITOR_NAME_SUFFIX;
    }

    public static String generateMatchAllDocMonitorName(String baseName) {
        return baseName + DOC_MATCH_ALL_MONITOR_NAME_SUFFIX;
    }
}
