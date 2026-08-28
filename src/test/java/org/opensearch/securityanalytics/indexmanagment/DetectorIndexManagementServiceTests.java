/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.securityanalytics.indexmanagment;

import org.opensearch.Version;
import org.opensearch.cluster.metadata.AliasMetadata;
import org.opensearch.cluster.metadata.IndexMetadata;
import org.opensearch.common.settings.Settings;
import org.opensearch.common.unit.TimeValue;
import org.opensearch.test.OpenSearchTestCase;

import java.lang.reflect.Constructor;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;

/**
 * Unit tests for {@link DetectorIndexManagementService#getHistoryIndexToDelete}.
 * Validates that indices are only deleted when they belong to the
 * history type being checked (i.e., have a matching alias).
 *
 * Regression tests for https://github.com/opensearch-project/security-analytics/issues/1759
 */
public class DetectorIndexManagementServiceTests extends OpenSearchTestCase {

    /**
     * Verifies that a findings index is NOT deleted when checked against
     * alert retention, even when the findings index is older than the
     * alert retention period.
     *
     * This is the core regression test for issue #1759.
     */
    public void testFindingsIndexNotDeletedByAlertRetention() throws Exception {
        // Simulate a findings index that is 3 days old
        long threeDaysAgo = Instant.now().toEpochMilli() - (3 * 24 * 60 * 60 * 1000L);

        // Alert retention is 2 days (findings index IS older than this)
        long alertRetentionMillis = 2 * 24 * 60 * 60 * 1000L;

        // Create an IndexMetadata with a findings alias (not an alert alias)
        String findingsAlias = ".opensearch-sap-findings-history-windows";
        IndexMetadata indexMetadata = createIndexMetadata(
                ".opensearch-sap-findings-history-windows-000001",
                threeDaysAgo,
                findingsAlias
        );

        // Alert history indices have a DIFFERENT alias pattern
        String alertAlias = ".opensearch-sap-alerts-history-windows";
        List historyIndices = createHistoryIndexInfoList(alertAlias);

        // Call getHistoryIndexToDelete with alert retention and alert history indices
        String result = DetectorIndexManagementService.getHistoryIndexToDelete(
                indexMetadata, alertRetentionMillis, historyIndices, true
        );

        // The findings index should NOT be deleted by alert retention check
        assertNull("Findings index should not be deleted when checked against alert retention", result);
    }

    /**
     * Verifies that a findings index IS deleted when it exceeds the finding
     * retention period and is checked against the correct (findings) history type
     * with history disabled (simulating the write alias moved to newer index).
     */
    public void testFindingsIndexDeletedByFindingRetentionWhenExpired() throws Exception {
        // Simulate a findings index that is 5 days old
        long fiveDaysAgo = Instant.now().toEpochMilli() - (5 * 24 * 60 * 60 * 1000L);

        // Finding retention is 4 days (findings index IS older than this)
        long findingRetentionMillis = 4 * 24 * 60 * 60 * 1000L;

        // Create an IndexMetadata with a findings alias
        String findingsAlias = ".opensearch-sap-findings-history-windows";
        IndexMetadata indexMetadata = createIndexMetadata(
                ".opensearch-sap-findings-history-windows-000001",
                fiveDaysAgo,
                findingsAlias
        );

        // Finding history indices with the MATCHING alias
        List historyIndices = createHistoryIndexInfoList(findingsAlias);

        // historyEnabled=false: the index no longer holds the write alias (rolled over)
        String result = DetectorIndexManagementService.getHistoryIndexToDelete(
                indexMetadata, findingRetentionMillis, historyIndices, false
        );

        assertNotNull("Findings index should be deleted when it exceeds finding retention", result);
        assertEquals(".opensearch-sap-findings-history-windows-000001", result);
    }

    /**
     * Verifies that a findings index is NOT deleted when it has not yet
     * exceeded the finding retention period.
     */
    public void testFindingsIndexNotDeletedWhenYoungerThanRetention() throws Exception {
        // Simulate a findings index that is 3 days old
        long threeDaysAgo = Instant.now().toEpochMilli() - (3 * 24 * 60 * 60 * 1000L);

        // Finding retention is 4 days (findings index is NOT older than this)
        long findingRetentionMillis = 4 * 24 * 60 * 60 * 1000L;

        String findingsAlias = ".opensearch-sap-findings-history-windows";
        IndexMetadata indexMetadata = createIndexMetadata(
                ".opensearch-sap-findings-history-windows-000001",
                threeDaysAgo,
                findingsAlias
        );

        List historyIndices = createHistoryIndexInfoList(findingsAlias);

        String result = DetectorIndexManagementService.getHistoryIndexToDelete(
                indexMetadata, findingRetentionMillis, historyIndices, true
        );

        assertNull("Findings index should not be deleted when younger than retention period", result);
    }

    // --- Helpers ---

    private IndexMetadata createIndexMetadata(String indexName, long creationDate, String alias) {
        return IndexMetadata.builder(indexName)
                .settings(Settings.builder()
                        .put(IndexMetadata.SETTING_VERSION_CREATED, Version.CURRENT)
                        .put(IndexMetadata.SETTING_NUMBER_OF_SHARDS, 1)
                        .put(IndexMetadata.SETTING_NUMBER_OF_REPLICAS, 0)
                        .put(IndexMetadata.SETTING_CREATION_DATE, creationDate)
                        .build())
                .putAlias(AliasMetadata.builder(alias).build())
                .build();
    }

    /**
     * Creates a list containing a single HistoryIndexInfo with the given alias.
     * Uses reflection since HistoryIndexInfo is a private static inner class.
     */
    @SuppressWarnings("unchecked")
    private List createHistoryIndexInfoList(String alias) throws Exception {
        Class<?> historyIndexInfoClass = Class.forName(
                "org.opensearch.securityanalytics.indexmanagment.DetectorIndexManagementService$HistoryIndexInfo"
        );
        Constructor<?> constructor = historyIndexInfoClass.getDeclaredConstructors()[0];
        constructor.setAccessible(true);
        // HistoryIndexInfo(String indexAlias, String indexPattern, String indexMappings, Long maxDocs, TimeValue maxAge, boolean isInitialized)
        Object info = constructor.newInstance(alias, alias + "-*", "{}", 1000L, TimeValue.timeValueDays(30), true);
        List list = new ArrayList<>();
        list.add(info);
        return list;
    }
}
