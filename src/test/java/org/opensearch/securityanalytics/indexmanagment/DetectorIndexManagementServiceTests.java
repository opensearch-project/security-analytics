/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.securityanalytics.indexmanagment;

import org.opensearch.Version;
import org.opensearch.cluster.metadata.AliasMetadata;
import org.opensearch.cluster.metadata.IndexMetadata;
import org.opensearch.cluster.service.ClusterManagerThrottlingException;
import org.opensearch.common.regex.Regex;
import org.opensearch.common.settings.Settings;
import org.opensearch.common.unit.TimeValue;
import org.opensearch.securityanalytics.config.monitors.DetectorMonitorConfig;
import org.opensearch.snapshots.SnapshotInProgressException;
import org.opensearch.test.OpenSearchTestCase;
import org.opensearch.transport.RemoteTransportException;

import java.util.List;
import java.util.Set;
import java.util.concurrent.TimeUnit;

public class DetectorIndexManagementServiceTests extends OpenSearchTestCase {

    private static final long NOW = System.currentTimeMillis();
    private static final long RETENTION_30D = TimeUnit.DAYS.toMillis(30);
    private static final String FINDINGS_ALIAS = DetectorMonitorConfig.getFindingsIndex("windows");

    public void testRolledOverIndexOlderThanRetentionIsDeleted() {
        IndexMetadata rolledOver = index(".opensearch-sap-windows-findings-2026.01.01-000001", 31, null);

        assertEquals(
                rolledOver.getIndex().getName(),
                DetectorIndexManagementService.getHistoryIndexToDelete(rolledOver, NOW, RETENTION_30D, Set.of(FINDINGS_ALIAS), true)
        );
    }

    public void testIndexYoungerThanRetentionIsKept() {
        IndexMetadata young = index(".opensearch-sap-windows-findings-2026.01.01-000002", 29, null);

        assertNull(DetectorIndexManagementService.getHistoryIndexToDelete(young, NOW, RETENTION_30D, Set.of(FINDINGS_ALIAS), true));
    }

    public void testCurrentWriteIndexIsKeptWhenHistoryEnabled() {
        IndexMetadata writeIndex = index(".opensearch-sap-windows-findings-2026.01.01-000003", 45, FINDINGS_ALIAS);

        assertNull(DetectorIndexManagementService.getHistoryIndexToDelete(writeIndex, NOW, RETENTION_30D, Set.of(FINDINGS_ALIAS), true));
    }

    public void testCurrentWriteIndexIsDeletedWhenHistoryDisabled() {
        IndexMetadata writeIndex = index(".opensearch-sap-windows-findings-2026.01.01-000003", 45, FINDINGS_ALIAS);

        assertEquals(
                writeIndex.getIndex().getName(),
                DetectorIndexManagementService.getHistoryIndexToDelete(writeIndex, NOW, RETENTION_30D, Set.of(FINDINGS_ALIAS), false)
        );
    }

    /**
     * Each history type is evaluated against its own retention only: a findings index older than the alerts
     * retention but younger than the findings retention must not be selected.
     */
    public void testFindingsIndexEvaluatedOnlyAgainstFindingsRetention() {
        IndexMetadata findings = index(".opensearch-sap-windows-findings-2026.01.01-000004", 31, null);
        long findingsRetention60d = TimeUnit.DAYS.toMillis(60);

        assertTrue(
                DetectorIndexManagementService.getIndicesToDelete(
                        List.of(findings), NOW, findingsRetention60d, Set.of(FINDINGS_ALIAS), true
                ).isEmpty()
        );
    }

    public void testOnlyExpiredNonWriteIndicesAreSelected() {
        IndexMetadata expired = index(".opensearch-sap-windows-findings-2026.01.01-000001", 40, null);
        IndexMetadata expiredWriteIndex = index(".opensearch-sap-windows-findings-2026.01.01-000002", 35, FINDINGS_ALIAS);
        IndexMetadata young = index(".opensearch-sap-windows-findings-2026.01.01-000003", 5, null);

        assertEquals(
                List.of(expired.getIndex().getName()),
                DetectorIndexManagementService.getIndicesToDelete(
                        List.of(expired, expiredWriteIndex, young), NOW, RETENTION_30D, Set.of(FINDINGS_ALIAS), true
                )
        );
    }

    public void testAlertsHistoryPatternDoesNotMatchActiveAlertsIndex() {
        String pattern = DetectorMonitorConfig.getAllAlertsHistoryIndicesPattern("windows");

        assertFalse(Regex.simpleMatch(pattern, DetectorMonitorConfig.getAlertsIndex("windows")));
        assertTrue(Regex.simpleMatch(pattern, ".opensearch-sap-windows-alerts-history-2026.01.01-000001"));
    }

    public void testSnapshotAndThrottlingFailuresAreRetryable() {
        assertTrue(DetectorIndexManagementService.isRetryableHistoryDeleteFailure(
                new SnapshotInProgressException("Cannot delete indices that are being snapshotted")
        ));
        assertTrue(DetectorIndexManagementService.isRetryableHistoryDeleteFailure(
                new RemoteTransportException("wrapped", new SnapshotInProgressException("being snapshotted"))
        ));
        assertTrue(DetectorIndexManagementService.isRetryableHistoryDeleteFailure(
                new ClusterManagerThrottlingException("throttled")
        ));
    }

    public void testOtherFailuresAreNotRetryable() {
        assertFalse(DetectorIndexManagementService.isRetryableHistoryDeleteFailure(new IllegalArgumentException("bad request")));
    }

    public void testRetryDelayBacksOffExponentially() {
        assertEquals(3, DetectorIndexManagementService.MAX_HISTORY_DELETE_RETRIES);
        assertEquals(TimeValue.timeValueMinutes(5), DetectorIndexManagementService.historyDeleteRetryDelay(0));
        assertEquals(TimeValue.timeValueMinutes(10), DetectorIndexManagementService.historyDeleteRetryDelay(1));
        assertEquals(TimeValue.timeValueMinutes(20), DetectorIndexManagementService.historyDeleteRetryDelay(2));
    }

    private static IndexMetadata index(String name, int ageDays, String alias) {
        IndexMetadata.Builder builder = IndexMetadata.builder(name)
                .settings(Settings.builder().put(IndexMetadata.SETTING_VERSION_CREATED, Version.CURRENT))
                .creationDate(NOW - TimeUnit.DAYS.toMillis(ageDays))
                .numberOfShards(1)
                .numberOfReplicas(0);
        if (alias != null) {
            builder.putAlias(AliasMetadata.builder(alias).build());
        }
        return builder.build();
    }
}
