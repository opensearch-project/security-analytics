/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.securityanalytics.transport;

import java.time.Instant;
import java.time.ZoneId;
import java.util.List;
import java.util.Map;
import org.opensearch.action.support.WriteRequest;
import org.opensearch.commons.alerting.action.IndexMonitorRequest;
import org.opensearch.commons.alerting.model.CronSchedule;
import org.opensearch.commons.alerting.model.DataSources;
import org.opensearch.commons.alerting.model.Monitor;
import org.opensearch.rest.RestRequest;
import org.opensearch.securityanalytics.TestHelpers;
import org.opensearch.securityanalytics.model.Detector;
import org.opensearch.test.OpenSearchTestCase;

public class ChainedFindingsMonitorConfigTests extends OpenSearchTestCase {

    private Detector createDetectorForTest() {
        Detector detector = TestHelpers.randomDetector(List.of());
        detector.setRuleIndex(".opensearch-sap-windows-detectors-queries");
        detector.setFindingsIndex(".opensearch-sap-windows-findings");
        detector.setFindingsIndexPattern(".opensearch-sap-windows-findings*");
        detector.setAlertsIndex(".opensearch-sap-windows-alerts");
        detector.setAlertsHistoryIndex(".opensearch-sap-windows-alerts-history");
        detector.setAlertsHistoryIndexPattern(".opensearch-sap-windows-alerts-history*");
        return detector;
    }

    /**
     * Pins the public constants introduced in TransportIndexDetectorAction.
     * The production {@code createDocLevelMonitorMatchAllRequest} method references
     * {@code CHAINED_FINDINGS_DELETE_QUERY_INDEX_IN_EVERY_RUN} (false) and
     * {@code CHAINED_FINDINGS_SHOULD_CREATE_SINGLE_ALERT_FOR_FINDINGS} (true) directly.
     */
    public void testChainedFindingsMonitorConstants() {
        assertFalse(
                "CHAINED_FINDINGS_DELETE_QUERY_INDEX_IN_EVERY_RUN must be false to prevent the " +
                "chained_findings monitor from deleting its query index on every execution cycle " +
                "(regression #1725). Do not change this constant without understanding the " +
                "DocLevelMonitorQueries.kt interaction in opensearch-project/alerting.",
                TransportIndexDetectorAction.CHAINED_FINDINGS_DELETE_QUERY_INDEX_IN_EVERY_RUN
        );

        assertTrue(
                "CHAINED_FINDINGS_SHOULD_CREATE_SINGLE_ALERT_FOR_FINDINGS must be true so that " +
                "chained findings generate a single alert across all finding docs rather than separate alerts.",
                TransportIndexDetectorAction.CHAINED_FINDINGS_SHOULD_CREATE_SINGLE_ALERT_FOR_FINDINGS
        );
    }

    /**
     * Validates that production {@code createDocLevelMonitorMatchAllRequest} configures the
     * Monitor with deleteQueryIndexInEveryRun=false and shouldCreateSingleAlertForFindings=true,
     * even when enableDetectorWithDedicatedQueryIndices is true.
     */
    public void testCreateDocLevelMonitorMatchAllRequest_productionMonitorSettings() {
        Detector detector = createDetectorForTest();
        IndexMonitorRequest request = TransportIndexDetectorAction.createDocLevelMonitorMatchAllRequest(
                detector,
                WriteRequest.RefreshPolicy.IMMEDIATE,
                "test_monitor_id",
                RestRequest.Method.POST,
                List.of(),
                true
        );

        Monitor monitor = request.getMonitor();
        assertNotNull("Monitor must not be null", monitor);
        assertEquals(
                "chained_findings monitor must have deleteQueryIndexInEveryRun=false (regression #1725)",
                Boolean.FALSE,
                monitor.getDeleteQueryIndexInEveryRun()
        );
        assertEquals(
                "chained_findings monitor must have shouldCreateSingleAlertForFindings=true so multiple " +
                "docs in a finding result in a single alert rather than separate alerts",
                Boolean.TRUE,
                monitor.getShouldCreateSingleAlertForFindings()
        );
        assertEquals(
                "chained_findings monitor owner must be security_analytics",
                TransportIndexDetectorAction.PLUGIN_OWNER_FIELD,
                monitor.getOwner()
        );
    }

    /**
     * Validates that production {@code createDocLevelMonitorMatchAllRequest} configures the
     * Monitor correctly when enableDetectorWithDedicatedQueryIndices is false.
     */
    public void testCreateDocLevelMonitorMatchAllRequest_withDedicatedQueryIndicesFalse() {
        Detector detector = createDetectorForTest();
        IndexMonitorRequest request = TransportIndexDetectorAction.createDocLevelMonitorMatchAllRequest(
                detector,
                WriteRequest.RefreshPolicy.IMMEDIATE,
                "test_monitor_id",
                RestRequest.Method.POST,
                List.of(),
                false
        );

        Monitor monitor = request.getMonitor();
        assertNotNull("Monitor must not be null", monitor);
        assertEquals(
                "chained_findings monitor must have deleteQueryIndexInEveryRun=false",
                Boolean.FALSE,
                monitor.getDeleteQueryIndexInEveryRun()
        );
        assertEquals(
                "chained_findings monitor must have shouldCreateSingleAlertForFindings=true",
                Boolean.TRUE,
                monitor.getShouldCreateSingleAlertForFindings()
        );
    }

    /**
     * Validates the Monitor constructor API contract: parameter 15 is deleteQueryIndexInEveryRun
     * and parameter 16 is shouldCreateSingleAlertForFindings.
     */
    public void testMonitorConstructor_parameterSlots() {
        Monitor monitor = new Monitor(
                "test_monitor_id",
                -3L,
                "test_detector_chained_findings",
                false,
                new CronSchedule("0 * * * *", ZoneId.of("UTC"), Instant.ofEpochSecond(1538164858L)),
                Instant.now(),
                null,
                Monitor.MonitorType.DOC_LEVEL_MONITOR.getValue(),
                null,
                1,
                List.of(),
                List.of(),
                Map.of(),
                new DataSources(),
                false, // param 15: deleteQueryIndexInEveryRun
                true,  // param 16: shouldCreateSingleAlertForFindings
                TransportIndexDetectorAction.PLUGIN_OWNER_FIELD, // param 17: owner
                null,
                null
        );

        assertEquals(
                "Parameter 15 must map to deleteQueryIndexInEveryRun",
                Boolean.FALSE,
                monitor.getDeleteQueryIndexInEveryRun()
        );
        assertEquals(
                "Parameter 16 must map to shouldCreateSingleAlertForFindings",
                Boolean.TRUE,
                monitor.getShouldCreateSingleAlertForFindings()
        );
        assertEquals(
                "Parameter 17 must map to owner",
                "security_analytics",
                monitor.getOwner()
        );
    }

    /**
     * Adversarial sanity check: when {@code deleteQueryIndexInEveryRun=true} is passed,
     * the monitor reflects that value. Confirms the regression assertion above is
     * non-trivial — the getter does not ignore the constructor argument.
     */
    public void testMonitor_deleteQueryIndexInEveryRun_reflectsConstructorArg_whenTrue() {
        Monitor monitor = new Monitor(
                "test_monitor_id",
                -3L,
                "test_detector_chained_findings",
                false,
                new CronSchedule("0 * * * *", ZoneId.of("UTC"), Instant.ofEpochSecond(1538164858L)),
                Instant.now(),
                null,
                Monitor.MonitorType.DOC_LEVEL_MONITOR.getValue(),
                null,
                1,
                List.of(),
                List.of(),
                Map.of(),
                new DataSources(),
                true, // intentionally true
                null,
                TransportIndexDetectorAction.PLUGIN_OWNER_FIELD,
                null,
                null
        );

        assertEquals(
                "Monitor with deleteQueryIndexInEveryRun=true must expose that value via getter",
                Boolean.TRUE,
                monitor.getDeleteQueryIndexInEveryRun()
        );
    }

    /**
     * PLUGIN_OWNER_FIELD must equal the sentinel value the alerting plugin uses
     * to identify monitors owned by security-analytics.
     */
    public void testPluginOwnerField_hasExpectedValue() {
        assertEquals(
                "PLUGIN_OWNER_FIELD must identify this plugin to the alerting subsystem",
                "security_analytics",
                TransportIndexDetectorAction.PLUGIN_OWNER_FIELD
        );
    }
}
