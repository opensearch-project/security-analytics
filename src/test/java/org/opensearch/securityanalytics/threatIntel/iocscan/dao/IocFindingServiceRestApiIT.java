/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.securityanalytics.threatIntel.iocscan.dao;

import org.junit.Assert;
import org.opensearch.client.Response;
import org.opensearch.securityanalytics.SecurityAnalyticsPlugin;
import org.opensearch.securityanalytics.SecurityAnalyticsRestTestCase;
import org.opensearch.securityanalytics.model.threatintel.IocFinding;
import org.opensearch.securityanalytics.model.threatintel.IocWithFeeds;
import org.opensearch.test.OpenSearchTestCase;

import java.io.IOException;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;

import static org.opensearch.securityanalytics.settings.SecurityAnalyticsSettings.*;

public class IocFindingServiceRestApiIT extends SecurityAnalyticsRestTestCase {

    @SuppressWarnings("unchecked")
    public void testGetIocFindings() throws IOException {
        makeRequest(client(), "GET", SecurityAnalyticsPlugin.THREAT_INTEL_BASE_URI + "/findings/_search?startIndex=1&size=5",
                Map.of(), null);
        List<IocFinding> iocFindings = generateIocMatches(10);
        for (IocFinding iocFinding: iocFindings) {
            makeRequest(client(), "POST", IocFindingService.IOC_FINDING_ALIAS_NAME + "/_doc?refresh", Map.of(),
                    toHttpEntity(iocFinding));
        }

        Response response = makeRequest(client(), "GET", SecurityAnalyticsPlugin.THREAT_INTEL_BASE_URI + "/findings/_search?startIndex=1&size=5",
                Map.of(), null);
        Map<String, Object> responseAsMap = responseAsMap(response);
        Assert.assertEquals(5, ((List<Map<String, Object>>) responseAsMap.get("ioc_findings")).size());
    }

    @SuppressWarnings("unchecked")
    public void testGetIocFindingsWithIocIdFilter() throws IOException {
        makeRequest(client(), "GET", SecurityAnalyticsPlugin.THREAT_INTEL_BASE_URI + "/findings/_search?startIndex=1&size=5",
                Map.of(), null);
        List<IocFinding> iocFindings = generateIocMatches(10);
        for (IocFinding iocFinding: iocFindings) {
            makeRequest(client(), "POST", IocFindingService.IOC_FINDING_ALIAS_NAME + "/_doc?refresh", Map.of(),
                    toHttpEntity(iocFinding));
        }
        String iocId = iocFindings.stream().map(iocFinding -> iocFinding.getFeedIds().get(0).getIocId()).findFirst().get();

        Response response = makeRequest(client(), "GET", SecurityAnalyticsPlugin.THREAT_INTEL_BASE_URI + "/findings/_search?iocIds=" + iocId,
                Map.of(), null);
        Map<String, Object> responseAsMap = responseAsMap(response);
        Assert.assertEquals(1, ((List<Map<String, Object>>) responseAsMap.get("ioc_findings")).size());
    }

    public void testGetIocFindingsRolloverByMaxDocs() throws IOException, InterruptedException {
        updateClusterSetting(IOC_FINDING_HISTORY_ROLLOVER_PERIOD.getKey(), "1s");
        updateClusterSetting(IOC_FINDING_HISTORY_MAX_DOCS.getKey(), "1");
        makeRequest(client(), "GET", SecurityAnalyticsPlugin.THREAT_INTEL_BASE_URI + "/findings/_search?startIndex=1&size=5",
                Map.of(), null);
        List<IocFinding> iocFindings = generateIocMatches(5);
        for (IocFinding iocFinding: iocFindings) {
            makeRequest(client(), "POST", IocFindingService.IOC_FINDING_ALIAS_NAME + "/_doc?refresh", Map.of(),
                    toHttpEntity(iocFinding));
        }

        AtomicBoolean found = new AtomicBoolean(false);
        OpenSearchTestCase.waitUntil(() -> {
            try {
                found.set(getIocFindingIndices().size() == 2);
                return found.get();
            } catch (IOException e) {
                return false;
            }
        }, 30000, TimeUnit.SECONDS);
        Assert.assertTrue(found.get());
    }

    public void testGetIocFindingsRolloverByMaxAge() throws IOException, InterruptedException {
        updateClusterSetting(IOC_FINDING_HISTORY_ROLLOVER_PERIOD.getKey(), "1s");
        updateClusterSetting(IOC_FINDING_HISTORY_MAX_DOCS.getKey(), "1000");
        updateClusterSetting(IOC_FINDING_HISTORY_INDEX_MAX_AGE.getKey(), "1s");
        makeRequest(client(), "GET", SecurityAnalyticsPlugin.THREAT_INTEL_BASE_URI + "/findings/_search?startIndex=1&size=5",
                Map.of(), null);
        List<IocFinding> iocFindings = generateIocMatches(5);
        for (IocFinding iocFinding: iocFindings) {
            makeRequest(client(), "POST", IocFindingService.IOC_FINDING_ALIAS_NAME + "/_doc?refresh", Map.of(),
                    toHttpEntity(iocFinding));
        }

        AtomicBoolean found = new AtomicBoolean(false);
        OpenSearchTestCase.waitUntil(() -> {
            try {
                found.set(getIocFindingIndices().size() == 2);
                return found.get();
            } catch (IOException e) {
                return false;
            }
        }, 30000, TimeUnit.SECONDS);
        Assert.assertTrue(found.get());

        updateClusterSetting(IOC_FINDING_HISTORY_INDEX_MAX_AGE.getKey(), "1000s");
        updateClusterSetting(IOC_FINDING_HISTORY_RETENTION_PERIOD.getKey(), "1s");

        AtomicBoolean retFound = new AtomicBoolean(false);
        OpenSearchTestCase.waitUntil(() -> {
            try {
                retFound.set(getIocFindingIndices().size() == 1);
                return retFound.get();
            } catch (IOException e) {
                return false;
            }
        }, 30000, TimeUnit.SECONDS);
        Assert.assertTrue(retFound.get());
    }

    private List<IocFinding> generateIocMatches(int i) {
        List<IocFinding> iocFindings = new ArrayList<>();
        String monitorId = randomAlphaOfLength(10);
        String monitorName = randomAlphaOfLength(10);
        for (int i1 = 0; i1 < i; i1++) {
            iocFindings.add(new IocFinding(
                    randomAlphaOfLength(10),
                    randomList(1, 10, () -> randomAlphaOfLength(10)),//docids
                    randomList(1, 10, () -> new IocWithFeeds(randomAlphaOfLength(10), randomAlphaOfLength(10), randomAlphaOfLength(10))), //feedids
                    monitorId,
                    monitorName,
                    randomAlphaOfLength(10),
                    "IP",
                    Instant.now(),
                    randomAlphaOfLength(10)
            ));
        }
        return iocFindings;
    }
}