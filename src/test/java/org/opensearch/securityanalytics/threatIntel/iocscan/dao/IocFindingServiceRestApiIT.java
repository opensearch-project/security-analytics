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

import java.io.IOException;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

public class IocFindingServiceRestApiIT extends SecurityAnalyticsRestTestCase {

    @SuppressWarnings("unchecked")
    public void testGetIocFindings() throws IOException {
        List<IocFinding> iocFindings = generateIocMatches(10);
        for (IocFinding iocFinding: iocFindings) {
            makeRequest(client(), "POST", IocFindingService.INDEX_NAME + "/_doc?refresh", Map.of(),
                    toHttpEntity(iocFinding));
        }

        Response response = makeRequest(client(), "GET", SecurityAnalyticsPlugin.THREAT_INTEL_BASE_URI + "/findings/_search?startIndex=1&size=5",
                Map.of(), null);
        Map<String, Object> responseAsMap = responseAsMap(response);
        Assert.assertEquals(5, ((List<Map<String, Object>>) responseAsMap.get("ioc_findings")).size());
    }

    private List<IocFinding> generateIocMatches(int i) {
        List<IocFinding> iocFindings = new ArrayList<>();
        String monitorId = randomAlphaOfLength(10);
        String monitorName = randomAlphaOfLength(10);
        for (int i1 = 0; i1 < i; i1++) {
            iocFindings.add(new IocFinding(
                    randomAlphaOfLength(10),
                    randomList(1, 10, () -> randomAlphaOfLength(10)),//docids
                    randomList(1, 10, () -> randomAlphaOfLength(10)), //feedids
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