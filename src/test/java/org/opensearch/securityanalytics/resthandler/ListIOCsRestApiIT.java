/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package org.opensearch.securityanalytics.resthandler;

import org.junit.Assert;
import org.opensearch.client.Response;
import org.opensearch.core.rest.RestStatus;
import org.opensearch.securityanalytics.SecurityAnalyticsPlugin;
import org.opensearch.securityanalytics.SecurityAnalyticsRestTestCase;
import org.opensearch.securityanalytics.TestHelpers;
import org.opensearch.securityanalytics.action.ListIOCsActionResponse;
import org.opensearch.securityanalytics.commons.model.IOCType;
import org.opensearch.securityanalytics.model.STIX2IOC;
import org.opensearch.securityanalytics.model.STIX2IOCDto;
import org.opensearch.securityanalytics.threatIntel.common.SourceConfigType;
import org.opensearch.securityanalytics.threatIntel.model.IocUploadSource;
import org.opensearch.securityanalytics.threatIntel.model.SATIFSourceConfigDto;
import org.opensearch.securityanalytics.util.STIX2IOCGenerator;

import java.io.IOException;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Objects;

public class ListIOCsRestApiIT extends SecurityAnalyticsRestTestCase {

    public void testListIOCsBySearchString() throws IOException {
        String searchString = "test-search-string";
        List<STIX2IOCDto> iocs = List.of(
                // The 'name' field matches the searchString
                new STIX2IOCDto(
                        "id1",
                        searchString,
                        new IOCType(IOCType.IPV4_TYPE),
                        "ipv4value",
                        "severity",
                        null,
                        null,
                        "description",
                        List.of("labels"),
                        "specversion",
                        "feedId",
                        "feedName",
                        1L
                ),
                // The 'value' field matches the searchString
                new STIX2IOCDto(
                        "id2",
                        TestHelpers.randomLowerCaseString(),
                        new IOCType(IOCType.IPV4_TYPE),
                        searchString,
                        "severity",
                        null,
                        null,
                        "description",
                        List.of("labels"),
                        "specversion",
                        "feedId",
                        "feedName",
                        1L
                ),
                // No fields match the searchString
                new STIX2IOCDto(
                        "id3",
                        "name",
                        new IOCType(IOCType.IPV4_TYPE),
                        "ipv4value",
                        "severity",
                        null,
                        null,
                        "description",
                        List.of("labels"),
                        "specversion",
                        "feedId",
                        "feedName",
                        1L
                )
        );

        SATIFSourceConfigDto saTifSourceConfigDto = new SATIFSourceConfigDto(
                null,
                null,
                "test_list_ioc_searchstring",
                "STIX",
                SourceConfigType.IOC_UPLOAD,
                null,
                null,
                null,
                new IocUploadSource(null, iocs),
                null,
                null,
                null,
                null,
                null,
                null,
                null,
                false,
                List.of(IOCType.IPV4_TYPE),
                true
        );

        // Create the IOC system indexes using IOC_UPLOAD config
        Response response = makeRequest(client(), "POST", SecurityAnalyticsPlugin.THREAT_INTEL_SOURCE_URI, Collections.emptyMap(), toHttpEntity(saTifSourceConfigDto));
        Assert.assertEquals(RestStatus.CREATED, restStatus(response));

        // Retrieve IOCs matching searchString
        Response iocResponse = makeRequest(client(), "GET", STIX2IOCGenerator.getListIOCsURI(), Map.of("searchString", searchString), null);
        Assert.assertEquals(RestStatus.OK, restStatus(iocResponse));
        Map<String, Object> respMap = asMap(iocResponse);

        // Evaluate response
        int totalHits = (int) respMap.get(ListIOCsActionResponse.TOTAL_HITS_FIELD);
        assertEquals(2, totalHits);

        List<Map<String, Object>> iocHits = (List<Map<String, Object>>) respMap.get(ListIOCsActionResponse.HITS_FIELD);
        assertEquals(2, iocHits.size());

        int nameMatch = (int) iocHits.stream().filter((hit) -> Objects.equals(hit.get(STIX2IOC.NAME_FIELD), searchString)).count();
        int valueMatch = (int) iocHits.stream().filter((hit) -> Objects.equals(hit.get(STIX2IOC.VALUE_FIELD), searchString)).count();
        assertEquals(1, nameMatch);
        assertEquals(1, valueMatch);
    }

    // TODO: Implement additional tests using various query param combinations
}
