/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package org.opensearch.securityanalytics.resthandler;

import org.junit.Assert;
import org.opensearch.client.Response;
import org.opensearch.core.rest.RestStatus;
import org.opensearch.index.IndexNotFoundException;
import org.opensearch.securityanalytics.SecurityAnalyticsPlugin;
import org.opensearch.securityanalytics.SecurityAnalyticsRestTestCase;
import org.opensearch.securityanalytics.TestHelpers;
import org.opensearch.securityanalytics.model.DetailedSTIX2IOCDto;
import org.opensearch.securityanalytics.model.threatintel.IocFinding;
import org.opensearch.securityanalytics.model.threatintel.IocWithFeeds;
import org.opensearch.securityanalytics.threatIntel.action.ListIOCsActionResponse;
import org.opensearch.securityanalytics.commons.model.IOCType;
import org.opensearch.securityanalytics.model.STIX2IOC;
import org.opensearch.securityanalytics.model.STIX2IOCDto;
import org.opensearch.securityanalytics.threatIntel.common.SourceConfigType;
import org.opensearch.securityanalytics.threatIntel.iocscan.dao.IocFindingService;
import org.opensearch.securityanalytics.threatIntel.model.IocUploadSource;
import org.opensearch.securityanalytics.threatIntel.model.SATIFSourceConfigDto;
import org.opensearch.securityanalytics.util.STIX2IOCGenerator;

import java.io.IOException;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;

public class ListIOCsRestApiIT extends SecurityAnalyticsRestTestCase {

    public void testListIOCsWithNoFindingsIndex() throws IOException {
        // Delete findings system indexes if they exist
        try {
            makeRequest(client(), "DELETE", IocFindingService.IOC_FINDING_INDEX_PATTERN_REGEXP, Collections.emptyMap(), null);
        } catch (IndexNotFoundException indexNotFoundException) {
            logger.info("No threat intel findings indexes to delete.");
        } catch (Exception e) {
            logger.error(e.getMessage());
        }

        // Create IOCs
        String searchString = "test-list-iocs-no-findings-index";
        Map<String, STIX2IOCDto> iocs = new HashMap<>();
        for (int i = 0; i < 100; i++) {
            String iocId = searchString + "-" + i;
            iocs.put(
                    iocId,
                    new STIX2IOCDto(
                            iocId,
                            iocId + "-name",
                            new IOCType(IOCType.IPV4_TYPE),
                            "ipv4value" + i,
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
        }

        // Creating source config
        SATIFSourceConfigDto saTifSourceConfigDto = new SATIFSourceConfigDto(
                null,
                null,
                "test_list_ioc_" + searchString,
                "STIX",
                SourceConfigType.IOC_UPLOAD,
                null,
                null,
                null,
                new IocUploadSource(null, new ArrayList<>(iocs.values())),
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

        // Call ListIOCs API
        Map<String, String> params = Map.of(
                "searchString", searchString,
                "size", "10000"
        );
        Response iocResponse = makeRequest(client(), "GET", STIX2IOCGenerator.getListIOCsURI(), params, null);
        Assert.assertEquals(RestStatus.OK, restStatus(iocResponse));
        Map<String, Object> respMap = asMap(iocResponse);

        // Evaluate response
        int totalHits = (int) respMap.get(ListIOCsActionResponse.TOTAL_HITS_FIELD);
        assertEquals(iocs.size(), totalHits);

        List<Map<String, Object>> iocHits = (List<Map<String, Object>>) respMap.get(ListIOCsActionResponse.HITS_FIELD);
        assertEquals(iocs.size(), iocHits.size());

        iocHits.forEach((hit) -> {
            String iocId = (String) hit.get(STIX2IOC.ID_FIELD);
            String iocName = (String) hit.get(STIX2IOC.NAME_FIELD);
            String iocValue = (String) hit.get(STIX2IOC.VALUE_FIELD);

            STIX2IOCDto iocDto = iocs.get(iocId);
            assertNotNull(iocDto);

            assertEquals(iocDto.getId(), iocId);
            assertEquals(iocDto.getName(), iocName);
            assertEquals(iocDto.getValue(), iocValue);

            int findingsNum = (int) hit.get(DetailedSTIX2IOCDto.NUM_FINDINGS_FIELD);
            int expectedNumFindings = 0;
            assertEquals(expectedNumFindings, findingsNum);
        });
    }

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

    public void testListIOCsNumFindings() throws Exception {
        // Create IOCs
        String searchString = "test-list-iocs-num-findings";
        List<STIX2IOCDto> iocs = new ArrayList<>();
        Map<String, List<IocFinding>> iocIdFindingsNum = new HashMap<>();
        for (int i = 0; i < 5; i++) {
            String iocId = searchString + "-" + i;
            iocs.add(
                    new STIX2IOCDto(
                            iocId,
                            iocId + "-name",
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

            // Confirming the ListIOCs API can return a findings count greater than 10,000 by giving the first IOC 10,005 findings
            int numFindings = i == 0 ? 10005 : randomInt(10);
            List<IocFinding> iocFindings = generateIOCMatches(numFindings, iocId);

            // Tracking the number of findings expected for each IOC
            iocIdFindingsNum.put(iocId, iocFindings);
        }

        // Creating source config
        SATIFSourceConfigDto saTifSourceConfigDto = new SATIFSourceConfigDto(
                null,
                null,
                "test_list_ioc_" + searchString,
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

        // Generate IOC matches
        for (Map.Entry<String, List<IocFinding>> entry : iocIdFindingsNum.entrySet()) {
            ingestIOCMatches(entry.getValue());
        }

        // Call ListIOCs API
        Response iocResponse = makeRequest(client(), "GET", STIX2IOCGenerator.getListIOCsURI(), Map.of("searchString", searchString), null);
        Assert.assertEquals(RestStatus.OK, restStatus(iocResponse));
        Map<String, Object> respMap = asMap(iocResponse);

        // Evaluate response
        int totalHits = (int) respMap.get(ListIOCsActionResponse.TOTAL_HITS_FIELD);
        assertEquals(iocs.size(), totalHits);

        List<Map<String, Object>> iocHits = (List<Map<String, Object>>) respMap.get(ListIOCsActionResponse.HITS_FIELD);
        assertEquals(iocs.size(), iocHits.size());

        iocHits.forEach((hit) -> {
            String iocId = (String) hit.get(STIX2IOC.ID_FIELD);
            int findingsNum = (int) hit.get(DetailedSTIX2IOCDto.NUM_FINDINGS_FIELD);
            int expectedNumFindings = iocIdFindingsNum.get(iocId).size();
            assertEquals(expectedNumFindings, findingsNum);
        });
    }

    private List<IocFinding> generateIOCMatches(int numMatches, String iocId) {
        List<IocFinding> iocFindings = new ArrayList<>();
        String monitorId = randomAlphaOfLength(10);
        String monitorName = randomAlphaOfLength(10);
        for (int i = 0; i < numMatches; i++) {
            iocFindings.add(new IocFinding(
                    randomAlphaOfLength(10),
                    randomList(1, 10, () -> randomAlphaOfLength(10)),//docIds
                    randomList(1, 10, () -> new IocWithFeeds(
                            iocId,
                            randomAlphaOfLength(10),
                            randomAlphaOfLength(10),
                            randomAlphaOfLength(10))
                    ), //feedIds
                    monitorId,
                    monitorName,
                    randomAlphaOfLength(10),
                    IOCType.IPV4_TYPE,
                    Instant.now(),
                    randomAlphaOfLength(10)
            ));
        }
        return iocFindings;
    }

    private void ingestIOCMatches(List<IocFinding> iocFindings) throws IOException {
        for (IocFinding iocFinding: iocFindings) {
            makeRequest(client(), "POST", IocFindingService.IOC_FINDING_ALIAS_NAME + "/_doc?refresh", Map.of(),
                    toHttpEntity(iocFinding));
        }
    }
}
