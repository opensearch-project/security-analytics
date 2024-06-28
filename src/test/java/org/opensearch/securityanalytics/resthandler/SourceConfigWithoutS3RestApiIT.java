/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */

package org.opensearch.securityanalytics.resthandler;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.junit.Assert;
import org.opensearch.client.Response;
import org.opensearch.search.SearchHit;
import org.opensearch.securityanalytics.SecurityAnalyticsPlugin;
import org.opensearch.securityanalytics.SecurityAnalyticsRestTestCase;
import org.opensearch.securityanalytics.action.ListIOCsActionRequest;
import org.opensearch.securityanalytics.action.ListIOCsActionResponse;
import org.opensearch.securityanalytics.commons.model.IOCType;
import org.opensearch.securityanalytics.model.STIX2IOCDto;
import org.opensearch.securityanalytics.services.STIX2IOCFeedStore;
import org.opensearch.securityanalytics.threatIntel.common.SourceConfigType;
import org.opensearch.securityanalytics.threatIntel.model.IocUploadSource;
import org.opensearch.securityanalytics.threatIntel.model.SATIFSourceConfigDto;
import org.opensearch.securityanalytics.util.STIX2IOCGenerator;

import java.io.IOException;
import java.util.Collections;
import java.util.List;
import java.util.Locale;
import java.util.Map;

import static org.opensearch.securityanalytics.SecurityAnalyticsPlugin.JOB_INDEX_NAME;

public class SourceConfigWithoutS3RestApiIT extends SecurityAnalyticsRestTestCase {
    private static final Logger log = LogManager.getLogger(SourceConfigWithoutS3RestApiIT.class);

    public void testCreateIocUploadSourceConfig() throws IOException {
        String feedName = "test_ioc_upload";
        String feedFormat = "STIX";
        SourceConfigType sourceConfigType = SourceConfigType.IOC_UPLOAD;

        List<STIX2IOCDto> iocs = List.of(new STIX2IOCDto(
                "id",
                "name",
                IOCType.ip,
                "value",
                "severity",
                null,
                null,
                "description",
                List.of("labels"),
                "specversion",
                "feedId",
                "feedName",
                1L));

        IocUploadSource iocUploadSource = new IocUploadSource(null, iocs);
        Boolean enabled = false;
        List<String> iocTypes = List.of("ip");
        SATIFSourceConfigDto saTifSourceConfigDto = new SATIFSourceConfigDto(
                null,
                null,
                feedName,
                feedFormat,
                sourceConfigType,
                null,
                null,
                null,
                iocUploadSource,
                null,
                null,
                null,
                null,
                null,
                null,
                null,
                enabled,
                iocTypes
        );

        Response response = makeRequest(client(), "POST", SecurityAnalyticsPlugin.THREAT_INTEL_SOURCE_URI, Collections.emptyMap(), toHttpEntity(saTifSourceConfigDto));
        Assert.assertEquals(201, response.getStatusLine().getStatusCode());
        Map<String, Object> responseBody = asMap(response);

        String createdId = responseBody.get("_id").toString();
        Assert.assertNotEquals("response is missing Id", SATIFSourceConfigDto.NO_ID, createdId);

        int createdVersion = Integer.parseInt(responseBody.get("_version").toString());
        Assert.assertTrue("incorrect version", createdVersion > 0);
        Assert.assertEquals("Incorrect Location header", String.format(Locale.getDefault(), "%s/%s", SecurityAnalyticsPlugin.THREAT_INTEL_SOURCE_URI, createdId), response.getHeader("Location"));

        String request = "{\n" +
                "   \"query\" : {\n" +
                "     \"match_all\":{\n" +
                "     }\n" +
                "   }\n" +
                "}";
        List<SearchHit> hits = executeSearch(JOB_INDEX_NAME, request);
        Assert.assertEquals(1, hits.size());

        // ensure same number of iocs got indexed
        String indexName = STIX2IOCFeedStore.getIocIndexAlias(createdId);
        hits = executeSearch(indexName, request);
        Assert.assertEquals(iocs.size(), hits.size());

//         Retrieve all IOCs
        Response iocResponse = makeRequest(client(), "GET", STIX2IOCGenerator.getListIOCsURI(), Collections.emptyMap(), null);
        Assert.assertEquals(200, iocResponse.getStatusLine().getStatusCode());
        Map<String, Object> respMap = asMap(iocResponse);

        // Evaluate response
        int totalHits = (int) respMap.get(ListIOCsActionResponse.TOTAL_HITS_FIELD);
        assertEquals(iocs.size(), totalHits);

        List<Map<String, Object>> iocHits = (List<Map<String, Object>>) respMap.get(ListIOCsActionResponse.HITS_FIELD);
        assertEquals(iocs.size(), iocHits.size());
//         Retrieve all IOCs by feed Ids
        iocResponse = makeRequest(client(), "GET", STIX2IOCGenerator.getListIOCsURI(), Map.of("feed_id", createdId + ",random"), null);
        Assert.assertEquals(200, iocResponse.getStatusLine().getStatusCode());
        respMap = asMap(iocResponse);

        // Evaluate response
        totalHits = (int) respMap.get(ListIOCsActionResponse.TOTAL_HITS_FIELD);
        assertEquals(iocs.size(), totalHits);

        iocHits = (List<Map<String, Object>>) respMap.get(ListIOCsActionResponse.HITS_FIELD);
        assertEquals(iocs.size(), iocHits.size());
        //         Retrieve all IOCs by ip types
        iocResponse = makeRequest(client(), "GET", STIX2IOCGenerator.getListIOCsURI(), Map.of(ListIOCsActionRequest.TYPE_FIELD, "ip,domain"), null);
        Assert.assertEquals(200, iocResponse.getStatusLine().getStatusCode());
        respMap = asMap(iocResponse);

        // Evaluate response
        totalHits = (int) respMap.get(ListIOCsActionResponse.TOTAL_HITS_FIELD);
        assertEquals(iocs.size(), totalHits);

        iocHits = (List<Map<String, Object>>) respMap.get(ListIOCsActionResponse.HITS_FIELD);
        assertEquals(iocs.size(), iocHits.size());
    }

}
