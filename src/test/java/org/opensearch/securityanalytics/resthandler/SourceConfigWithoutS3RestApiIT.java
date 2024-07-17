/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */

package org.opensearch.securityanalytics.resthandler;

import org.apache.http.entity.StringEntity;
import org.apache.http.message.BasicHeader;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.junit.Assert;
import org.opensearch.client.Response;
import org.opensearch.client.ResponseException;
import org.opensearch.core.rest.RestStatus;
import org.opensearch.search.SearchHit;
import org.opensearch.securityanalytics.SecurityAnalyticsPlugin;
import org.opensearch.securityanalytics.SecurityAnalyticsRestTestCase;
import org.opensearch.securityanalytics.action.ListIOCsActionRequest;
import org.opensearch.securityanalytics.action.ListIOCsActionResponse;
import org.opensearch.securityanalytics.commons.model.IOCType;
import org.opensearch.securityanalytics.model.STIX2IOCDto;
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
import static org.opensearch.securityanalytics.services.STIX2IOCFeedStore.IOC_ALL_INDEX_PATTERN;
import static org.opensearch.securityanalytics.services.STIX2IOCFeedStore.getAllIocIndexPatternById;

public class SourceConfigWithoutS3RestApiIT extends SecurityAnalyticsRestTestCase {
    private static final Logger log = LogManager.getLogger(SourceConfigWithoutS3RestApiIT.class);

    public void testCreateIocUploadSourceConfig() throws IOException {
        String feedName = "test_ioc_upload";
        String feedFormat = "STIX";
        SourceConfigType sourceConfigType = SourceConfigType.IOC_UPLOAD;

        List<STIX2IOCDto> iocs = List.of(new STIX2IOCDto(
                "id",
                "name",
                new IOCType(IOCType.IPV4_TYPE),
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
        List<String> iocTypes = List.of(IOCType.IPV4_TYPE);
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
                iocTypes, true
        );

        Response response = makeRequest(client(), "POST", SecurityAnalyticsPlugin.THREAT_INTEL_SOURCE_URI, Collections.emptyMap(), toHttpEntity(saTifSourceConfigDto));
        Assert.assertEquals(RestStatus.CREATED, restStatus(response));
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
        String indexName = getAllIocIndexPatternById(createdId);
        hits = executeSearch(indexName, request);
        Assert.assertEquals(iocs.size(), hits.size());

        // Retrieve all IOCs
        Response iocResponse = makeRequest(client(), "GET", STIX2IOCGenerator.getListIOCsURI(), Collections.emptyMap(), null);
        Assert.assertEquals(RestStatus.OK, restStatus(iocResponse));
        Map<String, Object> respMap = asMap(iocResponse);

        // Evaluate response
        int totalHits = (int) respMap.get(ListIOCsActionResponse.TOTAL_HITS_FIELD);
        assertTrue(iocs.size() < totalHits); //due to default feed leading to more iocs

        List<Map<String, Object>> iocHits = (List<Map<String, Object>>) respMap.get(ListIOCsActionResponse.HITS_FIELD);
        assertTrue(iocs.size() < iocHits.size());
        // Retrieve all IOCs by feed Ids
        iocResponse = makeRequest(client(), "GET", STIX2IOCGenerator.getListIOCsURI(), Map.of("feed_ids", createdId + ",random"), null);
        Assert.assertEquals(RestStatus.OK, restStatus(iocResponse));
        respMap = asMap(iocResponse);

        // Evaluate response
        totalHits = (int) respMap.get(ListIOCsActionResponse.TOTAL_HITS_FIELD);
        assertEquals(iocs.size(), totalHits);

        iocHits = (List<Map<String, Object>>) respMap.get(ListIOCsActionResponse.HITS_FIELD);
        assertEquals(iocs.size(), iocHits.size());
        //         Retrieve all IOCs by ip types
        Map<String, String> params = Map.of(
                ListIOCsActionRequest.TYPE_FIELD,
                String.format("%s,%s", IOCType.IPV4_TYPE, IOCType.DOMAIN_NAME_TYPE)
        );
        iocResponse = makeRequest(client(), "GET", STIX2IOCGenerator.getListIOCsURI(), params, null);
        Assert.assertEquals(RestStatus.OK, restStatus(iocResponse));
        respMap = asMap(iocResponse);

        // Evaluate response
        totalHits = (int) respMap.get(ListIOCsActionResponse.TOTAL_HITS_FIELD);
        assertTrue(iocs.size() < totalHits);

        iocHits = (List<Map<String, Object>>) respMap.get(ListIOCsActionResponse.HITS_FIELD);
        assertTrue(iocs.size() < iocHits.size());
    }

    public void testCreateIocUploadSourceConfigIncorrectIocTypes() throws IOException {
        // Attempt to create ioc upload source config with no correct ioc types
        String feedName = "test_ioc_upload";
        String feedFormat = "STIX";
        SourceConfigType sourceConfigType = SourceConfigType.IOC_UPLOAD;

        List<STIX2IOCDto> iocs = List.of(new STIX2IOCDto(
                "id",
                "name",
                new IOCType(IOCType.IPV4_TYPE),
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
        List<String> iocTypes = List.of(IOCType.DOMAIN_NAME_TYPE);
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
                iocTypes, true
        );

        try {
            makeRequest(client(), "POST", SecurityAnalyticsPlugin.THREAT_INTEL_SOURCE_URI, Collections.emptyMap(), toHttpEntity(saTifSourceConfigDto));
        } catch (ResponseException ex) {
            Assert.assertEquals(RestStatus.BAD_REQUEST, restStatus(ex.getResponse()));
        }
    }

    public void testUpdateIocUploadSourceConfig() throws IOException, InterruptedException {
        // Create source config with IPV4 IOCs
        String feedName = "test_update";
        String feedFormat = "STIX";
        SourceConfigType sourceConfigType = SourceConfigType.IOC_UPLOAD;

        List<STIX2IOCDto> iocs = List.of(new STIX2IOCDto(
                "1",
                "ioc",
                new IOCType(IOCType.IPV4_TYPE),
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
        List<String> iocTypes = List.of("ipv4-addr");
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
                iocTypes, true
        );

        // create source config with ipv4 ioc type
        Response response = makeRequest(client(), "POST", SecurityAnalyticsPlugin.THREAT_INTEL_SOURCE_URI, Collections.emptyMap(), toHttpEntity(saTifSourceConfigDto));
        Assert.assertEquals(RestStatus.CREATED, restStatus(response));
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
        String indexName = getAllIocIndexPatternById(createdId);
        hits = executeSearch(indexName, request);
        Assert.assertEquals(iocs.size(), hits.size());

        // Retrieve all IOCs by feed Ids
        Response iocResponse = makeRequest(client(), "GET", STIX2IOCGenerator.getListIOCsURI(), Map.of("feed_ids", createdId + ",random"), null);
        Assert.assertEquals(RestStatus.OK, restStatus(iocResponse));
        Map<String, Object> respMap = asMap(iocResponse);

        // Evaluate response
        int totalHits = (int) respMap.get(ListIOCsActionResponse.TOTAL_HITS_FIELD);
        assertEquals(iocs.size(), totalHits);

        List<Map<String, Object>> iocHits = (List<Map<String, Object>>) respMap.get(ListIOCsActionResponse.HITS_FIELD);
        assertEquals(iocs.size(), iocHits.size());

        // update source config to contain only hashes as an ioc type
        iocs = List.of(new STIX2IOCDto(
                        "2",
                        "ioc",
                        new IOCType(IOCType.HASHES_TYPE),
                        "value",
                        "severity",
                        null,
                        null,
                        "description",
                        List.of("labels"),
                        "specversion",
                        "feedId",
                        "feedName",
                        1L),
                new STIX2IOCDto(
                        "3",
                        "ioc",
                        new IOCType(IOCType.DOMAIN_NAME_TYPE),
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

        iocUploadSource = new IocUploadSource(null, iocs);
        iocTypes = List.of("hashes");
        saTifSourceConfigDto = new SATIFSourceConfigDto(
                saTifSourceConfigDto.getId(),
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
                iocTypes, true
        );

        // update source config with hashes ioc type
        response = makeRequest(client(), "PUT", SecurityAnalyticsPlugin.THREAT_INTEL_SOURCE_URI +"/" + createdId, Collections.emptyMap(), toHttpEntity(saTifSourceConfigDto));
        Assert.assertEquals(RestStatus.OK, restStatus(response));

        // Retrieve all IOCs by feed Ids
        iocResponse = makeRequest(client(), "GET", STIX2IOCGenerator.getListIOCsURI(), Map.of("feed_ids", createdId + ",random"), null);
        Assert.assertEquals(RestStatus.OK, restStatus(iocResponse));
        respMap = asMap(iocResponse);

        // Evaluate response - there should only be 1 ioc indexed according to the ioc type
        totalHits = (int) respMap.get(ListIOCsActionResponse.TOTAL_HITS_FIELD);
        assertEquals(1, totalHits);

        iocHits = (List<Map<String, Object>>) respMap.get(ListIOCsActionResponse.HITS_FIELD);
        assertEquals(1, iocHits.size());
        Thread.sleep(10000);
    }

    public void testDeleteIocUploadSourceConfigAndAllIocs() throws IOException {
        String feedName = "test_ioc_upload";
        String feedFormat = "STIX";
        SourceConfigType sourceConfigType = SourceConfigType.IOC_UPLOAD;

        List<STIX2IOCDto> iocs = List.of(new STIX2IOCDto(
                "id",
                "name",
                new IOCType(IOCType.IPV4_TYPE),
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
        List<String> iocTypes = List.of(IOCType.IPV4_TYPE);
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
                iocTypes, true
        );

        Response response = makeRequest(client(), "POST", SecurityAnalyticsPlugin.THREAT_INTEL_SOURCE_URI, Collections.emptyMap(), toHttpEntity(saTifSourceConfigDto));
        Assert.assertEquals(RestStatus.CREATED, restStatus(response));
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

        // Delete source config
        response = makeRequest(client(), "DELETE", SecurityAnalyticsPlugin.THREAT_INTEL_SOURCE_URI + "/" + createdId, Collections.emptyMap(), null);
        Assert.assertEquals(RestStatus.OK, restStatus(response));
        responseBody = asMap(response);

        String id = responseBody.get("_id").toString();
        assertEquals(id, createdId);

        // ensure all source configs are deleted
        hits = executeSearch(JOB_INDEX_NAME, request);
        Assert.assertEquals(0, hits.size());

        // ensure all iocs are deleted
        hits = executeSearch(IOC_ALL_INDEX_PATTERN, request);
        Assert.assertEquals(0, hits.size());
    }

    public void testRefreshIocUploadSourceConfigFailure() throws IOException {
        String feedName = "test_ioc_upload";
        String feedFormat = "STIX";
        SourceConfigType sourceConfigType = SourceConfigType.IOC_UPLOAD;

        List<STIX2IOCDto> iocs = List.of(new STIX2IOCDto(
                "id",
                "name",
                new IOCType(IOCType.IPV4_TYPE),
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
        List<String> iocTypes = List.of(IOCType.IPV4_TYPE);
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
                iocTypes, true
        );

        Response response = makeRequest(client(), "POST", SecurityAnalyticsPlugin.THREAT_INTEL_SOURCE_URI, Collections.emptyMap(), toHttpEntity(saTifSourceConfigDto));
        Assert.assertEquals(RestStatus.CREATED, restStatus(response));
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

        // Try to execute refresh api
        try {
            makeRequest(client(), "POST", SecurityAnalyticsPlugin.THREAT_INTEL_SOURCE_URI + "/" + createdId + "/_refresh", Collections.emptyMap(), null);
        } catch (ResponseException ex) {
            Assert.assertEquals(RestStatus.BAD_REQUEST, restStatus(ex.getResponse()));
        }
    }

    public void testSearchIocUploadSourceConfig() throws IOException {
        String feedName = "test_ioc_upload";
        String feedFormat = "STIX";
        SourceConfigType sourceConfigType = SourceConfigType.IOC_UPLOAD;

        List<STIX2IOCDto> iocs = List.of(new STIX2IOCDto(
                "id",
                "name",
                new IOCType(IOCType.IPV4_TYPE),
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
        List<String> iocTypes = List.of(IOCType.IPV4_TYPE);
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
                iocTypes, true
        );

        Response response = makeRequest(client(), "POST", SecurityAnalyticsPlugin.THREAT_INTEL_SOURCE_URI, Collections.emptyMap(), toHttpEntity(saTifSourceConfigDto));
        Assert.assertEquals(RestStatus.CREATED, restStatus(response));
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

        // Search all source configs
        Response sourceConfigResponse = makeRequest(client(), "POST", SecurityAnalyticsPlugin.THREAT_INTEL_SOURCE_URI + "/_search", Collections.emptyMap(), new StringEntity(request), new BasicHeader("Content-type", "application/json"));
        Assert.assertEquals(RestStatus.OK, restStatus(sourceConfigResponse));
        Map<String, Object> respMap = asMap(sourceConfigResponse);

        // Expected value is 2 - one ioc upload source config and one default source config
        Assert.assertEquals(2, ((Map<String, Object>) ((Map<String, Object>) respMap.get("hits")).get("total")).get("value"));
    }

}
