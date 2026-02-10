/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */

package org.opensearch.securityanalytics.resthandler;

import org.apache.hc.core5.http.io.entity.StringEntity;
import org.apache.hc.core5.http.message.BasicHeader;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.junit.Assert;
import org.opensearch.client.Response;
import org.opensearch.client.ResponseException;
import org.opensearch.client.WarningFailureException;
import org.opensearch.common.settings.Settings;
import org.opensearch.core.rest.RestStatus;
import org.opensearch.jobscheduler.spi.schedule.IntervalSchedule;
import org.opensearch.search.SearchHit;
import org.opensearch.securityanalytics.SecurityAnalyticsPlugin;
import org.opensearch.securityanalytics.SecurityAnalyticsRestTestCase;
import org.opensearch.securityanalytics.threatIntel.action.ListIOCsActionRequest;
import org.opensearch.securityanalytics.threatIntel.action.ListIOCsActionResponse;
import org.opensearch.securityanalytics.commons.model.IOCType;
import org.opensearch.securityanalytics.model.STIX2IOCDto;
import org.opensearch.securityanalytics.threatIntel.common.SourceConfigType;
import org.opensearch.securityanalytics.threatIntel.model.IocUploadSource;
import org.opensearch.securityanalytics.threatIntel.model.SATIFSourceConfigDto;
import org.opensearch.securityanalytics.threatIntel.model.UrlDownloadSource;
import org.opensearch.securityanalytics.util.STIX2IOCGenerator;

import java.io.IOException;
import java.net.URL;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;

import static org.opensearch.securityanalytics.SecurityAnalyticsPlugin.JOB_INDEX_NAME;
import static org.opensearch.securityanalytics.TestHelpers.oldThreatIntelJobMapping;
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
                IOCType.IPV4_TYPE,
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
                iocTypes, true,
                null
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
                IOCType.IPV4_TYPE,
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
                iocTypes, true,
                null
        );

        try {
            makeRequest(client(), "POST", SecurityAnalyticsPlugin.THREAT_INTEL_SOURCE_URI, Collections.emptyMap(), toHttpEntity(saTifSourceConfigDto));
        } catch (ResponseException ex) {
            Assert.assertEquals(RestStatus.BAD_REQUEST, restStatus(ex.getResponse()));
        }
    }

    public void testUpdateIocUploadSourceConfig() throws IOException {
        // Create source config with IPV4 IOCs
        String feedName = "test_update";
        String feedFormat = "STIX";
        SourceConfigType sourceConfigType = SourceConfigType.IOC_UPLOAD;

        List<STIX2IOCDto> iocs = List.of(new STIX2IOCDto(
                "1",
                "ioc",
                IOCType.IPV4_TYPE,
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
                iocTypes, true,
                null
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
                        IOCType.HASHES_TYPE,
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
                        IOCType.DOMAIN_NAME_TYPE,
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
                iocTypes, true,
                null
        );

        // update source config with hashes ioc type
        response = makeRequest(client(), "PUT", SecurityAnalyticsPlugin.THREAT_INTEL_SOURCE_URI +"/" + createdId, Collections.emptyMap(), toHttpEntity(saTifSourceConfigDto));
        Assert.assertEquals(RestStatus.OK, restStatus(response));

        // Ensure that old ioc indices are retained (2 created from ioc upload source config + 1 from default source config)
        List<String> findingIndices = getIocIndices();
        Assert.assertEquals(3, findingIndices.size());

        // Retrieve all IOCs by feed Ids
        iocResponse = makeRequest(client(), "GET", STIX2IOCGenerator.getListIOCsURI(), Map.of("feed_ids", createdId + ",random"), null);
        Assert.assertEquals(RestStatus.OK, restStatus(iocResponse));
        respMap = asMap(iocResponse);

        // Evaluate response - there should only be 1 ioc indexed according to the ioc type
        totalHits = (int) respMap.get(ListIOCsActionResponse.TOTAL_HITS_FIELD);
        assertEquals(2, totalHits);

        iocHits = (List<Map<String, Object>>) respMap.get(ListIOCsActionResponse.HITS_FIELD);
        assertEquals(2, iocHits.size());
    }

    public void testActivateDeactivateIocUploadSourceConfig() throws IOException {
        // Create source config with IPV4 IOCs
        String feedName = "test_update";
        String feedFormat = "STIX";
        SourceConfigType sourceConfigType = SourceConfigType.IOC_UPLOAD;

        List<STIX2IOCDto> iocs = List.of(new STIX2IOCDto(
                "1",
                "ioc",
                IOCType.IPV4_TYPE,
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
                iocTypes, true,
                null
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
        iocs = Collections.emptyList();

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
                iocTypes, false,
                null
        );

        // update source config with hashes ioc type
        response = makeRequest(client(), "PUT", SecurityAnalyticsPlugin.THREAT_INTEL_SOURCE_URI +"/" + createdId, Collections.emptyMap(), toHttpEntity(saTifSourceConfigDto));
        Assert.assertEquals(RestStatus.OK, restStatus(response));
        Map<String, Object> updateResponseAsMap = asMap(response);
        assertNotNull(updateResponseAsMap);
        assertTrue(updateResponseAsMap.containsKey("source_config"));
        HashMap<String, Object> scr = (HashMap<String, Object>) updateResponseAsMap.get("source_config");
        assertTrue(scr.containsKey("enabled"));
        assertFalse((Boolean) scr.get("enabled"));
        assertTrue(scr.containsKey("enabled_for_scan"));
        assertFalse((Boolean) scr.get("enabled_for_scan"));

        // Ensure that old ioc indices are retained (2 created from ioc upload source config + 1 from default source config)
        List<String> findingIndices = getIocIndices();
        Assert.assertEquals(2, findingIndices.size());

        // Retrieve all IOCs by feed Ids
        iocResponse = makeRequest(client(), "GET", STIX2IOCGenerator.getListIOCsURI(), Map.of("feed_ids", createdId + ",random"), null);
        Assert.assertEquals(RestStatus.OK, restStatus(iocResponse));
        respMap = asMap(iocResponse);

        // Evaluate response - there should only be 1 ioc indexed according to the ioc type
        totalHits = (int) respMap.get(ListIOCsActionResponse.TOTAL_HITS_FIELD);
        assertEquals(1, totalHits);

        iocHits = (List<Map<String, Object>>) respMap.get(ListIOCsActionResponse.HITS_FIELD);
        assertEquals(1, iocHits.size());

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
                iocTypes, true,
                null
        );

        // update source config with hashes ioc type
        response = makeRequest(client(), "PUT", SecurityAnalyticsPlugin.THREAT_INTEL_SOURCE_URI +"/" + createdId, Collections.emptyMap(), toHttpEntity(saTifSourceConfigDto));
        Assert.assertEquals(RestStatus.OK, restStatus(response));
        updateResponseAsMap = asMap(response);
        assertNotNull(updateResponseAsMap);
        assertTrue(updateResponseAsMap.containsKey("source_config"));
        scr = (HashMap<String, Object>) updateResponseAsMap.get("source_config");
        assertTrue(scr.containsKey("enabled"));
        assertFalse((Boolean) scr.get("enabled")); // since its not url_download type, this flag should remain unaffected by the activate action in update source api
        assertTrue(scr.containsKey("enabled_for_scan"));
        assertTrue((Boolean) scr.get("enabled_for_scan"));
    }

    public void testActivateDeactivateUrlDownloadSourceConfig() throws IOException {
        // Search source configs when none are created
        String request = "{\n" +
                "   \"query\" : {\n" +
                "     \"match_all\":{\n" +
                "     }\n" +
                "   }\n" +
                "}";

        // Search all source configs
        Response sourceConfigResponse = makeRequest(client(), "POST", SecurityAnalyticsPlugin.THREAT_INTEL_SOURCE_URI + "/_search", Collections.emptyMap(), new StringEntity(request), new BasicHeader("Content-type", "application/json"));
        Assert.assertEquals(RestStatus.OK, restStatus(sourceConfigResponse));
        Map<String, Object> responseBody = asMap(sourceConfigResponse);

        // Expected value is 1 - only default source config
        Assert.assertEquals(1, ((Map<String, Object>) ((Map<String, Object>) responseBody.get("hits")).get("total")).get("value"));

        // Update default source config
        String feedName = "test_update_default";
        String feedFormat = "STIX";
        SourceConfigType sourceConfigType = SourceConfigType.URL_DOWNLOAD;
        UrlDownloadSource urlDownloadSource = new UrlDownloadSource(new URL("https://reputation.alienvault.com/reputation.generic"), "csv", false,0);
        Boolean enabled = false;
        List<String> iocTypes = List.of("ipv4-addr");
        IntervalSchedule schedule = new IntervalSchedule(Instant.now(), 1, ChronoUnit.DAYS);
        String id = "alienvault_reputation_ip_database";
        SATIFSourceConfigDto saTifSourceConfigDto = new SATIFSourceConfigDto(
                id,
                null,
                feedName,
                feedFormat,
                sourceConfigType,
                null,
                null,
                null,
                urlDownloadSource,
                null,
                null,
                schedule,
                null,
                null,
                null,
                null,
                enabled,
                iocTypes, false,
                null
        );

        // update default source config with enabled_for_scan updated
        Response response = makeRequest(client(), "PUT", SecurityAnalyticsPlugin.THREAT_INTEL_SOURCE_URI +"/" + id, Collections.emptyMap(), toHttpEntity(saTifSourceConfigDto));
        Assert.assertEquals(RestStatus.OK, restStatus(response));
        Map<String, Object> updateResponseAsMap = asMap(response);
        assertNotNull(updateResponseAsMap);
        assertTrue(updateResponseAsMap.containsKey("source_config"));
        HashMap<String, Object> scr = (HashMap<String, Object>) updateResponseAsMap.get("source_config");
        assertTrue(scr.containsKey("enabled"));
        assertFalse((Boolean) scr.get("enabled"));
        assertTrue(scr.containsKey("enabled_for_scan"));
        assertFalse((Boolean) scr.get("enabled_for_scan"));

        // Ensure that only 1 ioc index is present from default source
        List<String> findingIndices = getIocIndices();
        Assert.assertEquals(1, findingIndices.size());

        // try to update default source config again to ensure operation is not accepted when enabled_for_scan is unchanged
        try {
            makeRequest(client(), "PUT", SecurityAnalyticsPlugin.THREAT_INTEL_SOURCE_URI +"/" + id, Collections.emptyMap(), toHttpEntity(saTifSourceConfigDto));
        } catch (Exception e) {
            Assert.assertTrue(e.getMessage().contains("unsupported_operation_exception"));
        }
        // activate source
        saTifSourceConfigDto = new SATIFSourceConfigDto(
                id,
                null,
                feedName,
                feedFormat,
                sourceConfigType,
                null,
                null,
                null,
                urlDownloadSource,
                null,
                null,
                schedule,
                null,
                null,
                null,
                null,
                enabled,
                iocTypes, true,
                null
        );

        // update default source config with enabled_for_scan updated
        response = makeRequest(client(), "PUT", SecurityAnalyticsPlugin.THREAT_INTEL_SOURCE_URI +"/" + id, Collections.emptyMap(), toHttpEntity(saTifSourceConfigDto));
        Assert.assertEquals(RestStatus.OK, restStatus(response));
        updateResponseAsMap = asMap(response);
        assertNotNull(updateResponseAsMap);
        assertTrue(updateResponseAsMap.containsKey("source_config"));
        scr = (HashMap<String, Object>) updateResponseAsMap.get("source_config");
        assertTrue(scr.containsKey("enabled"));
        assertTrue((Boolean) scr.get("enabled"));
        assertTrue(scr.containsKey("enabled_for_scan"));
        assertTrue((Boolean) scr.get("enabled_for_scan"));
    }

    public void testDeleteIocUploadSourceConfigAndAllIocs() throws IOException {
        String feedName = "test_ioc_upload";
        String feedFormat = "STIX";
        SourceConfigType sourceConfigType = SourceConfigType.IOC_UPLOAD;

        List<STIX2IOCDto> iocs = List.of(new STIX2IOCDto(
                "id",
                "name",
                IOCType.IPV4_TYPE,
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
                iocTypes, true,
                null
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
                IOCType.IPV4_TYPE,
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
                iocTypes, true,
                null
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
                IOCType.IPV4_TYPE,
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
                iocTypes, true,
                null
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

    public void testSearchAndCreateDefaultSourceConfig() throws IOException {
        // Search source configs when none are created
        String request = "{\n" +
                "   \"query\" : {\n" +
                "     \"match_all\":{\n" +
                "     }\n" +
                "   }\n" +
                "}";

        // Search all source configs
        Response sourceConfigResponse = makeRequest(client(), "POST", SecurityAnalyticsPlugin.THREAT_INTEL_SOURCE_URI + "/_search", Collections.emptyMap(), new StringEntity(request), new BasicHeader("Content-type", "application/json"));
        Assert.assertEquals(RestStatus.OK, restStatus(sourceConfigResponse));
        Map<String, Object> responseBody = asMap(sourceConfigResponse);

        // Expected value is 1 - only default source config
        Assert.assertEquals(1, ((Map<String, Object>) ((Map<String, Object>) responseBody.get("hits")).get("total")).get("value"));
    }

    public void testUpdateDefaultSourceConfigThrowsError() throws IOException {
        // Search source configs when none are created
        String request = "{\n" +
                "   \"query\" : {\n" +
                "     \"match_all\":{\n" +
                "     }\n" +
                "   }\n" +
                "}";

        // Search all source configs
        Response sourceConfigResponse = makeRequest(client(), "POST", SecurityAnalyticsPlugin.THREAT_INTEL_SOURCE_URI + "/_search", Collections.emptyMap(), new StringEntity(request), new BasicHeader("Content-type", "application/json"));
        Assert.assertEquals(RestStatus.OK, restStatus(sourceConfigResponse));
        Map<String, Object> responseBody = asMap(sourceConfigResponse);

        // Expected value is 1 - only default source config
        Assert.assertEquals(1, ((Map<String, Object>) ((Map<String, Object>) responseBody.get("hits")).get("total")).get("value"));

        // Update default source config
        String feedName = "test_update_default";
        String feedFormat = "STIX";
        SourceConfigType sourceConfigType = SourceConfigType.URL_DOWNLOAD;
        UrlDownloadSource urlDownloadSource = new UrlDownloadSource(new URL("https://reputation.alienvault.com/reputation.generic"), "csv", false,0);
        Boolean enabled = false;
        List<String> iocTypes = List.of("ipv4-addr");
        IntervalSchedule schedule = new IntervalSchedule(Instant.now(), 1, ChronoUnit.DAYS);
        String id = "alienvault_reputation_ip_database";
        SATIFSourceConfigDto saTifSourceConfigDto = new SATIFSourceConfigDto(
                id,
                null,
                feedName,
                feedFormat,
                sourceConfigType,
                null,
                null,
                null,
                urlDownloadSource,
                null,
                null,
                schedule,
                null,
                null,
                null,
                null,
                enabled,
                iocTypes, true,
                null
        );

        // update default source config
        try {
            makeRequest(client(), "PUT", SecurityAnalyticsPlugin.THREAT_INTEL_SOURCE_URI +"/" + id, Collections.emptyMap(), toHttpEntity(saTifSourceConfigDto));
        } catch (Exception e) {
            Assert.assertTrue(e.getMessage().contains("unsupported_operation_exception"));
        }

        // update default source config again to ensure lock was released
        try {
            makeRequest(client(), "PUT", SecurityAnalyticsPlugin.THREAT_INTEL_SOURCE_URI +"/" + id, Collections.emptyMap(), toHttpEntity(saTifSourceConfigDto));
        } catch (Exception e) {
            Assert.assertTrue(e.getMessage().contains("unsupported_operation_exception"));
        }
    }

    public void testUpdateJobIndexMapping() throws IOException {
        // Create job index with old threat intel mapping
        // Try catch needed because of warning when creating a system index which is needed to replicate previous tif job mapping
        try {
            createIndex(JOB_INDEX_NAME, Settings.EMPTY, oldThreatIntelJobMapping());
        } catch (WarningFailureException e) {
            // Ensure index was created with old mappings
            String request = "{\n" +
                    "   \"query\" : {\n" +
                    "     \"match_all\":{\n" +
                    "     }\n" +
                    "   }\n" +
                    "}";
            List<SearchHit> hits = executeSearch(JOB_INDEX_NAME, request);
            Assert.assertEquals(0, hits.size());

            Map<String, Object> props = getIndexMappingsAPIFlat(JOB_INDEX_NAME);
            assertTrue(props.containsKey("enabled_time"));
            assertTrue(props.containsKey("schedule.interval.start_time"));
            assertFalse(props.containsKey("source_config.source.ioc_upload.file_name"));
            assertFalse(props.containsKey("source_config.source.s3.object_key"));
        }

        // Create new threat intel source config
        SATIFSourceConfigDto saTifSourceConfigDto = getSatifSourceConfigDto();

        Response makeResponse = makeRequest(client(), "POST", SecurityAnalyticsPlugin.THREAT_INTEL_SOURCE_URI, Collections.emptyMap(), toHttpEntity(saTifSourceConfigDto));
        Assert.assertEquals(RestStatus.CREATED, restStatus(makeResponse));
        Map<String, Object> responseBody = asMap(makeResponse);

        String createdId = responseBody.get("_id").toString();
        Assert.assertNotEquals("response is missing Id", SATIFSourceConfigDto.NO_ID, createdId);

        int createdVersion = Integer.parseInt(responseBody.get("_version").toString());
        Assert.assertTrue("incorrect version", createdVersion > 0);

        // Ensure source config document was indexed
        String request = "{\n" +
                "   \"query\" : {\n" +
                "     \"match_all\":{\n" +
                "     }\n" +
                "   }\n" +
                "}";
        List<SearchHit> hits = executeSearch(JOB_INDEX_NAME, request);
        Assert.assertEquals(1, hits.size());

        // Ensure index mappings were updated
        Map<String, Object> props = getIndexMappingsAPIFlat(JOB_INDEX_NAME);
        assertTrue(props.containsKey("source_config.source.ioc_upload.file_name"));
        assertTrue(props.containsKey("source_config.source.s3.object_key"));
        assertTrue(props.containsKey("source_config.description"));
        assertTrue(props.containsKey("source_config.last_update_time"));
        assertTrue(props.containsKey("source_config.refresh_type"));
    }

    private static SATIFSourceConfigDto getSatifSourceConfigDto() {
        String feedName = "test_ioc_upload";
        String feedFormat = "STIX";
        SourceConfigType sourceConfigType = SourceConfigType.IOC_UPLOAD;

        List<STIX2IOCDto> iocs = List.of(new STIX2IOCDto(
                "id",
                "name",
                IOCType.IPV4_TYPE,
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
        return new SATIFSourceConfigDto(
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
                iocTypes, true,
                null
        );
    }
}
