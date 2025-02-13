/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */

package org.opensearch.securityanalytics.resthandler;

import org.junit.Assert;
import org.opensearch.client.Response;
import org.opensearch.core.rest.RestStatus;
import org.opensearch.securityanalytics.SecurityAnalyticsPlugin;
import org.opensearch.securityanalytics.SecurityAnalyticsRestTestCase;
import org.opensearch.securityanalytics.commons.model.IOCType;
import org.opensearch.securityanalytics.model.DetailedSTIX2IOCDto;
import org.opensearch.securityanalytics.model.STIX2IOC;
import org.opensearch.securityanalytics.threatIntel.action.ListIOCsActionResponse;
import org.opensearch.securityanalytics.threatIntel.common.SourceConfigType;
import org.opensearch.securityanalytics.threatIntel.model.CustomSchemaIocUploadSource;
import org.opensearch.securityanalytics.threatIntel.model.JsonPathIocSchema;
import org.opensearch.securityanalytics.threatIntel.model.JsonPathSchemaField;
import org.opensearch.securityanalytics.threatIntel.model.SATIFSourceConfigDto;
import org.opensearch.securityanalytics.util.STIX2IOCGenerator;

import java.io.IOException;
import java.util.Collections;
import java.util.List;
import java.util.Locale;
import java.util.Map;

public class CustomSchemaSourceConfigIocUploadIT extends SecurityAnalyticsRestTestCase {
    /* Test scenarios
     * 1. Valid schemas with all fields present
     * 2. Valid schemas with optional fields absent
     * 4. Valid schemas but not communicating correct format
     * 5. Valid schemas but mandatory fields missing in iocs string
     * 6. Invalid schema json path in schema
     * 7. Invalid Json in Iocs
     * 8 Schema invalid because mandatory paths not passed*/
    public void testCustomSchemaIocUploadWithSingleton_success() throws IOException {
        String feedName = "test_ioc_upload";
        String feedFormat = "STIX";
        SourceConfigType sourceConfigType = SourceConfigType.IOC_UPLOAD;



        CustomSchemaIocUploadSource iocUploadSource = new CustomSchemaIocUploadSource(null,
                "{\"value\": \"value1\", \"type\":\"" + IOCType.IPV4_TYPE + "\", \"name\" : \"name\", \"id\":\"1\"}");
        Boolean enabled = false;
        List<String> iocTypes = List.of(IOCType.IPV4_TYPE);
        SATIFSourceConfigDto saTifSourceConfigDto = getSaTifSourceConfigDto(feedName, feedFormat, sourceConfigType, iocUploadSource, enabled, iocTypes, new JsonPathIocSchema(null,
                null,
                new JsonPathSchemaField("$.type"),
                new JsonPathSchemaField("$.value"),
                null,
                null,
                null,
                null,
                null,
                null));

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

        // Retrieve all IOCs by feed Ids
        Response iocResponse = makeRequest(client(), "GET", STIX2IOCGenerator.getListIOCsURI(), Map.of("feed_ids", createdId + ",random"), null);
        Assert.assertEquals(RestStatus.OK, restStatus(iocResponse));
        Map<String, Object> respMap = asMap(iocResponse);

        // Evaluate response
        int totalHits = (int) respMap.get(ListIOCsActionResponse.TOTAL_HITS_FIELD);
        assertEquals(1, totalHits);

    }

    public void testCustomSchemaIocUploadWithSingleIocTypeStringAndSingleIocValueArray_Success() throws IOException {
        String feedName = "test_ioc_upload";
        String feedFormat = "STIX";
        SourceConfigType sourceConfigType = SourceConfigType.IOC_UPLOAD;

        CustomSchemaIocUploadSource iocUploadSource = new CustomSchemaIocUploadSource(null,
                "{\"value\": [\"value1\", \"value2\"], \"type\":\"" + IOCType.IPV4_TYPE + "\", \"name\" : \"name\", \"id\":\"1\"}");
        Boolean enabled = false;
        List<String> iocTypes = List.of(IOCType.IPV4_TYPE);
        SATIFSourceConfigDto saTifSourceConfigDto = getSaTifSourceConfigDto(feedName, feedFormat, sourceConfigType, iocUploadSource, enabled, iocTypes, new JsonPathIocSchema(null,
                null,
                new JsonPathSchemaField("$.type"),
                new JsonPathSchemaField("$.value"),
                null,
                null,
                null,
                null,
                null,
                null));

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

        // Retrieve all IOCs by feed Ids
        Response iocResponse = makeRequest(client(), "GET", STIX2IOCGenerator.getListIOCsURI(), Map.of("feed_ids", createdId + ",random"), null);
        Assert.assertEquals(RestStatus.OK, restStatus(iocResponse));
        Map<String, Object> respMap = asMap(iocResponse);

        // Evaluate response
        int totalHits = (int) respMap.get(ListIOCsActionResponse.TOTAL_HITS_FIELD);
        assertEquals(2, totalHits);

    }

    public void testCustomSchemaIocUploadWithMissingIocTypeStringAndSingleIocValue_Failure() throws IOException {
        String feedName = "test_ioc_upload";
        String feedFormat = "STIX";
        SourceConfigType sourceConfigType = SourceConfigType.IOC_UPLOAD;



        CustomSchemaIocUploadSource iocUploadSource = new CustomSchemaIocUploadSource(null,
                "{\"value\": [\"value1\", \"value2\"], \"name\" : \"name\", \"id\":\"1\"}");
        Boolean enabled = false;
        List<String> iocTypes = List.of(IOCType.IPV4_TYPE);
        SATIFSourceConfigDto saTifSourceConfigDto = getSaTifSourceConfigDto(feedName, feedFormat, sourceConfigType, iocUploadSource, enabled, iocTypes, new JsonPathIocSchema(null,
                null,
                new JsonPathSchemaField("$.type"),
                new JsonPathSchemaField("$.value"),
                null,
                null,
                null,
                null,
                null,
                null));

        try {
            Response response = makeRequest(client(), "POST", SecurityAnalyticsPlugin.THREAT_INTEL_SOURCE_URI, Collections.emptyMap(), toHttpEntity(saTifSourceConfigDto));
            fail();
        } catch (Exception e) {
            System.out.println(e);
        }


    }

    public void testCustomSchemaIocUploadWithInvalidJson_Failure() throws IOException {
        String feedName = "test_ioc_upload";
        String feedFormat = "STIX";
        SourceConfigType sourceConfigType = SourceConfigType.IOC_UPLOAD;
        CustomSchemaIocUploadSource iocUploadSource = new CustomSchemaIocUploadSource(null,
                "{\"value\": [\"value1\", \"value2\"], \"name\" : \"name\", \"id\":\"1\"");
        Boolean enabled = false;
        List<String> iocTypes = List.of(IOCType.IPV4_TYPE);
        SATIFSourceConfigDto saTifSourceConfigDto = getSaTifSourceConfigDto(feedName, feedFormat, sourceConfigType, iocUploadSource, enabled, iocTypes, new JsonPathIocSchema(null,
                null,
                new JsonPathSchemaField("$.type"),
                new JsonPathSchemaField("$.value"),
                null,
                null,
                null,
                null,
                null,
                null));

        try {
            Response response = makeRequest(client(), "POST", SecurityAnalyticsPlugin.THREAT_INTEL_SOURCE_URI, Collections.emptyMap(), toHttpEntity(saTifSourceConfigDto));
            fail();
        } catch (Exception e) {
            System.out.println(e);
        }


    }

    public void testCustomSchemaIocUploadWithMissingIocValueStringAndSingleIocType_Failure() throws IOException {
        String feedName = "test_ioc_upload";
        String feedFormat = "STIX";
        SourceConfigType sourceConfigType = SourceConfigType.IOC_UPLOAD;



        CustomSchemaIocUploadSource iocUploadSource = new CustomSchemaIocUploadSource(null,
                "{\"type\": \"ipv4-addr\", \"name\" : \"name\", \"id\":\"1\"}");
        Boolean enabled = false;
        List<String> iocTypes = List.of(IOCType.IPV4_TYPE);
        SATIFSourceConfigDto saTifSourceConfigDto = getSaTifSourceConfigDto(feedName, feedFormat, sourceConfigType, iocUploadSource, enabled, iocTypes, new JsonPathIocSchema(null,
                null,
                new JsonPathSchemaField("$.type"),
                new JsonPathSchemaField("$.value"),
                null,
                null,
                null,
                null,
                null,
                null));

        try {
            Response response = makeRequest(client(), "POST", SecurityAnalyticsPlugin.THREAT_INTEL_SOURCE_URI, Collections.emptyMap(), toHttpEntity(saTifSourceConfigDto));
            fail();
        } catch (Exception e) {
            System.out.println(e);
        }


    }

    public void testCustomSchemaIocUploadWithMultiptleTuplesOfIocTypeValue_PartialNulls_success() throws IOException {
        String feedName = "test_ioc_upload";
        String feedFormat = "STIX";
        SourceConfigType sourceConfigType = SourceConfigType.IOC_UPLOAD;

        String jsonString = "{\"iocs\":[{\"ipath\":\"" + IOCType.IPV4_TYPE + "\"},{\"ivalue\":\"10.0.0.1\",\"ipath\":\"" + IOCType.IPV4_TYPE + "\"},{\"ivalue\":\"malware.com\",\"ipath\":\"" + IOCType.DOMAIN_NAME_TYPE + "\"}]}";

        CustomSchemaIocUploadSource iocUploadSource = new CustomSchemaIocUploadSource(null,
                    jsonString);
        Boolean enabled = false;
        List<String> iocTypes = List.of(IOCType.IPV4_TYPE, IOCType.DOMAIN_NAME_TYPE);
        SATIFSourceConfigDto saTifSourceConfigDto = getSaTifSourceConfigDto(feedName, feedFormat, sourceConfigType, iocUploadSource, enabled, iocTypes, new JsonPathIocSchema(null,
                null,
                new JsonPathSchemaField("$..ipath"),
                new JsonPathSchemaField("$..ivalue"),
                null,
                null,
                null,
                null,
                null,
                null));

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

        // Retrieve all IOCs by feed Ids
        Response iocResponse = makeRequest(client(), "GET", STIX2IOCGenerator.getListIOCsURI(), Map.of("feed_ids", createdId + ",random"), null);
        Assert.assertEquals(RestStatus.OK, restStatus(iocResponse));
        Map<String, Object> respMap = asMap(iocResponse);

        // Evaluate response
        int totalHits = (int) respMap.get(ListIOCsActionResponse.TOTAL_HITS_FIELD);
        assertEquals(2, totalHits);

    }

    public void testCustomSchemaIocUploadWithMultiptleTuplesOfIocTypeValue_InvalidIocTypes_success() throws IOException {
        String feedName = "test_ioc_upload";
        String feedFormat = "STIX";
        SourceConfigType sourceConfigType = SourceConfigType.IOC_UPLOAD;

        String jsonString = "{\"iocs\":[{\"ipath\":\"" + IOCType.IPV4_TYPE+"invalid" + "\"},{\"ivalue\":[\"10.0.0.1\", \"10.0.0.2\"],\"ipath\":\"" + IOCType.IPV4_TYPE + "\"},{\"ivalue\":\"malware.com\",\"ipath\":\"" + IOCType.DOMAIN_NAME_TYPE + "\"}]}";

        CustomSchemaIocUploadSource iocUploadSource = new CustomSchemaIocUploadSource(null,
                jsonString);
        Boolean enabled = false;
        List<String> iocTypes = List.of(IOCType.IPV4_TYPE, IOCType.DOMAIN_NAME_TYPE);
        SATIFSourceConfigDto saTifSourceConfigDto = getSaTifSourceConfigDto(feedName, feedFormat, sourceConfigType, iocUploadSource, enabled, iocTypes, new JsonPathIocSchema(null,
                null,
                new JsonPathSchemaField("$..ipath"),
                new JsonPathSchemaField("$..ivalue"),
                null,
                null,
                null,
                null,
                null,
                null));

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

        // Retrieve all IOCs by feed Ids
        Response iocResponse = makeRequest(client(), "GET", STIX2IOCGenerator.getListIOCsURI(), Map.of("feed_ids", createdId + ",random"), null);
        Assert.assertEquals(RestStatus.OK, restStatus(iocResponse));
        Map<String, Object> respMap = asMap(iocResponse);

        // Evaluate response
        int totalHits = (int) respMap.get(ListIOCsActionResponse.TOTAL_HITS_FIELD);
        assertEquals(3, totalHits);

    }

    public void testCustomSchemaIocUploadWithLegalJsonPathForTypeButPointingToJson() {
        String feedName = "test_ioc_upload";
        String feedFormat = "STIX";
        SourceConfigType sourceConfigType = SourceConfigType.IOC_UPLOAD;
        String ip1 = "10.0.0.1", ip2= "10.0.0.2";
        List<String> ips = List.of(ip1, ip2);
        String name1 = "malicious10xips", name2 = "malwaredomain";
        List<String> names = List.of(name1, name2);
        String type1= IOCType.IPV4_TYPE+"random", type2= IOCType.DOMAIN_NAME_TYPE;
        List<String> types= List.of(type1, type2);
        String domain1 = "malware.com";
        List<String> ids = List.of("id1");

        String jsonString = "{\"iocs\":[{\"ipath\":\"" + IOCType.IPV4_TYPE+"invalid"+ String.format("\"},{\"FOO\":\"%s\",\"NAME\":\"%s\",\"ivalue\":[\"%s\", \"%s\"],\"ipath\":\"", ids.get(0),name1, ip1, ip2) + type1 + String.format("\"},{\"NAME\":\"%s\",\"ivalue\":\"%s\",\"ipath\":\"", name2, domain1) + type2 + "\"}]}";

        CustomSchemaIocUploadSource iocUploadSource = new CustomSchemaIocUploadSource(null,
                jsonString);
        Boolean enabled = false;
        List<String> iocTypes = List.of(IOCType.IPV4_TYPE, IOCType.DOMAIN_NAME_TYPE);
        SATIFSourceConfigDto saTifSourceConfigDto = getSaTifSourceConfigDto(feedName, feedFormat, sourceConfigType, iocUploadSource, enabled, iocTypes,
                new JsonPathIocSchema(
                new JsonPathSchemaField("$..FOO"),
                new JsonPathSchemaField("$..NAME"),
                new JsonPathSchemaField("$.*"),
                new JsonPathSchemaField("$..ivalue"),
                null,
                null,
                null,
                null,
                null,
                null));

        try {
            Response response = makeRequest(client(), "POST", SecurityAnalyticsPlugin.THREAT_INTEL_SOURCE_URI, Collections.emptyMap(), toHttpEntity(saTifSourceConfigDto));
            fail();
        } catch (Exception e) {
            assertTrue(e.getMessage().contains("Failed to parse threat intel ioc JSON"));
        }

    }

    public void testCustomSchemaIocUploadWithLegalJsonPathForValueButPointingToJson() {
        String feedName = "test_ioc_upload";
        String feedFormat = "STIX";
        SourceConfigType sourceConfigType = SourceConfigType.IOC_UPLOAD;
        String ip1 = "10.0.0.1", ip2= "10.0.0.2";
        List<String> ips = List.of(ip1, ip2);
        String name1 = "malicious10xips", name2 = "malwaredomain";
        List<String> names = List.of(name1, name2);
        String type1= IOCType.IPV4_TYPE+"random", type2= IOCType.DOMAIN_NAME_TYPE;
        List<String> types= List.of(type1, type2);
        String domain1 = "malware.com";
        List<String> ids = List.of("id1");

        String jsonString = "{\"iocs\":[{\"ipath\":\"" + IOCType.IPV4_TYPE+"invalid"+ String.format("\"},{\"FOO\":\"%s\",\"NAME\":\"%s\",\"ivalue\":[\"%s\", \"%s\"],\"ipath\":\"", ids.get(0),name1, ip1, ip2) + type1 + String.format("\"},{\"NAME\":\"%s\",\"ivalue\":\"%s\",\"ipath\":\"", name2, domain1) + type2 + "\"}]}";

        CustomSchemaIocUploadSource iocUploadSource = new CustomSchemaIocUploadSource(null,
                jsonString);
        Boolean enabled = false;
        List<String> iocTypes = List.of(IOCType.IPV4_TYPE, IOCType.DOMAIN_NAME_TYPE);
        SATIFSourceConfigDto saTifSourceConfigDto = getSaTifSourceConfigDto(feedName, feedFormat, sourceConfigType, iocUploadSource, enabled, iocTypes,
                new JsonPathIocSchema(
                        new JsonPathSchemaField("$..FOO"),
                        new JsonPathSchemaField("$..NAME"),
                        new JsonPathSchemaField("$..ipath"),
                        new JsonPathSchemaField("$.*"),
                        null,
                        null,
                        null,
                        null,
                        null,
                        null));

        try {
            Response response = makeRequest(client(), "POST", SecurityAnalyticsPlugin.THREAT_INTEL_SOURCE_URI, Collections.emptyMap(), toHttpEntity(saTifSourceConfigDto));
            fail();
        } catch (Exception e) {
            assertTrue(e.getMessage().contains("Failed to parse threat intel ioc JSON"));
        }

    }

    public void testCustomSchemaIocUploadWithMultipleTuplesOfIocTypeValue_MixOfValueArrayAndStrings_success() throws IOException {
        String feedName = "test_ioc_upload";
        String feedFormat = "STIX";
        SourceConfigType sourceConfigType = SourceConfigType.IOC_UPLOAD;
        String ip1 = "10.0.0.1", ip2= "10.0.0.2";
        List<String> ips = List.of(ip1, ip2);
        String name1 = "malicious10xips", name2 = "malwaredomain";
        List<String> names = List.of(name1, name2);
        String type1= IOCType.IPV4_TYPE+"random", type2= IOCType.DOMAIN_NAME_TYPE;
        List<String> types= List.of(type1, type2);
        String domain1 = "malware.com";
        List<String> ids = List.of("id1");

        String jsonString = "{\"iocs\":[{\"ipath\":\"" + IOCType.IPV4_TYPE+"invalid"+ String.format("\"},{\"FOO\":\"%s\",\"NAME\":\"%s\",\"ivalue\":[\"%s\", \"%s\"],\"ipath\":\"", ids.get(0),name1, ip1, ip2) + type1 + String.format("\"},{\"NAME\":\"%s\",\"ivalue\":\"%s\",\"ipath\":\"", name2, domain1) + type2 + "\"}]}";

        CustomSchemaIocUploadSource iocUploadSource = new CustomSchemaIocUploadSource(null,
                jsonString);
        Boolean enabled = false;
        List<String> iocTypes = List.of(IOCType.IPV4_TYPE, IOCType.DOMAIN_NAME_TYPE);
        SATIFSourceConfigDto saTifSourceConfigDto = getSaTifSourceConfigDto(feedName, feedFormat, sourceConfigType, iocUploadSource, enabled, iocTypes,
                new JsonPathIocSchema(
                        new JsonPathSchemaField("$..FOO"),
                        new JsonPathSchemaField("$..NAME"),
                        new JsonPathSchemaField("$..ipath"),
                        new JsonPathSchemaField("$..ivalue"),
                        null,
                        null,
                        null,
                        null,
                        null,
                        null));

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

        // Retrieve all IOCs by feed Ids
        Response iocResponse = makeRequest(client(), "GET", STIX2IOCGenerator.getListIOCsURI(), Map.of("feed_ids", createdId + ",random"), null);
        Assert.assertEquals(RestStatus.OK, restStatus(iocResponse));
        Map<String, Object> respMap = asMap(iocResponse);

        // Evaluate response
        int totalHits = (int) respMap.get(ListIOCsActionResponse.TOTAL_HITS_FIELD);
        assertEquals(3, totalHits);
        List<Map<String, Object>> iocHits = (List<Map<String, Object>>) respMap.get(ListIOCsActionResponse.HITS_FIELD);

        boolean idFound = false;
        for (Map<String, Object> hit : iocHits) {
            String iocId = (String) hit.get(STIX2IOC.ID_FIELD);
            String iocName = (String) hit.get(STIX2IOC.NAME_FIELD);
            String iocValue = (String) hit.get(STIX2IOC.VALUE_FIELD);
            String iocType = (String) hit.get(STIX2IOC.TYPE_FIELD);
            assertTrue(names.contains(iocName));
            assertTrue(types.contains(iocType));
            if (iocId.equals(ids.get(0))) idFound = true;
            if (iocType.equals(IOCType.DOMAIN_NAME_TYPE)) {
                assertEquals(domain1, iocValue);
            } else {
                assertTrue(ips.contains(iocValue));
            }


            int findingsNum = (int) hit.get(DetailedSTIX2IOCDto.NUM_FINDINGS_FIELD);
            int expectedNumFindings = 0;
            assertEquals(expectedNumFindings, findingsNum);
        }
        assertTrue(idFound);

    }

    public void testCustomSchemaIocUpload1() throws IOException {
        String feedName = "test_ioc_upload";
        String feedFormat = "STIX";
        SourceConfigType sourceConfigType = SourceConfigType.IOC_UPLOAD;
        String filePath = "threatIntel/custom_schema_ioc/custom_schema_1.json";
        String jsonString = readResource(filePath);

        CustomSchemaIocUploadSource iocUploadSource = new CustomSchemaIocUploadSource(null,
                jsonString);
        Boolean enabled = false;
        List<String> iocTypes = List.of(IOCType.IPV4_TYPE, IOCType.DOMAIN_NAME_TYPE);
        SATIFSourceConfigDto saTifSourceConfigDto = getSaTifSourceConfigDto(feedName, feedFormat, sourceConfigType, iocUploadSource, enabled, iocTypes, new JsonPathIocSchema(null,
                null,
                new JsonPathSchemaField("$.*[*].ioc_type"),
                new JsonPathSchemaField("$.*[*].ioc_value"),
                null,
                null,
                null,
                null,
                null,
                null));

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

        // Retrieve all IOCs by feed Ids
        Response iocResponse = makeRequest(client(), "GET", STIX2IOCGenerator.getListIOCsURI(), Map.of("feed_ids", createdId), null);
        Assert.assertEquals(RestStatus.OK, restStatus(iocResponse));
        Map<String, Object> respMap = asMap(iocResponse);

        // Evaluate response
        int totalHits = (int) respMap.get(ListIOCsActionResponse.TOTAL_HITS_FIELD);
        assertEquals(312, totalHits);

    }

    private static SATIFSourceConfigDto getSaTifSourceConfigDto(String feedName, String feedFormat, SourceConfigType sourceConfigType, CustomSchemaIocUploadSource iocUploadSource, Boolean enabled, List<String> iocTypes, JsonPathIocSchema iocSchema) {
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
                iocSchema
        );
    }


    @Override
    protected boolean preserveIndicesUponCompletion() {
        return false;
    }
}
