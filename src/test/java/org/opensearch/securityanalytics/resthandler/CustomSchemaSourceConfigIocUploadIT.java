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
import org.opensearch.securityanalytics.threatIntel.action.ListIOCsActionResponse;
import org.opensearch.securityanalytics.threatIntel.common.SourceConfigType;
import org.opensearch.securityanalytics.threatIntel.model.CustomSchemaIocUploadSource;
import org.opensearch.securityanalytics.threatIntel.model.JsonPathIocSchema;
import org.opensearch.securityanalytics.threatIntel.model.JsonPathIocSchema.JsonPathSchemaField;
import org.opensearch.securityanalytics.threatIntel.model.SATIFSourceConfigDto;
import org.opensearch.securityanalytics.util.STIX2IOCGenerator;

import java.io.IOException;
import java.util.Collections;
import java.util.List;
import java.util.Locale;
import java.util.Map;

public class CustomSchemaSourceConfigIocUploadIT extends SecurityAnalyticsRestTestCase {
    /* Test scenarios
     * 1. Valid schemas with isKey false and all fields present
     * 2. Valid schemas with isKey false and optional fields absent
     *    i.   Valid schemas with isKey false
     *    ii.  Valid schema with key : value tuple (1:1)
     *    iii. Valid schema with key : value nested (1:n)
     * 3. Valid schemas with isKey true
     * 4. Valid schemas but not communicating correct format
     * 5. Valid schemas but mandatory fields missing in iocs string
     * 6. Invalid schema json path in schema
     * 7. Invalid Json in Iocs
     * 8 Schema invalid because mandatory paths not passed*/
    public void testCustomSchemaIocUploadWithSingleton_success() throws IOException {
        String feedName = "test_ioc_upload";
        String feedFormat = "STIX";
        SourceConfigType sourceConfigType = SourceConfigType.CUSTOM_SCHEMA_IOC_UPLOAD;



        CustomSchemaIocUploadSource iocUploadSource = new CustomSchemaIocUploadSource(null,
                "{\"value\": \"value1\", \"type\":\"" + IOCType.IPV4_TYPE + "\", \"name\" : \"name\", \"id\":\"1\"}");
        Boolean enabled = false;
        List<String> iocTypes = List.of(IOCType.IPV4_TYPE);
        SATIFSourceConfigDto saTifSourceConfigDto = getSaTifSourceConfigDto(feedName, feedFormat, sourceConfigType, iocUploadSource, enabled, iocTypes, new JsonPathIocSchema(null,
                null,
                new JsonPathSchemaField("$.type", false),
                new JsonPathSchemaField("$.value", false),
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
        SourceConfigType sourceConfigType = SourceConfigType.CUSTOM_SCHEMA_IOC_UPLOAD;

        CustomSchemaIocUploadSource iocUploadSource = new CustomSchemaIocUploadSource(null,
                "{\"value\": [\"value1\", \"value2\"], \"type\":\"" + IOCType.IPV4_TYPE + "\", \"name\" : \"name\", \"id\":\"1\"}");
        Boolean enabled = false;
        List<String> iocTypes = List.of(IOCType.IPV4_TYPE);
        SATIFSourceConfigDto saTifSourceConfigDto = getSaTifSourceConfigDto(feedName, feedFormat, sourceConfigType, iocUploadSource, enabled, iocTypes, new JsonPathIocSchema(null,
                null,
                new JsonPathSchemaField("$.type", false),
                new JsonPathSchemaField("$.value", false),
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
        SourceConfigType sourceConfigType = SourceConfigType.CUSTOM_SCHEMA_IOC_UPLOAD;



        CustomSchemaIocUploadSource iocUploadSource = new CustomSchemaIocUploadSource(null,
                "{\"value\": [\"value1\", \"value2\"], \"name\" : \"name\", \"id\":\"1\"}");
        Boolean enabled = false;
        List<String> iocTypes = List.of(IOCType.IPV4_TYPE);
        SATIFSourceConfigDto saTifSourceConfigDto = getSaTifSourceConfigDto(feedName, feedFormat, sourceConfigType, iocUploadSource, enabled, iocTypes, new JsonPathIocSchema(null,
                null,
                new JsonPathSchemaField("$.type", false),
                new JsonPathSchemaField("$.value", false),
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
        SourceConfigType sourceConfigType = SourceConfigType.CUSTOM_SCHEMA_IOC_UPLOAD;
        CustomSchemaIocUploadSource iocUploadSource = new CustomSchemaIocUploadSource(null,
                "{\"value\": [\"value1\", \"value2\"], \"name\" : \"name\", \"id\":\"1\"");
        Boolean enabled = false;
        List<String> iocTypes = List.of(IOCType.IPV4_TYPE);
        SATIFSourceConfigDto saTifSourceConfigDto = getSaTifSourceConfigDto(feedName, feedFormat, sourceConfigType, iocUploadSource, enabled, iocTypes, new JsonPathIocSchema(null,
                null,
                new JsonPathSchemaField("$.type", false),
                new JsonPathSchemaField("$.value", false),
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
        SourceConfigType sourceConfigType = SourceConfigType.CUSTOM_SCHEMA_IOC_UPLOAD;



        CustomSchemaIocUploadSource iocUploadSource = new CustomSchemaIocUploadSource(null,
                "{\"type\": \"ipv4-addr\", \"name\" : \"name\", \"id\":\"1\"}");
        Boolean enabled = false;
        List<String> iocTypes = List.of(IOCType.IPV4_TYPE);
        SATIFSourceConfigDto saTifSourceConfigDto = getSaTifSourceConfigDto(feedName, feedFormat, sourceConfigType, iocUploadSource, enabled, iocTypes, new JsonPathIocSchema(null,
                null,
                new JsonPathSchemaField("$.type", false),
                new JsonPathSchemaField("$.value", false),
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
        SourceConfigType sourceConfigType = SourceConfigType.CUSTOM_SCHEMA_IOC_UPLOAD;

        String jsonString = "{\"iocs\":[{\"ipath\":\"" + IOCType.IPV4_TYPE + "\"},{\"ivalue\":\"10.0.0.1\",\"ipath\":\"" + IOCType.IPV4_TYPE + "\"},{\"ivalue\":\"malware.com\",\"ipath\":\"" + IOCType.DOMAIN_NAME_TYPE + "\"}]}";

        CustomSchemaIocUploadSource iocUploadSource = new CustomSchemaIocUploadSource(null,
                    jsonString);
        Boolean enabled = false;
        List<String> iocTypes = List.of(IOCType.IPV4_TYPE, IOCType.DOMAIN_NAME_TYPE);
        SATIFSourceConfigDto saTifSourceConfigDto = getSaTifSourceConfigDto(feedName, feedFormat, sourceConfigType, iocUploadSource, enabled, iocTypes, new JsonPathIocSchema(null,
                null,
                new JsonPathSchemaField("$..ipath", false),
                new JsonPathSchemaField("$..ivalue", false),
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
        SourceConfigType sourceConfigType = SourceConfigType.CUSTOM_SCHEMA_IOC_UPLOAD;

        String jsonString = "{\"iocs\":[{\"ipath\":\"" + IOCType.IPV4_TYPE+"invalid" + "\"},{\"ivalue\":[\"10.0.0.1\", \"10.0.0.2\"],\"ipath\":\"" + IOCType.IPV4_TYPE + "\"},{\"ivalue\":\"malware.com\",\"ipath\":\"" + IOCType.DOMAIN_NAME_TYPE + "\"}]}";

        CustomSchemaIocUploadSource iocUploadSource = new CustomSchemaIocUploadSource(null,
                jsonString);
        Boolean enabled = false;
        List<String> iocTypes = List.of(IOCType.IPV4_TYPE, IOCType.DOMAIN_NAME_TYPE);
        SATIFSourceConfigDto saTifSourceConfigDto = getSaTifSourceConfigDto(feedName, feedFormat, sourceConfigType, iocUploadSource, enabled, iocTypes, new JsonPathIocSchema(null,
                null,
                new JsonPathSchemaField("$..ipath", false),
                new JsonPathSchemaField("$..ivalue", false),
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

    public void testCustomSchemaIocUploadWithMultiptleTuplesOfIocTypeValue_MixOfValueArrayAndStrings_success() throws IOException {
        String feedName = "test_ioc_upload";
        String feedFormat = "STIX";
        SourceConfigType sourceConfigType = SourceConfigType.CUSTOM_SCHEMA_IOC_UPLOAD;

        String jsonString = "{\"iocs\":[{\"ipath\":\"" + IOCType.IPV4_TYPE+"invalid" + "\"},{\"ivalue\":[\"10.0.0.1\", \"10.0.0.2\"],\"ipath\":\"" + IOCType.IPV4_TYPE + "\"},{\"ivalue\":\"malware.com\",\"ipath\":\"" + IOCType.DOMAIN_NAME_TYPE + "\"}]}";

        CustomSchemaIocUploadSource iocUploadSource = new CustomSchemaIocUploadSource(null,
                jsonString);
        Boolean enabled = false;
        List<String> iocTypes = List.of(IOCType.IPV4_TYPE, IOCType.DOMAIN_NAME_TYPE);
        SATIFSourceConfigDto saTifSourceConfigDto = getSaTifSourceConfigDto(feedName, feedFormat, sourceConfigType, iocUploadSource, enabled, iocTypes, new JsonPathIocSchema(null,
                null,
                new JsonPathSchemaField("$..ipath", false),
                new JsonPathSchemaField("$..ivalue", false),
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

    public void testCustomSchemaIocUpload1() throws IOException {
        String feedName = "test_ioc_upload";
        String feedFormat = "STIX";
        SourceConfigType sourceConfigType = SourceConfigType.CUSTOM_SCHEMA_IOC_UPLOAD;
        String filePath = "threatIntel/custom_schema_ioc/custom_schema_1.json";
        String jsonString = readResource(filePath);

        CustomSchemaIocUploadSource iocUploadSource = new CustomSchemaIocUploadSource(null,
                jsonString);
        Boolean enabled = false;
        List<String> iocTypes = List.of(IOCType.IPV4_TYPE, IOCType.DOMAIN_NAME_TYPE);
        SATIFSourceConfigDto saTifSourceConfigDto = getSaTifSourceConfigDto(feedName, feedFormat, sourceConfigType, iocUploadSource, enabled, iocTypes, new JsonPathIocSchema(null,
                null,
                new JsonPathSchemaField("$.*[*].ioc_type", false),
                new JsonPathSchemaField("$.*[*].ioc_value", false),
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
