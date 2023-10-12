///*
// * Copyright OpenSearch Contributors
// * SPDX-License-Identifier: Apache-2.0
// *
// * The OpenSearch Contributors require contributions made to
// * this file be licensed under the Apache-2.0 license or a
// * compatible open source license.
// */
//package org.opensearch.securityanalytics.threatIntel;
//
//
//import org.apache.hc.core5.http.Header;
//import org.apache.hc.core5.http.HttpEntity;
//import org.apache.hc.core5.http.ContentType;
//import org.apache.hc.core5.http.io.entity.StringEntity;
//import org.junit.Assert;
//import org.opensearch.client.Request;
//import org.opensearch.client.RequestOptions;
//import org.opensearch.client.Response;
//import org.opensearch.client.RestClient;
//import org.opensearch.client.WarningsHandler;
//import org.opensearch.common.settings.Settings;
//import org.opensearch.common.xcontent.LoggingDeprecationHandler;
//import org.opensearch.core.xcontent.NamedXContentRegistry;
//import org.opensearch.common.xcontent.json.JsonXContent;
//import org.opensearch.jobscheduler.spi.schedule.IntervalSchedule;
//import org.opensearch.core.rest.RestStatus;
//import org.opensearch.securityanalytics.threatIntel.jobscheduler.TIFJobExtension;
//import org.opensearch.securityanalytics.threatIntel.jobscheduler.TIFJobParameter;
//import org.opensearch.test.rest.OpenSearchRestTestCase;
//
//import java.io.IOException;
//import java.time.Instant;
//import java.time.temporal.ChronoUnit;
//import java.util.Collections;
//import java.util.HashMap;
//import java.util.Locale;
//import java.util.List;
//import java.util.Map;
//import java.util.Timer;
//import java.util.TimerTask;
//
//public class TIFExtensionIntegTestCase extends OpenSearchRestTestCase {
//
//    protected TIFJobParameter createWatcherJob(String jobId, TIFJobParameter jobParameter) throws IOException {
//        return createWatcherJobWithClient(client(), jobId, jobParameter);
//    }
//
//    protected TIFJobParameter createWatcherJobWithClient(RestClient client, String jobId, TIFJobParameter jobParameter)
//            throws IOException {
//        Map<String, String> params = getJobParameterAsMap(jobId, jobParameter);
//        Response response = makeRequest(client, "POST", SampleExtensionRestHandler.WATCH_INDEX_URI, params, null);
//        Assert.assertEquals("Unable to create a watcher job", RestStatus.OK, RestStatus.fromCode(response.getStatusLine().getStatusCode()));
//
//        Map<String, Object> responseJson = JsonXContent.jsonXContent.createParser(
//                NamedXContentRegistry.EMPTY,
//                LoggingDeprecationHandler.INSTANCE,
//                response.getEntity().getContent()
//        ).map();
//        return getJobParameter(client, responseJson.get("_id").toString());
//    }
//
//    protected void deleteWatcherJob(String jobId) throws IOException {
//        deleteWatcherJobWithClient(client(), jobId);
//    }
//
//    protected void deleteWatcherJobWithClient(RestClient client, String jobId) throws IOException {
//        Response response = makeRequest(
//                client,
//                "DELETE",
//                SampleExtensionRestHandler.WATCH_INDEX_URI,
//                Collections.singletonMap("id", jobId),
//                null
//        );
//
//        Assert.assertEquals("Unable to delete a watcher job", RestStatus.OK, RestStatus.fromCode(response.getStatusLine().getStatusCode()));
//    }
//
//    protected Response makeRequest(
//            RestClient client,
//            String method,
//            String endpoint,
//            Map<String, String> params,
//            HttpEntity entity,
//            Header... headers
//    ) throws IOException {
//        Request request = new Request(method, endpoint);
//        RequestOptions.Builder options = RequestOptions.DEFAULT.toBuilder();
//        options.setWarningsHandler(WarningsHandler.PERMISSIVE);
//
//        for (Header header : headers) {
//            options.addHeader(header.getName(), header.getValue());
//        }
//        request.setOptions(options.build());
//        request.addParameters(params);
//        if (entity != null) {
//            request.setEntity(entity);
//        }
//        return client.performRequest(request);
//    }
//
//    protected Map<String, String> getJobParameterAsMap(String jobId, TIFJobParameter jobParameter) throws IOException {
//        Map<String, String> params = new HashMap<>();
//        params.put("id", jobId);
//        params.put("job_name", jobParameter.getName());
//        params.put("interval", String.valueOf(((IntervalSchedule) jobParameter.getSchedule()).getInterval()));
//        params.put("lock_duration_seconds", String.valueOf(jobParameter.getLockDurationSeconds()));
//        return params;
//    }
//
//    @SuppressWarnings("unchecked")
//    protected TIFJobParameter getJobParameter(RestClient client, String jobId) throws IOException {
//        Request request = new Request("POST", "/" + TIFJobExtension.JOB_INDEX_NAME + "/_search");
//        String entity = "{\n"
//                + "    \"query\": {\n"
//                + "        \"match\": {\n"
//                + "            \"_id\": {\n"
//                + "                \"query\": \""
//                + jobId
//                + "\"\n"
//                + "            }\n"
//                + "        }\n"
//                + "    }\n"
//                + "}";
//        request.setJsonEntity(entity);
//        Response response = client.performRequest(request);
//        Map<String, Object> responseJson = JsonXContent.jsonXContent.createParser(
//                NamedXContentRegistry.EMPTY,
//                LoggingDeprecationHandler.INSTANCE,
//                response.getEntity().getContent()
//        ).map();
//        Map<String, Object> hit = (Map<String, Object>) ((List<Object>) ((Map<String, Object>) responseJson.get("hits")).get("hits")).get(
//                0
//        );
//        Map<String, Object> jobSource = (Map<String, Object>) hit.get("_source");
//
//        TIFJobParameter jobParameter = new TIFJobParameter();
//        jobParameter.setName(jobSource.get("name").toString());
//
//        Map<String, Object> jobSchedule = (Map<String, Object>) jobSource.get("schedule");
//        jobParameter.setSchedule(
//                new IntervalSchedule(
//                        Instant.ofEpochMilli(Long.parseLong(((Map<String, Object>) jobSchedule.get("interval")).get("start_time").toString())),
//                        Integer.parseInt(((Map<String, Object>) jobSchedule.get("interval")).get("period").toString()),
//                        ChronoUnit.MINUTES
//                )
//        );
//        return jobParameter;
//    }
//
//    protected String createTestIndex() throws IOException {
//        String index = randomAlphaOfLength(10).toLowerCase(Locale.ROOT);
//        createTestIndex(index);
//        return index;
//    }
//
//    protected void createTestIndex(String index) throws IOException {
//        createIndex(index, Settings.builder().put("index.number_of_shards", 2).put("index.number_of_replicas", 0).build());
//    }
//
//    protected void deleteTestIndex(String index) throws IOException {
//        deleteIndex(index);
//    }
//
//    protected long countRecordsInTestIndex(String index) throws IOException {
//        String entity = "{\n" + "    \"query\": {\n" + "        \"match_all\": {\n" + "        }\n" + "    }\n" + "}";
//        Response response = makeRequest(
//                client(),
//                "POST",
//                "/" + index + "/_count",
//                Collections.emptyMap(),
//                new StringEntity(entity, ContentType.APPLICATION_JSON)
//        );
//        Map<String, Object> responseJson = JsonXContent.jsonXContent.createParser(
//                NamedXContentRegistry.EMPTY,
//                LoggingDeprecationHandler.INSTANCE,
//                response.getEntity().getContent()
//        ).map();
//        return Integer.parseInt(responseJson.get("count").toString());
//    }
//
//    protected void waitAndCreateWatcherJob(String prevIndex, String jobId, TIFJobParameter jobParameter) {
//        Timer timer = new Timer();
//        TimerTask timerTask = new TimerTask() {
//            private int timeoutCounter = 0;
//
//            @Override
//            public void run() {
//                try {
//                    long count = countRecordsInTestIndex(prevIndex);
//                    ++timeoutCounter;
//                    if (count == 1) {
//                        createWatcherJob(jobId, jobParameter);
//                        timer.cancel();
//                        timer.purge();
//                    }
//                    if (timeoutCounter >= 24) {
//                        timer.cancel();
//                        timer.purge();
//                    }
//                } catch (IOException ex) {
//                    // do nothing
//                    // suppress exception
//                }
//            }
//        };
//        timer.scheduleAtFixedRate(timerTask, 2000, 5000);
//    }
//
////    protected void waitAndDeleteWatcherJob(List<String> indices, String jobId) {
////        Timer timer = new Timer();
////        TimerTask timerTask = new TimerTask() {
////            private int timeoutCounter = 0;
////
////            @Override
////            public void run() {
////                try {
////                    long count = countRecordsInTestIndex(prevIndex);
////                    ++timeoutCounter;
////                    if (count == 1) {
////                        deleteWatcherJob(jobId);
////                        timer.cancel();
////                        timer.purge();
////                    }
////                    if (timeoutCounter >= 24) {
////                        timer.cancel();
////                        timer.purge();
////                    }
////                } catch (IOException ex) {
////                    // do nothing
////                    // suppress exception
////                }
////            }
////        };
////        timer.scheduleAtFixedRate(timerTask, 2000, 5000);
////    }
//}
