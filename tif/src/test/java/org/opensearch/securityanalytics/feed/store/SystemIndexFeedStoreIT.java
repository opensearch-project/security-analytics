package org.opensearch.securityanalytics.feed.store;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.apache.http.HttpHost;
import org.apache.http.auth.AuthScope;
import org.apache.http.auth.UsernamePasswordCredentials;
import org.apache.http.client.CredentialsProvider;
import org.apache.http.impl.client.BasicCredentialsProvider;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.opensearch.action.admin.indices.refresh.RefreshRequest;
import org.opensearch.action.get.GetRequest;
import org.opensearch.action.get.GetResponse;
import org.opensearch.action.search.SearchRequest;
import org.opensearch.action.search.SearchResponse;
import org.opensearch.client.RequestOptions;
import org.opensearch.client.RestClient;
import org.opensearch.client.RestClientBuilder;
import org.opensearch.client.RestHighLevelClient;
import org.opensearch.index.query.QueryBuilders;
import org.opensearch.search.SearchHit;
import org.opensearch.search.builder.SearchSourceBuilder;
import org.opensearch.securityanalytics.connector.util.STIX2Generator;
import org.opensearch.securityanalytics.feed.store.model.UpdateType;
import org.opensearch.securityanalytics.index.IndexAccessor;
import org.opensearch.securityanalytics.index.RHLCIndexAccessor;
import org.opensearch.securityanalytics.model.IOC;
import org.opensearch.securityanalytics.model.STIX2;
import org.opensearch.securityanalytics.util.ResourceReader;

import java.io.IOException;
import java.util.Arrays;
import java.util.List;
import java.util.Random;
import java.util.Set;
import java.util.UUID;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.opensearch.securityanalytics.index.IndexAccessor.ROLLOVER_INDEX_FORMAT;

public class SystemIndexFeedStoreIT {
    private static final int NUMBER_OF_IOCS = new Random().nextInt(99) + 1;
    private static final String FEED_ID = UUID.randomUUID().toString();
    private static final ObjectMapper OBJECT_MAPPER = new ObjectMapper();

    private RestHighLevelClient client;
    private IndexAccessor indexAccessor;
    private SystemIndexFeedStore systemIndexFeedStore;
    private STIX2Generator stix2Generator;

    @BeforeEach
    public void setup() {
        final String userName = System.getProperty("tests.opensearch.user");
        final String password = System.getProperty("tests.opensearch.password");
        final String host = System.getProperty("tests.opensearch.host");

        final CredentialsProvider credentialsProvider = new BasicCredentialsProvider();
        final UsernamePasswordCredentials credentials = new UsernamePasswordCredentials(userName, password);
        credentialsProvider.setCredentials(AuthScope.ANY, credentials);

        final RestClientBuilder restClientBuilder = RestClient.builder(new HttpHost(host, 9200, "http"))
                .setHttpClientConfigCallback(httpClientBuilder -> httpClientBuilder.setDefaultCredentialsProvider(credentialsProvider));
        client = new RestHighLevelClient(restClientBuilder);

        indexAccessor = new RHLCIndexAccessor(client, new ResourceReader(), OBJECT_MAPPER);
        systemIndexFeedStore = new SystemIndexFeedStore(indexAccessor);
        stix2Generator = new STIX2Generator();

        deleteAlias();
    }

    @AfterEach
    public void tearDown() {
        //deleteAlias();
    }

//    @ParameterizedTest
//    @MethodSource("getUpdateTypes")
//    public void testStoreIOCs_Success(final UpdateType updateType) throws IOException {
//        final List<IOC> iocs = stix2Generator.generateSTIX2(NUMBER_OF_IOCS, FEED_ID);
//        systemIndexFeedStore.storeIOCs(iocs, updateType);
//
//        validateIOCs(iocs);
//    }

    @Test
    public void testStoreIOCs_ReplaceUpdateTypeDeletesOriginalIOCs() throws IOException {
        // Load initial IOCs
        final List<IOC> iocs = stix2Generator.generateSTIX2(NUMBER_OF_IOCS, FEED_ID);
        systemIndexFeedStore.storeIOCs(iocs, UpdateType.REPLACE);
        validateIOCs(iocs);

        // Load replacement IOCs
        final List<IOC> replacementIOCs = stix2Generator.generateSTIX2(12, FEED_ID);
        systemIndexFeedStore.storeIOCs(replacementIOCs, UpdateType.REPLACE);
        validateIOCs(replacementIOCs);
    }

//    @Test
//    public void testStoreIOCs_DeltaUpdateTypeReplacesOriginalIOC() throws IOException {
//        // Load initial IOCs
//        final List<IOC> iocs = stix2Generator.generateSTIX2(NUMBER_OF_IOCS, FEED_ID);
//        systemIndexFeedStore.storeIOCs(iocs, UpdateType.DELTA);
//        validateIOCs(iocs);
//
//        final STIX2 originalIOC = (STIX2) iocs.get(0);
//        final STIX2 indexedIOC = getIOCById(originalIOC.getFeedId(), originalIOC.getId());
//        assertEquals(originalIOC.getType(), indexedIOC.getType());
//
//        // Load replacement IOC and validate original IOCs still present
//        final STIX2 updatedIOC = (STIX2) iocs.get(0);
//        final String updatedType = UUID.randomUUID().toString();
//        updatedIOC.setType(updatedType);
//        final List<IOC> replacementIOCs = List.of(updatedIOC);
//        systemIndexFeedStore.storeIOCs(replacementIOCs, UpdateType.DELTA);
//        validateIOCs(iocs);
//
//        final STIX2 replacedIOC = getIOCById(updatedIOC.getFeedId(), updatedIOC.getId());
//        assertEquals(updatedType, replacedIOC.getType());
//        assertNotEquals(indexedIOC.getType(), replacedIOC.getType());
//    }

    private static Stream<Arguments> getUpdateTypes() {
        return Arrays.stream(UpdateType.values())
                .map(Arguments::of);
    }

    private void validateIOCs(final List<IOC> iocs) throws IOException {
        refreshIndex();
        final SearchResponse searchResponse = searchIndex();
        assertEquals(iocs.size(), searchResponse.getHits().getHits().length);

        final Set<String> actualDocIds = Arrays.stream(searchResponse.getHits().getHits())
                .map(SearchHit::getId)
                .collect(Collectors.toSet());
        final Set<String> expectedDocIds = iocs.stream()
                .map(ioc -> String.format(SystemIndexFeedStore.IOC_DOC_ID_FORMAT, ioc.getFeedId(), ioc.getId()))
                .collect(Collectors.toSet());

        assertEquals(expectedDocIds, actualDocIds);
        iocs.forEach(ioc -> assertEquals(FEED_ID, ioc.getFeedId()));
    }

    private void deleteAlias() {
        indexAccessor.deleteRolloverAlias(SystemIndexFeedStore.ALIAS_NAME);
    }

    private void refreshIndex() throws IOException {
        final RefreshRequest refreshRequest = new RefreshRequest();
        refreshRequest.indices(SystemIndexFeedStore.ALIAS_NAME);
        client.indices().refresh(refreshRequest, RequestOptions.DEFAULT);
    }

    private SearchResponse searchIndex() throws IOException {
        final SearchSourceBuilder searchSourceBuilder = new SearchSourceBuilder();
        searchSourceBuilder.query(QueryBuilders.matchAllQuery());
        searchSourceBuilder.size(10000);

        final SearchRequest searchRequest = new SearchRequest();
        searchRequest.indices(SystemIndexFeedStore.ALIAS_NAME);
        searchRequest.source(searchSourceBuilder);

        return client.search(searchRequest, RequestOptions.DEFAULT);
    }

    private STIX2 getIOCById(final String feedId, final String id) throws IOException {
        final String docId = String.format(SystemIndexFeedStore.IOC_DOC_ID_FORMAT, feedId, id);
        final GetRequest getRequest = new GetRequest(SystemIndexFeedStore.ALIAS_NAME, docId);
        final GetResponse getResponse = client.get(getRequest, RequestOptions.DEFAULT);

        return OBJECT_MAPPER.readValue(getResponse.getSourceAsBytes(), STIX2.class);
    }
}
