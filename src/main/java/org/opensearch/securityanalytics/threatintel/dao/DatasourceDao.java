package org.opensearch.securityanalytics.threatintel.dao;

import org.opensearch.action.DocWriteRequest;
import org.opensearch.action.get.GetRequest;
import org.opensearch.action.get.GetResponse;
import org.opensearch.action.index.IndexResponse;
import org.opensearch.action.support.WriteRequest;
import org.opensearch.client.Client;
import org.opensearch.cluster.service.ClusterService;
import org.opensearch.common.settings.ClusterSettings;
import org.opensearch.common.xcontent.LoggingDeprecationHandler;
import org.opensearch.common.xcontent.XContentFactory;
import org.opensearch.common.xcontent.XContentHelper;

import org.opensearch.core.xcontent.NamedXContentRegistry;
import org.opensearch.core.xcontent.ToXContent;
import org.opensearch.core.xcontent.XContentParser;
import org.opensearch.index.IndexNotFoundException;
import org.opensearch.securityanalytics.model.DetectorTrigger;
import org.opensearch.securityanalytics.threatintel.common.StashedThreadContext;
import org.opensearch.securityanalytics.threatintel.common.ThreatIntelSettings;
import org.opensearch.securityanalytics.threatintel.jobscheduler.DatasourceExtension;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.opensearch.securityanalytics.threatintel.jobscheduler.Datasource;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.stream.Collectors;

public class DatasourceDao {
    private static final Logger log = LogManager.getLogger(DetectorTrigger.class);

    private static final Integer MAX_SIZE = 1000;
    private final Client client;
    private final ClusterService clusterService;
    private final ClusterSettings clusterSettings;

    public DatasourceDao(final Client client, final ClusterService clusterService) {
        this.client = client;
        this.clusterService = clusterService;
        this.clusterSettings = clusterService.getClusterSettings();
    }

//    /**
//     * Create datasource index
//     *
//     * @param stepListener setup listener
//     */
//    public void createIndexIfNotExists(final StepListener<Void> stepListener) {
//        if (clusterService.state().metadata().hasIndex(DatasourceExtension.JOB_INDEX_NAME) == true) {
//            stepListener.onResponse(null);
//            return;
//        }
//        final CreateIndexRequest createIndexRequest = new CreateIndexRequest(DatasourceExtension.JOB_INDEX_NAME).mapping(getIndexMapping())
//                .settings(DatasourceExtension.INDEX_SETTING);
//
//        StashedThreadContext.run(client, () -> client.admin().indices().create(createIndexRequest, new ActionListener<>() {
//            @Override
//            public void onResponse(final CreateIndexResponse createIndexResponse) {
//                stepListener.onResponse(null);
//            }
//
//            @Override
//            public void onFailure(final Exception e) {
//                if (e instanceof ResourceAlreadyExistsException) {
//                    log.info("index[{}] already exist", DatasourceExtension.JOB_INDEX_NAME);
//                    stepListener.onResponse(null);
//                    return;
//                }
//                stepListener.onFailure(e);
//            }
//        }));
//    }

    private String getIndexMapping() {
        try {
            try (InputStream is = DatasourceDao.class.getResourceAsStream("/mappings/threatintel_datasource.json")) {
                try (BufferedReader reader = new BufferedReader(new InputStreamReader(is, StandardCharsets.UTF_8))) {
                    return reader.lines().map(String::trim).collect(Collectors.joining());
                }
            }
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    /**
     * Get datasource from an index {@code DatasourceExtension.JOB_INDEX_NAME}
     * @param name the name of a datasource
     * @return datasource
     * @throws IOException exception
     */
    public Datasource getDatasource(final String name) throws IOException {
        GetRequest request = new GetRequest(DatasourceExtension.JOB_INDEX_NAME, name);
        GetResponse response;
        try {
            response = StashedThreadContext.run(client, () -> client.get(request).actionGet(clusterSettings.get(ThreatIntelSettings.TIMEOUT)));
            if (response.isExists() == false) {
                log.error("Datasource[{}] does not exist in an index[{}]", name, DatasourceExtension.JOB_INDEX_NAME);
                return null;
            }
        } catch (IndexNotFoundException e) {
            log.error("Index[{}] is not found", DatasourceExtension.JOB_INDEX_NAME);
            return null;
        }

        XContentParser parser = XContentHelper.createParser(
                NamedXContentRegistry.EMPTY,
                LoggingDeprecationHandler.INSTANCE,
                response.getSourceAsBytesRef()
        );
        return Datasource.PARSER.parse(parser, null);
    }

    /**
     * Update datasource in an index {@code DatasourceExtension.JOB_INDEX_NAME}
     * @param datasource the datasource
     * @return index response
     */
    public IndexResponse updateDatasource(final Datasource datasource) {
        datasource.setLastUpdateTime(Instant.now());
        return StashedThreadContext.run(client, () -> {
            try {
                return client.prepareIndex(DatasourceExtension.JOB_INDEX_NAME)
                        .setId(datasource.getName())
                        .setOpType(DocWriteRequest.OpType.INDEX)
                        .setRefreshPolicy(WriteRequest.RefreshPolicy.IMMEDIATE)
                        .setSource(datasource.toXContent(XContentFactory.jsonBuilder(), ToXContent.EMPTY_PARAMS))
                        .execute()
                        .actionGet(clusterSettings.get(ThreatIntelSettings.TIMEOUT));
            } catch (IOException e) {
                throw new RuntimeException(e);
            }
        });
    }

}
