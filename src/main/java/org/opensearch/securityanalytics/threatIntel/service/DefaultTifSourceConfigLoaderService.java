package org.opensearch.securityanalytics.threatIntel.service;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.opensearch.action.search.SearchResponse;
import org.opensearch.action.support.GroupedActionListener;
import org.opensearch.client.Client;
import org.opensearch.core.action.ActionListener;
import org.opensearch.index.query.BoolQueryBuilder;
import org.opensearch.index.query.MatchQueryBuilder;
import org.opensearch.index.query.QueryBuilders;
import org.opensearch.jobscheduler.spi.schedule.IntervalSchedule;
import org.opensearch.rest.RestRequest;
import org.opensearch.search.SearchHit;
import org.opensearch.search.builder.SearchSourceBuilder;
import org.opensearch.securityanalytics.commons.model.IOCType;
import org.opensearch.securityanalytics.threatIntel.common.RefreshType;
import org.opensearch.securityanalytics.threatIntel.common.SourceConfigType;
import org.opensearch.securityanalytics.threatIntel.common.TIFJobState;
import org.opensearch.securityanalytics.threatIntel.feedMetadata.BuiltInTIFMetadataLoader;
import org.opensearch.securityanalytics.threatIntel.model.SATIFSourceConfigDto;
import org.opensearch.securityanalytics.threatIntel.model.TIFMetadata;
import org.opensearch.securityanalytics.threatIntel.model.UrlDownloadSource;

import java.net.URL;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Collection;
import java.util.List;
import java.util.Map;
import java.util.function.Function;
import java.util.stream.Collectors;

//todo handle refresh, update tif config
// todo block creation of url based config in transport layer
public class DefaultTifSourceConfigLoaderService {
    private static final Logger log = LogManager.getLogger(DefaultTifSourceConfigLoaderService.class);
    private final BuiltInTIFMetadataLoader tifMetadataLoader;
    private final Client client;
    private final SATIFSourceConfigManagementService satifSourceConfigManagementService;

    public DefaultTifSourceConfigLoaderService(BuiltInTIFMetadataLoader tifMetadataLoader, Client client, SATIFSourceConfigManagementService satifSourceConfigManagementService) {
        this.tifMetadataLoader = tifMetadataLoader;
        this.client = client;
        this.satifSourceConfigManagementService = satifSourceConfigManagementService;
    }

    /**
     * check if the default tif source configs are loaded. if not, try create them from the feedMetadata.json file.
     */
    public void createDefaultTifConfigsIfNotExists(ActionListener<Void> listener) {
        List<TIFMetadata> tifMetadataList = tifMetadataLoader.getTifMetadataList();
        if (tifMetadataList.isEmpty()) {
            log.error("No built-in TIF Configs found");
            listener.onResponse(null);
            return;
        }
        BoolQueryBuilder boolQueryBuilder = QueryBuilders.boolQuery();
        for (TIFMetadata tifMetadata : tifMetadataList) {
            boolQueryBuilder.should(new MatchQueryBuilder("_id", tifMetadata.getFeedId()));
        }
        SearchSourceBuilder searchSourceBuilder = new SearchSourceBuilder().query(boolQueryBuilder).size(9999);
        satifSourceConfigManagementService.searchTIFSourceConfigs(searchSourceBuilder,
                ActionListener.wrap(searchResponse -> {
                    createTifConfigsThatDontExist(searchResponse, tifMetadataList, listener);
                }, e -> {
                    log.error("Failed to search tif config index for default tif configs", e);
                    listener.onFailure(e);
                }));
    }

    private void createTifConfigsThatDontExist(SearchResponse searchResponse, List<TIFMetadata> tifMetadataList, ActionListener<Void> listener) {
        Map<String, TIFMetadata> feedsToCreate = tifMetadataList.stream()
                .collect(Collectors.toMap(
                        TIFMetadata::getFeedId,
                        Function.identity()
                ));
        if (searchResponse.getHits() != null && searchResponse.getHits().getHits() != null) {
            for (SearchHit hit : searchResponse.getHits().getHits()) {
                feedsToCreate.remove(hit.getId());
            }
        }
        if (feedsToCreate.isEmpty()) {
            listener.onResponse(null);
            return;
        }
        GroupedActionListener<ResponseOrException<SATIFSourceConfigDto>> groupedActionListener = new GroupedActionListener<>(
                new ActionListener<>() {
                    @Override
                    public void onResponse(Collection<ResponseOrException<SATIFSourceConfigDto>> responseOrExceptions) {
                        if (responseOrExceptions.stream().allMatch(it -> it.getException() != null)) { // all configs returned error
                            Exception e = responseOrExceptions.stream().findFirst().get().getException();
                            log.error("Failed to create default tif configs", e);
                            listener.onFailure(e);
                            return;
                        }
                        listener.onResponse(null);
                        return;
                    }

                    @Override
                    public void onFailure(Exception e) {
                        log.error("Unexpected failure while creating Default Threat intel source configs", e);
                        listener.onFailure(e);
                        return;
                    }
                }, feedsToCreate.size()
        );
        for (TIFMetadata tifMetadata : feedsToCreate.values()) {
            if (tifMetadata == null) {
                continue;
            }
            try {
                Instant now = Instant.now();
                String iocType = null;
                if (tifMetadata.getIocType().equalsIgnoreCase("ip")) {
                    iocType = IOCType.ipv4_addr.toString();
                }
                satifSourceConfigManagementService.createOrUpdateTifSourceConfig(
                        new SATIFSourceConfigDto(
                                tifMetadata.getFeedId(),
                                SATIFSourceConfigDto.NO_VERSION,
                                tifMetadata.getName(),
                                "STIX2",
                                SourceConfigType.URL_DOWNLOAD,
                                tifMetadata.getDescription(),
                                null,
                                now,
                                new UrlDownloadSource(new URL(tifMetadata.getUrl()), tifMetadata.getFeedType(), tifMetadata.hasHeader(), tifMetadata.getIocCol()),
                                now,
                                now,
                                new IntervalSchedule(now, 1, ChronoUnit.DAYS),
                                TIFJobState.CREATING,
                                RefreshType.FULL,
                                null,
                                null,
                                true,
                                List.of(iocType),
                                true
                        ),
                        null,
                        RestRequest.Method.POST,
                        null,
                        ActionListener.wrap(
                                r -> {
                                    groupedActionListener.onResponse(new ResponseOrException<>(r, null));
                                },
                                e -> {
                                    log.error("failed to create default tif source config " + tifMetadata.getFeedId(), e);
                                    groupedActionListener.onResponse(new ResponseOrException<>(null, e));
                                })
                );
                continue;
            } catch (Exception ex) {
                log.error("Unexpected failure while creating Default Threat intel source configs " + tifMetadata.getFeedId(), ex);
                groupedActionListener.onResponse(new ResponseOrException<>(null, ex));
                continue;
            }
        }
    }

    private static class ResponseOrException<R> {
        private final R response;
        private final Exception exception;

        private ResponseOrException(R response, Exception exception) {
            this.response = response;
            this.exception = exception;
        }

        public R getResponse() {
            return response;
        }

        public Exception getException() {
            return exception;
        }
    }
}

