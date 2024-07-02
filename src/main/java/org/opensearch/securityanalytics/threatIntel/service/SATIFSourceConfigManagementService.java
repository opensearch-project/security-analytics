package org.opensearch.securityanalytics.threatIntel.service;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.opensearch.OpenSearchException;
import org.opensearch.action.delete.DeleteResponse;
import org.opensearch.action.search.SearchRequest;
import org.opensearch.action.search.SearchResponse;
import org.opensearch.cluster.ClusterState;
import org.opensearch.cluster.metadata.IndexAbstraction;
import org.opensearch.cluster.metadata.IndexMetadata;
import org.opensearch.cluster.routing.Preference;
import org.opensearch.cluster.service.ClusterService;
import org.opensearch.common.inject.Inject;
import org.opensearch.common.xcontent.LoggingDeprecationHandler;
import org.opensearch.common.xcontent.XContentFactory;
import org.opensearch.common.xcontent.XContentType;
import org.opensearch.commons.authuser.User;
import org.opensearch.core.action.ActionListener;
import org.opensearch.core.common.bytes.BytesReference;
import org.opensearch.core.xcontent.NamedXContentRegistry;
import org.opensearch.core.xcontent.ToXContent;
import org.opensearch.core.xcontent.XContentBuilder;
import org.opensearch.core.xcontent.XContentParser;
import org.opensearch.index.IndexNotFoundException;
import org.opensearch.index.query.BoolQueryBuilder;
import org.opensearch.index.query.QueryBuilders;
import org.opensearch.jobscheduler.spi.LockModel;
import org.opensearch.rest.RestRequest;
import org.opensearch.search.SearchHit;
import org.opensearch.search.builder.SearchSourceBuilder;
import org.opensearch.securityanalytics.SecurityAnalyticsPlugin;
import org.opensearch.securityanalytics.model.STIX2IOC;
import org.opensearch.securityanalytics.model.STIX2IOCDto;
import org.opensearch.securityanalytics.services.STIX2IOCFetchService;
import org.opensearch.securityanalytics.settings.SecurityAnalyticsSettings;
import org.opensearch.securityanalytics.threatIntel.common.TIFJobState;
import org.opensearch.securityanalytics.threatIntel.common.TIFLockService;
import org.opensearch.securityanalytics.threatIntel.model.DefaultIocStoreConfig;
import org.opensearch.securityanalytics.threatIntel.model.IocStoreConfig;
import org.opensearch.securityanalytics.threatIntel.model.IocUploadSource;
import org.opensearch.securityanalytics.threatIntel.model.SATIFSourceConfig;
import org.opensearch.securityanalytics.threatIntel.model.SATIFSourceConfigDto;
import org.opensearch.securityanalytics.util.IndexUtils;

import java.time.Instant;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.SortedMap;

import static org.opensearch.securityanalytics.services.STIX2IOCFeedStore.getIocIndexAlias;

import java.util.stream.Collectors;

import static org.opensearch.securityanalytics.threatIntel.common.SourceConfigType.IOC_UPLOAD;

/**
 * Service class for threat intel feed source config object
 */
public class SATIFSourceConfigManagementService {
    private static final Logger log = LogManager.getLogger(SATIFSourceConfigManagementService.class);
    private final SATIFSourceConfigService saTifSourceConfigService;
    private final TIFLockService lockService; //TODO: change to js impl lock
    private final STIX2IOCFetchService stix2IOCFetchService;
    private final NamedXContentRegistry xContentRegistry;
    private final ClusterService clusterService;

    /**
     * Default constructor
     *
     * @param saTifSourceConfigService the tif source config dao
     * @param lockService              the lock service
     * @param stix2IOCFetchService     the service to download, and store IOCs
     */
    @Inject
    public SATIFSourceConfigManagementService(
            final SATIFSourceConfigService saTifSourceConfigService,
            final TIFLockService lockService,
            final STIX2IOCFetchService stix2IOCFetchService,
            final NamedXContentRegistry xContentRegistry,
            final ClusterService clusterService
    ) {
        this.saTifSourceConfigService = saTifSourceConfigService;
        this.lockService = lockService;
        this.stix2IOCFetchService = stix2IOCFetchService;
        this.xContentRegistry = xContentRegistry;
        this.clusterService = clusterService;
    }

    public void createOrUpdateTifSourceConfig(
            final SATIFSourceConfigDto saTifSourceConfigDto,
            final LockModel lock,
            final RestRequest.Method restMethod,
            final User user,
            final ActionListener<SATIFSourceConfigDto> listener
    ) {
        if (restMethod == RestRequest.Method.POST) {
            createIocAndTIFSourceConfig(saTifSourceConfigDto, lock, user, listener);
        } else if (restMethod == RestRequest.Method.PUT) {
            updateIocAndTIFSourceConfig(saTifSourceConfigDto, lock, user, listener);
        }
    }

    /**
     * Creates the job index if it doesn't exist and indexes the tif source config object
     *
     * @param saTifSourceConfigDto the tif source config dto
     * @param lock                 the lock object
     * @param listener             listener that accepts a tif source config if successful
     */
    public void createIocAndTIFSourceConfig(
            final SATIFSourceConfigDto saTifSourceConfigDto,
            final LockModel lock,
            final User createdByUser,
            final ActionListener<SATIFSourceConfigDto> listener
    ) {
        try {
            SATIFSourceConfig saTifSourceConfig = convertToSATIFConfig(saTifSourceConfigDto, null, TIFJobState.CREATING, createdByUser);

            // Don't index iocs into source config index
            List<STIX2IOC> iocs;
            if (saTifSourceConfig.getSource() instanceof IocUploadSource) {
                List<STIX2IOCDto> iocDtos = ((IocUploadSource) saTifSourceConfigDto.getSource()).getIocs();
                ((IocUploadSource) saTifSourceConfig.getSource()).setIocs(List.of());
                iocs = convertToIocs(iocDtos, saTifSourceConfig.getName(), saTifSourceConfig.getId());
            } else {
                iocs = null;
            }

            // Index threat intel source config as creating and update the last refreshed time
            saTifSourceConfig.setLastRefreshedTime(Instant.now());
            saTifSourceConfig.setLastRefreshedUser(createdByUser);

            saTifSourceConfigService.indexTIFSourceConfig(
                    saTifSourceConfig,
                    lock,
                    ActionListener.wrap(
                            indexSaTifSourceConfigResponse -> {
                                log.debug("Indexed threat intel source config as CREATING for [{}]", indexSaTifSourceConfigResponse.getId());
                                // Call to download and save IOCS's, update state as AVAILABLE on success
                                downloadAndSaveIOCs(
                                        indexSaTifSourceConfigResponse,
                                        iocs,
                                        ActionListener.wrap(
                                                r -> {
                                                    markSourceConfigAsAction(
                                                            indexSaTifSourceConfigResponse,
                                                            TIFJobState.AVAILABLE,
                                                            ActionListener.wrap(
                                                                    updateSaTifSourceConfigResponse -> {
                                                                        log.debug("Updated threat intel source config as AVAILABLE for [{}]", indexSaTifSourceConfigResponse.getId());
                                                                        SATIFSourceConfigDto returnedSaTifSourceConfigDto = new SATIFSourceConfigDto(updateSaTifSourceConfigResponse);
                                                                        listener.onResponse(returnedSaTifSourceConfigDto);
                                                                    }, e -> {
                                                                        log.error("Failed to index threat intel source config with id [{}]", indexSaTifSourceConfigResponse.getId());
                                                                        listener.onFailure(e);
                                                                    }
                                                            ));
                                                },
                                                e -> {
                                                    log.error("Failed to download and save IOCs for source config [{}]", indexSaTifSourceConfigResponse.getId());
                                                    saTifSourceConfigService.deleteTIFSourceConfig(indexSaTifSourceConfigResponse, ActionListener.wrap(
                                                            deleteResponse -> {
                                                                log.debug("Successfully deleted threat intel source config [{}]", indexSaTifSourceConfigResponse.getId());
                                                                listener.onFailure(e);
                                                            }, ex -> {
                                                                log.error("Failed to delete threat intel source config [{}]", indexSaTifSourceConfigResponse.getId());
                                                                listener.onFailure(e);
                                                            }
                                                    ));
                                                })
                                );
                            }, e -> {
                                log.error("Failed to index threat intel source config with id [{}]", saTifSourceConfig.getId());
                                listener.onFailure(e);
                            }));
        } catch (Exception e) {
            log.error("Failed to create IOCs and threat intel source config");
            listener.onFailure(e);
        }
    }

    /**
     * Function to download and save IOCs, if source is not null, grab IOCs from S3 otherwise IOCs are passed in
     *
     * @param saTifSourceConfig
     * @param stix2IOCList
     * @param actionListener
     */
    public void downloadAndSaveIOCs(SATIFSourceConfig saTifSourceConfig,
                                    List<STIX2IOC> stix2IOCList,
                                    ActionListener<STIX2IOCFetchService.STIX2IOCFetchResponse> actionListener) {
        switch (saTifSourceConfig.getType()) {
            case S3_CUSTOM:
                stix2IOCFetchService.downloadAndIndexIOCs(saTifSourceConfig, actionListener);
                break;
            case IOC_UPLOAD:
                stix2IOCFetchService.onlyIndexIocs(saTifSourceConfig, stix2IOCList, actionListener);
                break;
        }
    }

    public void getTIFSourceConfig(
            final String saTifSourceConfigId,
            final ActionListener<SATIFSourceConfigDto> listener
    ) {
        saTifSourceConfigService.getTIFSourceConfig(saTifSourceConfigId, ActionListener.wrap(
                saTifSourceConfigResponse -> {
                    SATIFSourceConfigDto returnedSaTifSourceConfigDto = new SATIFSourceConfigDto(saTifSourceConfigResponse);
                    listener.onResponse(returnedSaTifSourceConfigDto);
                }, e -> {
                    log.error("Failed to get threat intel source config for [{}]", saTifSourceConfigId);
                    listener.onFailure(e);
                }
        ));
    }

    public void searchTIFSourceConfigs(
            final SearchSourceBuilder searchSourceBuilder,
            final ActionListener<SearchResponse> listener
    ) {
        try {
            SearchRequest searchRequest = getSearchRequest(searchSourceBuilder);

            // convert search response to threat intel source config dtos
            saTifSourceConfigService.searchTIFSourceConfigs(searchRequest, ActionListener.wrap(
                    searchResponse -> {
                        for (SearchHit hit : searchResponse.getHits()) {
                            XContentParser xcp = XContentType.JSON.xContent().createParser(
                                    xContentRegistry,
                                    LoggingDeprecationHandler.INSTANCE, hit.getSourceAsString()
                            );
                            SATIFSourceConfigDto satifSourceConfigDto = SATIFSourceConfigDto.docParse(xcp, hit.getId(), hit.getVersion());
                            XContentBuilder xcb = satifSourceConfigDto.toXContent(XContentFactory.jsonBuilder(), ToXContent.EMPTY_PARAMS);
                            hit.sourceRef(BytesReference.bytes(xcb));
                        }
                        listener.onResponse(searchResponse);
                    }, e -> {
                        log.error("Failed to fetch all threat intel source configs for search request [{}]", searchSourceBuilder, e);
                        listener.onFailure(e);
                    }
            ));
        } catch (Exception e) {
            log.error("Failed to search and parse all threat intel source configs");
            listener.onFailure(e);
        }
    }

    private static SearchRequest getSearchRequest(SearchSourceBuilder searchSourceBuilder) {

        // update search source builder
        searchSourceBuilder.seqNoAndPrimaryTerm(true);
        searchSourceBuilder.version(true);

        // construct search request
        SearchRequest searchRequest = new SearchRequest().source(searchSourceBuilder);
        searchRequest.indices(SecurityAnalyticsPlugin.JOB_INDEX_NAME);
        searchRequest.preference(Preference.PRIMARY_FIRST.type());

        BoolQueryBuilder boolQueryBuilder;

        if (searchRequest.source().query() == null) {
            boolQueryBuilder = new BoolQueryBuilder();
        } else {
            boolQueryBuilder = QueryBuilders.boolQuery().must(searchRequest.source().query());
        }

        BoolQueryBuilder bqb = new BoolQueryBuilder();
        bqb.should().add(new BoolQueryBuilder().must(QueryBuilders.existsQuery("source_config")));

        boolQueryBuilder.filter(bqb);
        searchRequest.source().query(boolQueryBuilder);
        return searchRequest;
    }

    public void updateIocAndTIFSourceConfig(
            final SATIFSourceConfigDto saTifSourceConfigDto,
            final LockModel lock,
            final User updatedByUser,
            final ActionListener<SATIFSourceConfigDto> listener
    ) {
        try {
            saTifSourceConfigService.getTIFSourceConfig(saTifSourceConfigDto.getId(), ActionListener.wrap(
                    retrievedSaTifSourceConfig -> {
                        if (TIFJobState.AVAILABLE.equals(retrievedSaTifSourceConfig.getState()) == false && TIFJobState.REFRESH_FAILED.equals(retrievedSaTifSourceConfig.getState()) == false) {
                            log.error("Invalid TIF job state. Expecting {} or {} but received {}", TIFJobState.AVAILABLE, TIFJobState.REFRESH_FAILED, retrievedSaTifSourceConfig.getState());
                            listener.onFailure(new OpenSearchException("Invalid TIF job state. Expecting {} or {} but received {}", TIFJobState.AVAILABLE, TIFJobState.REFRESH_FAILED, retrievedSaTifSourceConfig.getState()));
                            return;
                        }

                        if (false == saTifSourceConfigDto.getType().equals(retrievedSaTifSourceConfig.getType())) {
                            log.error("Unable to update source config, type cannot change from {} to {}", retrievedSaTifSourceConfig.getType(), saTifSourceConfigDto.getType());
                            listener.onFailure(new OpenSearchException("Unable to update source config, type cannot change from {} to {}", retrievedSaTifSourceConfig.getType(), saTifSourceConfigDto.getType()));
                            return;
                        }

                        SATIFSourceConfig updatedSaTifSourceConfig = updateSaTifSourceConfig(saTifSourceConfigDto, retrievedSaTifSourceConfig);

                        // Don't index iocs into source config index
                        List<STIX2IOC> iocs;
                        if (updatedSaTifSourceConfig.getSource() instanceof IocUploadSource) {
                            List<STIX2IOCDto> iocDtos = ((IocUploadSource) saTifSourceConfigDto.getSource()).getIocs();
                            ((IocUploadSource) updatedSaTifSourceConfig.getSource()).setIocs(List.of());
                            iocs = convertToIocs(iocDtos, updatedSaTifSourceConfig.getName(), updatedSaTifSourceConfig.getId());
                        } else {
                            iocs = null;
                        }

                        // Download and save IOCS's based on new threat intel source config
                        updatedSaTifSourceConfig.setLastRefreshedTime(Instant.now());
                        updatedSaTifSourceConfig.setLastRefreshedUser(updatedByUser);
                        markSourceConfigAsAction(updatedSaTifSourceConfig, TIFJobState.REFRESHING, ActionListener.wrap(
                                r -> {
                                    log.info("Set threat intel source config as REFRESHING for [{}]", updatedSaTifSourceConfig.getId());
                                    switch (updatedSaTifSourceConfig.getType()) {
                                        case S3_CUSTOM:
                                            downloadAndSaveIocsToRefresh(listener, updatedSaTifSourceConfig);
                                            break;
                                        case IOC_UPLOAD:
                                            storeAndDeleteIocIndices(
                                                    iocs,
                                                    listener,
                                                    updatedSaTifSourceConfig
                                            );
                                            break;
                                    }
                                }, e -> {
                                    log.error("Failed to set threat intel source config as REFRESH_FAILED for [{}]", updatedSaTifSourceConfig.getId());
                                    listener.onFailure(e);
                                }
                        ));
                    }, e -> {
                        log.error("Failed to get threat intel source config for [{}]", saTifSourceConfigDto.getId());
                        listener.onFailure(e);
                    }
            ));
        } catch (Exception e) {
            log.error("Failed to update IOCs and threat intel source config for [{}]", saTifSourceConfigDto.getId());
            listener.onFailure(e);
        }
    }

    private void storeAndDeleteIocIndices(List<STIX2IOC> stix2IOCList, ActionListener<SATIFSourceConfigDto> listener, SATIFSourceConfig updatedSaTifSourceConfig) {
        // Index the new iocs
        downloadAndSaveIOCs(updatedSaTifSourceConfig, stix2IOCList, ActionListener.wrap(
                downloadAndSaveIocsResponse -> {

                    // delete the old ioc index created with the source config
                    String type = updatedSaTifSourceConfig.getIocTypes().get(0);
                    Map<String, List<String>> iocToAliasMap = ((DefaultIocStoreConfig) updatedSaTifSourceConfig.getIocStoreConfig()).getIocMapStore();
                    List<String> iocIndices = iocToAliasMap.get(type);
                    List<String> indicesToDelete = new ArrayList<>();
                    String alias = getIocIndexAlias(updatedSaTifSourceConfig.getId());
                    String writeIndex = IndexUtils.getWriteIndex(alias, clusterService.state());
                    for (String index: iocIndices) {
                        if (index.equals(writeIndex) == false && index.equals(alias) == false) {
                            indicesToDelete.add(index);
                        }
                    }
                    // delete the old indices
                    saTifSourceConfigService.deleteAllIocIndices(indicesToDelete, true, null);

                    // remove all indices from the store config from above list for all types
                    for (String iocType : updatedSaTifSourceConfig.getIocTypes()) {
                        iocToAliasMap.get(iocType).removeAll(indicesToDelete);
                    }

                    updatedSaTifSourceConfig.setIocStoreConfig(new DefaultIocStoreConfig(iocToAliasMap));
                    markSourceConfigAsAction(
                            updatedSaTifSourceConfig,
                            TIFJobState.AVAILABLE,
                            ActionListener.wrap(
                                    saTifSourceConfigResponse -> {
                                        SATIFSourceConfigDto returnedSaTifSourceConfigDto = new SATIFSourceConfigDto(saTifSourceConfigResponse);
                                        listener.onResponse(returnedSaTifSourceConfigDto);
                                    }, e -> {
                                        log.error("Failed to index threat intel source config with id [{}]", updatedSaTifSourceConfig.getId());
                                        listener.onFailure(e);
                                    }
                            ));
                },
                e -> {
                    log.error("Failed to download and save IOCs for source config [{}]", updatedSaTifSourceConfig.getId());
                    markSourceConfigAsAction(updatedSaTifSourceConfig, TIFJobState.REFRESH_FAILED, ActionListener.wrap(
                            r -> {
                                log.info("Set threat intel source config as REFRESH_FAILED for [{}]", updatedSaTifSourceConfig.getId());
                                listener.onFailure(new OpenSearchException("Set threat intel source config as REFRESH_FAILED for [{}]", updatedSaTifSourceConfig.getId()));
                            }, ex -> {
                                log.error("Failed to set threat intel source config as REFRESH_FAILED for [{}]", updatedSaTifSourceConfig.getId());
                                listener.onFailure(ex);
                            }
                    ));
                    listener.onFailure(e);
                })
        );
    }

    public void internalUpdateTIFSourceConfig(
            final SATIFSourceConfig saTifSourceConfig,
            final ActionListener<SATIFSourceConfig> listener
    ) {
        try {
            saTifSourceConfig.setLastUpdateTime(Instant.now());
            saTifSourceConfigService.updateTIFSourceConfig(saTifSourceConfig, listener);
        } catch (Exception e) {
            log.error("Failed to update threat intel source config [{}]", saTifSourceConfig.getId());
            listener.onFailure(e);
        }
    }

    public void refreshTIFSourceConfig(
            final String saTifSourceConfigId,
            final User user,
            final ActionListener<SATIFSourceConfigDto> listener
    ) {
        saTifSourceConfigService.getTIFSourceConfig(saTifSourceConfigId, ActionListener.wrap(
                saTifSourceConfig -> {
                    if (saTifSourceConfig.getType() == IOC_UPLOAD) {
                        log.error("Unable to refresh source config [{}] with a source type of [{}]", saTifSourceConfig.getId(), IOC_UPLOAD);
                        listener.onFailure(new OpenSearchException("Unable to refresh source config [{}] with a source type of [{}]", saTifSourceConfig.getId(), IOC_UPLOAD));
                        return;
                    }

                    if (TIFJobState.AVAILABLE.equals(saTifSourceConfig.getState()) == false && TIFJobState.REFRESH_FAILED.equals(saTifSourceConfig.getState()) == false) {
                        log.error("Invalid TIF job state. Expecting {} or {} but received {}", TIFJobState.AVAILABLE, TIFJobState.REFRESH_FAILED, saTifSourceConfig.getState());
                        listener.onFailure(new OpenSearchException("Invalid TIF job state. Expecting {} or {} but received {}", TIFJobState.AVAILABLE, TIFJobState.REFRESH_FAILED, saTifSourceConfig.getState()));
                        return;
                    }

                    // set the last refreshed user
                    if (user != null) {
                        saTifSourceConfig.setLastRefreshedUser(user);
                    }

                    // REFRESH FLOW
                    log.debug("Refreshing IOCs and updating threat intel source config");
                    saTifSourceConfig.setLastRefreshedTime(Instant.now());
                    markSourceConfigAsAction(saTifSourceConfig, TIFJobState.REFRESHING, ActionListener.wrap(
                            updatedSourceConfig -> {
                                downloadAndSaveIocsToRefresh(listener, updatedSourceConfig);
                            }, e -> {
                                log.error("Failed to set threat intel source config as REFRESHING for [{}]", saTifSourceConfig.getId());
                                listener.onFailure(e);
                            }
                    ));
                }, e -> {
                    log.error("Failed to get threat intel source config [{}]", saTifSourceConfigId);
                    listener.onFailure(e);
                }
        ));
    }

    private void downloadAndSaveIocsToRefresh(ActionListener<SATIFSourceConfigDto> listener, SATIFSourceConfig updatedSourceConfig) {
        downloadAndSaveIOCs(updatedSourceConfig, null, ActionListener.wrap(
                response -> {
                    // delete old IOCs and update the source config
                    deleteOldIocIndices(updatedSourceConfig, ActionListener.wrap(
                            newIocStoreConfig -> {
                                updatedSourceConfig.setIocStoreConfig(newIocStoreConfig);
                                // Update source config as succeeded, change state back to available
                                markSourceConfigAsAction(updatedSourceConfig, TIFJobState.AVAILABLE, ActionListener.wrap(
                                        r -> {
                                            log.debug("Set threat intel source config as AVAILABLE for [{}]", updatedSourceConfig.getId());
                                            SATIFSourceConfigDto returnedSaTifSourceConfigDto = new SATIFSourceConfigDto(updatedSourceConfig);
                                            listener.onResponse(returnedSaTifSourceConfigDto);
                                        }, ex -> {
                                            log.error("Failed to set threat intel source config as AVAILABLE for [{}]", updatedSourceConfig.getId());
                                            listener.onFailure(ex);
                                        }
                                ));
                            }, deleteIocIndicesError -> {
                                log.error("Failed to delete old IOC indices", deleteIocIndicesError);
                                listener.onFailure(deleteIocIndicesError);
                            }
                    ));
                }, downloadAndSaveIocsError -> {
                    // Update source config as refresh failed
                    log.error("Failed to download and save IOCs for threat intel source config [{}]", updatedSourceConfig.getId());
                    markSourceConfigAsAction(updatedSourceConfig, TIFJobState.REFRESH_FAILED, ActionListener.wrap(
                            r -> {
                                log.debug("Set threat intel source config as REFRESH_FAILED for [{}]", updatedSourceConfig.getId());
                                listener.onFailure(new OpenSearchException("Set threat intel source config as REFRESH_FAILED for [{}]", updatedSourceConfig.getId()));
                            }, e -> {
                                log.error("Failed to set threat intel source config as REFRESH_FAILED for [{}]", updatedSourceConfig.getId());
                                listener.onFailure(e);
                            }
                    ));
                    listener.onFailure(downloadAndSaveIocsError);
                }));
    }

    /**
     * @param saTifSourceConfigId
     * @param listener
     */
    public void deleteTIFSourceConfig(
            final String saTifSourceConfigId,
            final ActionListener<DeleteResponse> listener
    ) {
        saTifSourceConfigService.getTIFSourceConfig(saTifSourceConfigId, ActionListener.wrap(
                saTifSourceConfig -> {
                    // Check if all threat intel monitors are deleted
                    saTifSourceConfigService.checkAndEnsureThreatIntelMonitorsDeleted(ActionListener.wrap(
                            isDeleted -> {
                                onDeleteThreatIntelMonitors(saTifSourceConfigId, listener, saTifSourceConfig, isDeleted);
                            }, e -> {
                                log.error("Failed to check if all threat intel monitors are deleted or if multiple threat intel source configs exist");
                                listener.onFailure(e);
                            }
                    ));
                }, e -> {
                    log.error("Failed to get threat intel source config for [{}]", saTifSourceConfigId);
                    if (e instanceof IndexNotFoundException) {
                        listener.onFailure(new OpenSearchException("Threat intel source config [{}] not found", saTifSourceConfigId));
                    } else {
                        listener.onFailure(e);
                    }
                }
        ));
    }

    /**
     * Deletes the old ioc indices based on retention age and number of indices per alias
     *
     * @param saTifSourceConfig
     * @param listener
     */
    public void deleteOldIocIndices(
            final SATIFSourceConfig saTifSourceConfig,
            ActionListener<IocStoreConfig> listener
    ) {
        Map<String, List<String>> iocToAliasMap = ((DefaultIocStoreConfig) saTifSourceConfig.getIocStoreConfig()).getIocMapStore();

        // Grabbing the first ioc type since all the indices are stored in one index
        String type = saTifSourceConfig.getIocTypes().get(0);
        String alias = getIocIndexAlias(saTifSourceConfig.getId());
        List<String> concreteIndices = new ArrayList<>(iocToAliasMap.get(type));
        concreteIndices.remove(alias);

        saTifSourceConfigService.getClusterState(ActionListener.wrap(
                clusterStateResponse -> {
                    List<String> indicesToDeleteByAge = getIocIndicesToDeleteByAge(clusterStateResponse.getState(), alias);
                    List<String> indicesToDeleteBySize = getIocIndicesToDeleteBySize(
                            clusterStateResponse.getState(),
                            iocToAliasMap.get(type).size(),
                            indicesToDeleteByAge.size(),
                            alias,
                            concreteIndices);

                    List<String> iocIndicesToDelete = new ArrayList<>();
                    iocIndicesToDelete.addAll(indicesToDeleteByAge);
                    iocIndicesToDelete.addAll(indicesToDeleteBySize);

                    // delete the indices
                    saTifSourceConfigService.deleteAllIocIndices(iocIndicesToDelete, true, null);

                    // update source config
                    saTifSourceConfig.getIocTypes()
                            .stream()
                            .forEach(iocType -> iocToAliasMap.get(iocType).removeAll(iocIndicesToDelete));

                    // return source config
                    listener.onResponse(new DefaultIocStoreConfig(iocToAliasMap));
                }, e-> {
                    log.error("Failed to get the cluster metadata");
                    listener.onFailure(e);
                }
        ), concreteIndices.toArray(new String[0]));
    }

    /**
     * Helper function to retrieve a list of IOC indices to delete based on retention age
     *
     * @param clusterState
     * @param alias
     * @return indicesToDelete
     */
    private List<String> getIocIndicesToDeleteByAge(
            ClusterState clusterState,
            String alias
    ) {
        List<String> indicesToDelete = new ArrayList<>();
        String writeIndex = IndexUtils.getWriteIndex(alias, clusterState);
        Long maxRetentionPeriod = clusterService.getClusterSettings().get(SecurityAnalyticsSettings.IOC_INDEX_RETENTION_PERIOD).millis();

        for (IndexMetadata indexMetadata : clusterState.metadata().indices().values()) {
            Long creationTime = indexMetadata.getCreationDate();
            if ((Instant.now().toEpochMilli() - creationTime) > maxRetentionPeriod) {
                String indexToDelete = indexMetadata.getIndex().getName();
                // ensure index is not the current write index
                if (indexToDelete.equals(writeIndex) == false) {
                    indicesToDelete.add(indexToDelete);
                }
            }
        }
        return indicesToDelete;
    }


    /**
     * Helper function to retrieve a list of IOC indices to delete based on number of indices associated with alias
     * @param clusterState
     * @param totalNumIndicesAndAlias
     * @param totalNumIndicesDeleteByAge
     * @param alias
     * @param concreteIndices
     * @return
     */
    private List<String> getIocIndicesToDeleteBySize(
            ClusterState clusterState,
            Integer totalNumIndicesAndAlias,
            Integer totalNumIndicesDeleteByAge,
            String alias,
            List<String> concreteIndices
    ) {
        Integer numIndicesToDelete = numOfIndicesToDelete(totalNumIndicesAndAlias - 1, totalNumIndicesDeleteByAge); // subtract to account for alias
        List<String> indicesToDelete = new ArrayList<>();

        if (numIndicesToDelete > 0) {
            String writeIndex = IndexUtils.getWriteIndex(alias, clusterState);

            // store indices and creation date in map
            Map<String, Long> indexToAgeMap = new LinkedHashMap<>();
            final SortedMap<String, IndexAbstraction> lookup = clusterState.getMetadata().getIndicesLookup();
            for (String indexName : concreteIndices) {
                IndexAbstraction index = lookup.get(indexName);
                IndexMetadata indexMetadata = clusterState.getMetadata().index(indexName);
                if (index != null && index.getType() == IndexAbstraction.Type.CONCRETE_INDEX) {
                    indexToAgeMap.putIfAbsent(indexName, indexMetadata.getCreationDate());
                }
            }

            // sort the indexToAgeMap by creation date
            List<Map.Entry<String, Long>> sortedList = new ArrayList<>(indexToAgeMap.entrySet());
            sortedList.sort(Map.Entry.comparingByValue());

            // ensure range is not out of bounds
            int endIndex = totalNumIndicesDeleteByAge + numIndicesToDelete;
            endIndex = Math.min(endIndex, totalNumIndicesAndAlias);

            // grab names of indices from totalNumIndicesDeleteByAge to totalNumIndicesDeleteByAge + numIndicesToDelete
            for (int i = totalNumIndicesDeleteByAge; i < endIndex; i++) {
                // ensure index is not the current write index
                if (false == sortedList.get(i).getKey().equals(writeIndex)) {
                    indicesToDelete.add(sortedList.get(i).getKey());
                }
            }
        }
        return indicesToDelete;
    }

    /**
     * Helper function to determine how many indices should be deleted based on setting for number of indices per alias
     * @param totalNumIndices
     * @param totalNumIndicesDeleteByAge
     * @return
     */
    private Integer numOfIndicesToDelete(Integer totalNumIndices, Integer totalNumIndicesDeleteByAge) {
        Integer maxIndicesPerAlias = clusterService.getClusterSettings().get(SecurityAnalyticsSettings.IOC_MAX_INDICES_PER_ALIAS);
        Integer numIndicesAfterDeletingByAge = totalNumIndices - totalNumIndicesDeleteByAge;
        if (numIndicesAfterDeletingByAge > maxIndicesPerAlias) {
            return numIndicesAfterDeletingByAge - maxIndicesPerAlias;
        }
        return 0;
    }

    private void onDeleteThreatIntelMonitors(String saTifSourceConfigId, ActionListener<DeleteResponse> listener, SATIFSourceConfig saTifSourceConfig, Boolean isDeleted) {
        if (isDeleted == false) {
            listener.onFailure(new IllegalArgumentException("All threat intel monitors need to be deleted before deleting last threat intel source config"));
        } else {
            log.debug("All threat intel monitors are deleted or multiple threat intel source configs exist, can delete threat intel source config [{}]", saTifSourceConfigId);
            markSourceConfigAsAction(
                    saTifSourceConfig,
                    TIFJobState.DELETING,
                    ActionListener.wrap(
                            updateSaTifSourceConfigResponse -> {
                                String type = updateSaTifSourceConfigResponse.getIocTypes().get(0);
                                DefaultIocStoreConfig iocStoreConfig = (DefaultIocStoreConfig) updateSaTifSourceConfigResponse.getIocStoreConfig();
                                List<String> indicesWithoutAlias = new ArrayList<>(iocStoreConfig.getIocMapStore().get(type));
                                indicesWithoutAlias.remove(getIocIndexAlias(updateSaTifSourceConfigResponse.getId()));
                                saTifSourceConfigService.deleteAllIocIndices(indicesWithoutAlias, false, ActionListener.wrap(
                                        r -> {
                                            log.debug("Successfully deleted all ioc indices");
                                            saTifSourceConfigService.deleteTIFSourceConfig(updateSaTifSourceConfigResponse, ActionListener.wrap(
                                                    deleteResponse -> {
                                                        log.debug("Successfully deleted threat intel source config [{}]", updateSaTifSourceConfigResponse.getId());
                                                        listener.onResponse(deleteResponse);
                                                    }, e -> {
                                                        log.error("Failed to delete threat intel source config [{}]", saTifSourceConfigId);
                                                        listener.onFailure(e);
                                                    }
                                            ));
                                        }, e -> {
                                            log.error("Failed to delete IOC indices for source config [{}]", updateSaTifSourceConfigResponse.getId());
                                            listener.onFailure(e);
                                        }
                                ));
                            }, e -> {
                                log.error("Failed to update threat intel source config with state as {}", TIFJobState.DELETING);
                                listener.onFailure(e);
                            }
                    ));
        }
    }

    public void markSourceConfigAsAction(final SATIFSourceConfig saTifSourceConfig, TIFJobState state, ActionListener<SATIFSourceConfig> actionListener) {
        saTifSourceConfig.setState(state);
        try {
            internalUpdateTIFSourceConfig(saTifSourceConfig, actionListener);
        } catch (Exception e) {
            log.error("Failed to mark threat intel source config as {} for [{}]", state, saTifSourceConfig.getId(), e);
            actionListener.onFailure(e);
        }
    }

    /**
     * Converts the DTO to entity when creating the source config
     *
     * @param saTifSourceConfigDto
     * @return saTifSourceConfig
     */
    public SATIFSourceConfig convertToSATIFConfig(SATIFSourceConfigDto saTifSourceConfigDto,
                                                  IocStoreConfig iocStoreConfig,
                                                  TIFJobState state,
                                                  User createdByUser) {
        return new SATIFSourceConfig(
                saTifSourceConfigDto.getId(),
                saTifSourceConfigDto.getVersion(),
                saTifSourceConfigDto.getName(),
                saTifSourceConfigDto.getFormat(),
                saTifSourceConfigDto.getType(),
                saTifSourceConfigDto.getDescription(),
                createdByUser,
                saTifSourceConfigDto.getCreatedAt(),
                saTifSourceConfigDto.getSource(),
                saTifSourceConfigDto.getEnabledTime(),
                saTifSourceConfigDto.getLastUpdateTime(),
                saTifSourceConfigDto.getSchedule(),
                state,
                saTifSourceConfigDto.getRefreshType(),
                saTifSourceConfigDto.getLastRefreshedTime(),
                saTifSourceConfigDto.getLastRefreshedUser(),
                saTifSourceConfigDto.isEnabled(),
                iocStoreConfig,
                saTifSourceConfigDto.getIocTypes()
        );
    }

    private SATIFSourceConfig updateSaTifSourceConfig(SATIFSourceConfigDto saTifSourceConfigDto, SATIFSourceConfig saTifSourceConfig) {
        return new SATIFSourceConfig(
                saTifSourceConfig.getId(),
                saTifSourceConfig.getVersion(),
                saTifSourceConfigDto.getName(),
                saTifSourceConfigDto.getFormat(),
                saTifSourceConfigDto.getType(),
                saTifSourceConfigDto.getDescription(),
                saTifSourceConfig.getCreatedByUser(),
                saTifSourceConfig.getCreatedAt(),
                saTifSourceConfigDto.getSource(),
                saTifSourceConfig.getEnabledTime(),
                saTifSourceConfig.getLastUpdateTime(),
                saTifSourceConfigDto.getSchedule(),
                saTifSourceConfig.getState(),
                saTifSourceConfigDto.getRefreshType(),
                saTifSourceConfig.getLastRefreshedTime(),
                saTifSourceConfig.getLastRefreshedUser(),
                saTifSourceConfigDto.isEnabled(),
                saTifSourceConfig.getIocStoreConfig(),
                saTifSourceConfigDto.getIocTypes()
        );
    }

    public List<STIX2IOC> convertToIocs(List<STIX2IOCDto> stix2IocDtoList, String name, String id) {
        if (stix2IocDtoList == null) {
            return null;
        }
        return stix2IocDtoList.stream()
                .map(dto -> new STIX2IOC(dto, id, name))
                .collect(Collectors.toList());
    }

}
