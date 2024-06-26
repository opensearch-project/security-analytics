package org.opensearch.securityanalytics.threatIntel.service;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.opensearch.OpenSearchException;
import org.opensearch.action.StepListener;
import org.opensearch.action.admin.cluster.state.ClusterStateResponse;
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
import org.opensearch.securityanalytics.threatIntel.model.SATIFSourceConfig;
import org.opensearch.securityanalytics.threatIntel.model.SATIFSourceConfigDto;
import org.opensearch.securityanalytics.util.IndexUtils;

import java.time.Instant;
import java.util.ArrayList;
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
            final User createdByUser,
            final ActionListener<SATIFSourceConfigDto> listener
    ) {
        if (restMethod == RestRequest.Method.POST) {
            createIocAndTIFSourceConfig(saTifSourceConfigDto, lock, createdByUser, listener);
        } else if (restMethod == RestRequest.Method.PUT) {
            updateIocAndTIFSourceConfig(saTifSourceConfigDto, lock, listener);
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

            // Index threat intel source config as creating
            saTifSourceConfigService.indexTIFSourceConfig(
                    saTifSourceConfig,
                    lock,
                    ActionListener.wrap(
                            indexSaTifSourceConfigResponse -> {
                                log.debug("Indexed threat intel source config as CREATING for [{}]", indexSaTifSourceConfigResponse.getId());
                                // Call to download and save IOCS's, update state as AVAILABLE on success
                                downloadAndSaveIOCs(
                                        indexSaTifSourceConfigResponse,
                                        convertToIocs(saTifSourceConfigDto.getIocs(), indexSaTifSourceConfigResponse.getName(), indexSaTifSourceConfigResponse.getId()),
                                        ActionListener.wrap(
                                                r -> {
                                                    // TODO: Update the IOC map to store list of indices, sync up with @hurneyt
                                                    // TODO: Only return list of ioc indices if no errors occur (no partial iocs)
                                                    markSourceConfigAsAction(
                                                            indexSaTifSourceConfigResponse,
                                                            TIFJobState.AVAILABLE,
                                                            ActionListener.wrap(
                                                                    updateSaTifSourceConfigResponse -> {
                                                                        log.debug("Updated threat intel source config as AVAILABLE for [{}]", indexSaTifSourceConfigResponse.getId());
                                                                        SATIFSourceConfigDto returnedSaTifSourceConfigDto = new SATIFSourceConfigDto(updateSaTifSourceConfigResponse);
                                                                        returnedSaTifSourceConfigDto.setIocs(saTifSourceConfigDto.getIocs());
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
                                                                listener.onFailure(new OpenSearchException("Successfully deleted threat intel source config [{}]", indexSaTifSourceConfigResponse.getId()));
                                                            }, ex -> {
                                                                log.error("Failed to delete threat intel source config [{}]", indexSaTifSourceConfigResponse.getId());
                                                                listener.onFailure(ex);
                                                            }
                                                    ));
                                                    listener.onFailure(e);
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
            final ActionListener<SATIFSourceConfigDto> listener
    ) {
        try {
            saTifSourceConfigService.getTIFSourceConfig(saTifSourceConfigDto.getId(), ActionListener.wrap(
                    retrievedSaTifSourceConfig -> {
                        if (TIFJobState.AVAILABLE.equals(retrievedSaTifSourceConfig.getState()) == false) {
                            log.error("Invalid TIF job state. Expecting {} but received {}", TIFJobState.AVAILABLE, retrievedSaTifSourceConfig.getState());
                            listener.onFailure(new OpenSearchException("Invalid TIF job state. Expecting {} but received {}", TIFJobState.AVAILABLE, retrievedSaTifSourceConfig.getState()));
                            return;
                        }

                        if (false == saTifSourceConfigDto.getType().equals(retrievedSaTifSourceConfig.getType())) {
                            log.error("Unable to update source config, type cannot change from {} to {}", retrievedSaTifSourceConfig.getType(), saTifSourceConfigDto.getType());
                            listener.onFailure(new OpenSearchException("Unable to update source config, type cannot change from {} to {}", retrievedSaTifSourceConfig.getType(), saTifSourceConfigDto.getType()));
                            return;
                        }

                        SATIFSourceConfig updatedSaTifSourceConfig = updateSaTifSourceConfig(saTifSourceConfigDto, retrievedSaTifSourceConfig);

                        // Download and save IOCS's based on new threat intel source config
                        markSourceConfigAsAction(updatedSaTifSourceConfig, TIFJobState.REFRESHING, ActionListener.wrap(
                                r -> {
                                    log.info("Set threat intel source config as REFRESHING for [{}]", updatedSaTifSourceConfig.getId());
                                    switch (updatedSaTifSourceConfig.getType()) {
                                        case S3_CUSTOM:
                                            downloadAndSaveIocsToRefresh(listener, updatedSaTifSourceConfig);
                                            break;
                                        case IOC_UPLOAD:
                                            justDownloadAndDeleteIocIndices(
                                                    convertToIocs(saTifSourceConfigDto.getIocs(), updatedSaTifSourceConfig.getName(), updatedSaTifSourceConfig.getId()),
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

    private void justDownloadAndDeleteIocIndices(List<STIX2IOC> stix2IOCList, ActionListener<SATIFSourceConfigDto> listener, SATIFSourceConfig updatedSaTifSourceConfig) {
        // index new iocs
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
                    saTifSourceConfigService.deleteAllIocIndices(indicesToDelete);

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
                                // TODO: download and save iocs listener should return the source config, sync up with @hurneyt
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

        List<String> iocIndicesDeleted = new ArrayList<>();
        StepListener<List<String>> deleteIocIndicesByAgeListener = new StepListener<>();

        List<String> indicesWithoutAlias = new ArrayList<>(iocToAliasMap.get(type));
        indicesWithoutAlias.remove(alias);
        checkAndDeleteOldIocIndicesByAge(indicesWithoutAlias, deleteIocIndicesByAgeListener, alias);
        deleteIocIndicesByAgeListener.whenComplete(
                iocIndicesDeletedByAge -> {
                    // remove indices deleted by age from the ioc map and add to ioc indices deleted list
                    iocToAliasMap.get(type).removeAll(iocIndicesDeletedByAge);
                    iocIndicesDeleted.addAll(iocIndicesDeletedByAge);

                    List<String> newIndicesWithoutAlias = new ArrayList<>(iocToAliasMap.get(type));
                    newIndicesWithoutAlias.remove(alias);
                    checkAndDeleteOldIocIndicesBySize(newIndicesWithoutAlias, alias, ActionListener.wrap(
                            iocIndicesDeletedBySize -> {
                                iocToAliasMap.get(type).removeAll(iocIndicesDeletedBySize);
                                iocIndicesDeleted.addAll(iocIndicesDeletedBySize);

                                // delete the ioc indices for other IOC types
                                saTifSourceConfig.getIocTypes()
                                        .stream()
                                        .filter(iocType -> iocType.equals(type) == false)
                                        .forEach(iocType -> iocToAliasMap.get(iocType).removeAll(iocIndicesDeleted));
                                listener.onResponse(new DefaultIocStoreConfig(iocToAliasMap));
                            }, e -> {
                                log.error("Failed to check and delete ioc indices by size", e);
                                listener.onFailure(e);
                            }
                    ));
                }, e -> {
                    log.error("Failed to check and delete ioc indices by age", e);
                    listener.onFailure(e);
                });
    }

    /**
     * Checks if any IOC index is greater than retention period and deletes it
     *
     * @param indices
     * @param stepListener
     * @param alias
     */
    private void checkAndDeleteOldIocIndicesByAge(
            List<String> indices,
            StepListener<List<String>> stepListener,
            String alias
    ) {
        log.debug("Delete old IOC indices by age");
        saTifSourceConfigService.getClusterState(
                ActionListener.wrap(
                        clusterStateResponse -> {
                            List<String> indicesToDelete = new ArrayList<>();
                            log.debug("Checking if we should delete indices: [" + indicesToDelete + "]");
                            indicesToDelete = getIocIndicesToDeleteByAge(clusterStateResponse, alias);
                            if (indicesToDelete.isEmpty()) {
                                stepListener.onResponse(indicesToDelete);
                            } else {
                                List<String> finalIndicesToDelete = indicesToDelete;
                                saTifSourceConfigService.deleteAllIocIndices(finalIndicesToDelete);
                                stepListener.onResponse(finalIndicesToDelete);
//                                        ActionListener.wrap(
//                                        r -> {
//                                            stepListener.onResponse(finalIndicesToDelete);
//                                        }, e -> {
//                                            log.error("Failed to delete old ioc indices by age");
//                                            stepListener.onFailure(e);
//                                        }
//                                ));
                            }
                        }, e -> {
                            log.error("Failed to get the cluster metadata");
                            stepListener.onFailure(e);
                        }
                ), indices.toArray(new String[0])
        );
    }

    /**
     * Checks if number of allowed indices per alias is reached and delete old indices
     *
     * @param indices
     * @param alias
     * @param listener
     */
    private void checkAndDeleteOldIocIndicesBySize( // TODO: max indices in alias
            List<String> indices,
            String alias,
            ActionListener<List<String>> listener
    ) {
        log.debug("Delete old IOC indices by size");
        saTifSourceConfigService.getClusterState(
                ActionListener.wrap(
                        clusterStateResponse -> {
                            List<String> indicesToDelete = new ArrayList<>();
                            Integer numIndicesToDelete = numOfIndicesToDelete(indices);
                            if (numIndicesToDelete > 0) {
                                indicesToDelete = getIocIndicesToDeleteBySize(clusterStateResponse, numIndicesToDelete, indices, alias);
                                if (indicesToDelete.isEmpty() == false) {
                                    List<String> finalIndicesToDelete = indicesToDelete;
                                    saTifSourceConfigService.deleteAllIocIndices(finalIndicesToDelete);
                                    listener.onResponse(finalIndicesToDelete);
//                                            ActionListener.wrap(
//                                            r -> {
//                                                listener.onResponse(finalIndicesToDelete);
//                                            }, e -> {
//                                                log.error("Failed to delete old ioc indices by size");
//                                                listener.onFailure(e); // TODO: maybe remove this
//                                            }
//                                    ));
                                } else {
                                    listener.onResponse(indicesToDelete);
                                }
                            } else {
                                listener.onResponse(indicesToDelete);
                            }
                        }, e -> {
                            log.error("Failed to get the cluster metadata");
                            listener.onFailure(e);
                        }
                ), indices.toArray(new String[0])
        );
    }

    /**
     * Helper function to retrieve a list of IOC indices to delete based on retention age
     *
     * @param clusterStateResponse
     * @param alias
     * @return indicesToDelete
     */
    private List<String> getIocIndicesToDeleteByAge(
            ClusterStateResponse clusterStateResponse,
            String alias
    ) {
        List<String> indicesToDelete = new ArrayList<>();
        String writeIndex = IndexUtils.getWriteIndex(alias, clusterStateResponse.getState());
        Long maxRetentionPeriod = clusterService.getClusterSettings().get(SecurityAnalyticsSettings.IOC_INDEX_RETENTION_PERIOD).millis();

        for (IndexMetadata indexMetadata : clusterStateResponse.getState().metadata().indices().values()) {
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
     *
     * @param clusterStateResponse
     * @param numOfIndices
     * @param concreteIndices
     * @param alias
     * @return indicesToDelete
     */

    // i can probs reuse this
    private List<String> getIocIndicesToDeleteBySize(
            ClusterStateResponse clusterStateResponse,
            Integer numOfIndices,
            List<String> concreteIndices,
            String alias
    ) {
        List<String> indicesToDelete = new ArrayList<>();
        String writeIndex = IndexUtils.getWriteIndex(alias, clusterStateResponse.getState());

        for (int i = 0; i < numOfIndices; i++) {
            String indexToDelete = getOldestIndexByCreationDate(concreteIndices, clusterStateResponse.getState(), indicesToDelete);
            if (indexToDelete.equals(writeIndex) == false) {
                indicesToDelete.add(indexToDelete);
            }
        }
        return indicesToDelete;
    }

    /**
     * Helper function to retrieve oldest index in a list of concrete indices
     *
     * @param concreteIndices
     * @param clusterState
     * @param indicesToDelete
     * @return oldestIndex
     */
    private static String getOldestIndexByCreationDate(
            List<String> concreteIndices,
            ClusterState clusterState,
            List<String> indicesToDelete
    ) {
        final SortedMap<String, IndexAbstraction> lookup = clusterState.getMetadata().getIndicesLookup();
        long minCreationDate = Long.MAX_VALUE;
        String oldestIndex = null;
        for (String indexName : concreteIndices) {
            IndexAbstraction index = lookup.get(indexName);
            IndexMetadata indexMetadata = clusterState.getMetadata().index(indexName);
            if (index != null && index.getType() == IndexAbstraction.Type.CONCRETE_INDEX) {
                if (indexMetadata.getCreationDate() < minCreationDate && indicesToDelete.contains(indexName) == false) {
                    minCreationDate = indexMetadata.getCreationDate();
                    oldestIndex = indexName;
                }
            }
        }
        return oldestIndex;
    }

    /**
     * Helper function to determine how many indices should be deleted based on setting for number of indices per alias
     *
     * @param concreteIndices
     * @return
     */
    private Integer numOfIndicesToDelete(List<String> concreteIndices) {
        Integer maxIndicesPerAlias = clusterService.getClusterSettings().get(SecurityAnalyticsSettings.IOC_MAX_INDICES_PER_ALIAS);
        if (concreteIndices.size() > maxIndicesPerAlias) {
            return concreteIndices.size() - maxIndicesPerAlias;
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
                                saTifSourceConfigService.deleteAllIocIndices(indicesWithoutAlias);
                                log.debug("Successfully deleted all ioc indices");
                                saTifSourceConfigService.deleteTIFSourceConfig(saTifSourceConfig, ActionListener.wrap(
                                        deleteResponse -> {
                                            log.debug("Successfully deleted threat intel source config [{}]", saTifSourceConfig.getId());
                                            listener.onResponse(deleteResponse);
                                        }, e -> {
                                            log.error("Failed to delete threat intel source config [{}]", saTifSourceConfigId);
                                            listener.onFailure(e);
                                        }
                                ));
//                                        ActionListener.wrap(
//                                        response -> {
//                                            log.debug("Successfully deleted all ioc indices");
//                                            saTifSourceConfigService.deleteTIFSourceConfig(saTifSourceConfig, ActionListener.wrap(
//                                                    deleteResponse -> {
//                                                        log.debug("Successfully deleted threat intel source config [{}]", saTifSourceConfig.getId());
//                                                        listener.onResponse(deleteResponse);
//                                                    }, e -> {
//                                                        log.error("Failed to delete threat intel source config [{}]", saTifSourceConfigId);
//                                                        listener.onFailure(e);
//                                                    }
//                                            ));
//                                        }, e -> {
//                                            log.error("Failed to delete ioc indices");
//                                            listener.onFailure(e);
//                                        }
//                                ));
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
                .map(dto -> {
                    STIX2IOC stix2ioc = new STIX2IOC(dto);
                    stix2ioc.setFeedName(name);
                    stix2ioc.setFeedId(id);
                    return stix2ioc;
                })
                .collect(Collectors.toList());
    }

}
