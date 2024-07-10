package org.opensearch.securityanalytics.threatIntel.service;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.opensearch.OpenSearchException;
import org.opensearch.OpenSearchStatusException;
import org.opensearch.action.delete.DeleteResponse;
import org.opensearch.action.search.SearchResponse;
import org.opensearch.cluster.ClusterState;
import org.opensearch.cluster.metadata.IndexAbstraction;
import org.opensearch.cluster.metadata.IndexMetadata;
import org.opensearch.cluster.service.ClusterService;
import org.opensearch.common.inject.Inject;
import org.opensearch.common.xcontent.LoggingDeprecationHandler;
import org.opensearch.common.xcontent.XContentFactory;
import org.opensearch.common.xcontent.XContentType;
import org.opensearch.commons.authuser.User;
import org.opensearch.core.action.ActionListener;
import org.opensearch.core.common.bytes.BytesReference;
import org.opensearch.core.rest.RestStatus;
import org.opensearch.core.xcontent.NamedXContentRegistry;
import org.opensearch.core.xcontent.ToXContent;
import org.opensearch.core.xcontent.XContentBuilder;
import org.opensearch.core.xcontent.XContentParser;
import org.opensearch.index.IndexNotFoundException;
import org.opensearch.jobscheduler.spi.LockModel;
import org.opensearch.rest.RestRequest;
import org.opensearch.search.SearchHit;
import org.opensearch.search.builder.SearchSourceBuilder;
import org.opensearch.securityanalytics.commons.model.IOCType;
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

import java.time.Instant;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.SortedMap;
import java.util.stream.Collectors;

import static org.opensearch.securityanalytics.threatIntel.common.SourceConfigType.IOC_UPLOAD;
import static org.opensearch.securityanalytics.threatIntel.common.SourceConfigType.URL_DOWNLOAD;

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
                                                                listener.onFailure(ex);
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
            case URL_DOWNLOAD:
                stix2IOCFetchService.downloadFromUrlAndIndexIOCs(saTifSourceConfig, actionListener);
                break;
            case IOC_UPLOAD:
                List<STIX2IOC> validStix2IocList = new ArrayList<>();
                // If the IOC received is not a type listed for the config, do not add it to the queue
                for (STIX2IOC stix2IOC : stix2IOCList) {
                    if (saTifSourceConfig.getIocTypes().contains(stix2IOC.getType().getType())) {
                        validStix2IocList.add(stix2IOC);
                    } else {
                        log.error("{} is not a supported Ioc type for tif source config {}. Skipping IOC {}: of type {} value {}",
                                stix2IOC.getType().getType(), saTifSourceConfig.getId(),
                                stix2IOC.getId(), stix2IOC.getType().getType(), stix2IOC.getValue()
                        );
                    }
                }
                if (validStix2IocList.isEmpty()) {
                    log.error("No supported IOCs to index");
                    actionListener.onFailure(new OpenSearchStatusException("No compatible Iocs were uploaded for config " + saTifSourceConfig.getName(), RestStatus.BAD_REQUEST));
                    return;
                }
                stix2IOCFetchService.onlyIndexIocs(saTifSourceConfig, validStix2IocList, actionListener);
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
            // convert search response to threat intel source config dtos
            saTifSourceConfigService.searchTIFSourceConfigs(searchSourceBuilder, ActionListener.wrap(
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

                    Set<String> iocIndexPatterns = new HashSet<>();
                    if (updatedSaTifSourceConfig.getIocStoreConfig() instanceof DefaultIocStoreConfig) {
                        // get all the index patterns
                        DefaultIocStoreConfig defaultIocStoreConfig = (DefaultIocStoreConfig) updatedSaTifSourceConfig.getIocStoreConfig();
                        defaultIocStoreConfig.getIocToIndexDetails().forEach(e -> iocIndexPatterns.add(e.getIndexPattern()));
                    }

                    saTifSourceConfigService.getClusterState(ActionListener.wrap(
                            clusterStateResponse -> {
                                List<String> iocTypes = updatedSaTifSourceConfig.getIocTypes();
                                IocStoreConfig iocStoreConfig = updatedSaTifSourceConfig.getIocStoreConfig();
                                Set<String> activeIndices = new HashSet<>();
                                Set<String> indicesToDelete = new HashSet<>();

                                if (iocStoreConfig instanceof DefaultIocStoreConfig) {
                                    DefaultIocStoreConfig defaultIocStoreConfig = (DefaultIocStoreConfig) iocStoreConfig;
                                    Set<String> concreteIndices = SATIFSourceConfigService.getConcreteIndices(clusterStateResponse);

                                    // remove ioc types not specified in list
                                    defaultIocStoreConfig.getIocToIndexDetails().removeIf(iocToIndexDetails -> !IOCType.supportedType(iocToIndexDetails.getIocType().getType()));

                                    // get the active indices
                                    defaultIocStoreConfig.getIocToIndexDetails().forEach(e -> activeIndices.add(e.getActiveIndex()));

                                    for (String index : concreteIndices) {
                                        if (false == activeIndices.contains(index)) {
                                            indicesToDelete.add(index);
                                        }
                                    }
                                }

                                // delete the old indices
                                saTifSourceConfigService.deleteAllIocIndices(indicesToDelete, true, null);
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
                            }, e -> {
                                log.error("Failed to get the cluster metadata");
                                listener.onFailure(e);
                            }
                    ), iocIndexPatterns.toArray(new String[0]));
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
                                List<String> iocTypes = updatedSourceConfig.getIocTypes();
                                if (newIocStoreConfig instanceof DefaultIocStoreConfig) {
                                    DefaultIocStoreConfig defaultIocStoreConfig = (DefaultIocStoreConfig) newIocStoreConfig;
                                    // remove ioc types not specified in list
                                    defaultIocStoreConfig.getIocToIndexDetails().removeIf(iocToIndexDetails -> !IOCType.supportedType(iocToIndexDetails.getIocType().getType()));
                                    updatedSourceConfig.setIocStoreConfig(defaultIocStoreConfig);
                                }
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
                    if (URL_DOWNLOAD.equals(saTifSourceConfig.getType())) {
                        log.error("Cannot delete tif source config {} as it's a built-in config and not user-defined.", saTifSourceConfigId);
                        listener.onFailure(new IllegalArgumentException("Cannot delete built-in tif source config " + saTifSourceConfigId));
                        return;
                    }
                    // Check if all threat intel monitors are deleted
                    saTifSourceConfigService.checkAndEnsureThreatIntelMonitorsDeleted(ActionListener.wrap(
                            isDeleted -> {
                                deleteAllIocsAndSourceConfig(saTifSourceConfigId, listener, saTifSourceConfig, isDeleted);
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
     * Deletes the old ioc indices based on retention age and number of indices per index pattern
     *
     * @param saTifSourceConfig
     * @param listener
     */
    public void deleteOldIocIndices(
            final SATIFSourceConfig saTifSourceConfig,
            ActionListener<IocStoreConfig> listener
    ) {
        Set<String> activeIndices = new HashSet<>();
        IocStoreConfig iocStoreConfig = saTifSourceConfig.getIocStoreConfig();
        Set<String> iocIndexPatterns = new HashSet<>();
        if (iocStoreConfig instanceof DefaultIocStoreConfig) {
            // get the active indices
            DefaultIocStoreConfig defaultIocStoreConfig = (DefaultIocStoreConfig) saTifSourceConfig.getIocStoreConfig();
            defaultIocStoreConfig.getIocToIndexDetails().forEach(e -> activeIndices.add(e.getActiveIndex()));
            // get all the index patterns
            defaultIocStoreConfig.getIocToIndexDetails().forEach(e -> iocIndexPatterns.add(e.getIndexPattern()));
        }

        saTifSourceConfigService.getClusterState(ActionListener.wrap(
                clusterStateResponse -> {
                    Set<String> concreteIndices = SATIFSourceConfigService.getConcreteIndices(clusterStateResponse);
                    List<String> indicesToDeleteByAge = getIocIndicesToDeleteByAge(clusterStateResponse.getState(), activeIndices);
                    List<String> indicesToDeleteBySize = getIocIndicesToDeleteBySize(
                            clusterStateResponse.getState(),
                            indicesToDeleteByAge.size(),
                            activeIndices,
                            concreteIndices);

                    Set<String> iocIndicesToDelete = new HashSet<>();
                    iocIndicesToDelete.addAll(indicesToDeleteByAge);
                    iocIndicesToDelete.addAll(indicesToDeleteBySize);

                    // delete the indices
                    saTifSourceConfigService.deleteAllIocIndices(iocIndicesToDelete, true, null);

                    // return store config
                    listener.onResponse(iocStoreConfig);
                }, e -> {
                    log.error("Failed to get the cluster metadata");
                    listener.onFailure(e);
                }
        ), iocIndexPatterns.toArray(new String[0]));
    }

    /**
     * Helper function to retrieve a list of IOC indices to delete based on retention age
     *
     * @param clusterState
     * @param activeIndices
     * @return indicesToDelete
     */
    private List<String> getIocIndicesToDeleteByAge(
            ClusterState clusterState,
            Set<String> activeIndices
    ) {
        List<String> indicesToDelete = new ArrayList<>();
        Long maxRetentionPeriod = clusterService.getClusterSettings().get(SecurityAnalyticsSettings.IOC_INDEX_RETENTION_PERIOD).millis();

        for (IndexMetadata indexMetadata : clusterState.metadata().indices().values()) {
            Long creationTime = indexMetadata.getCreationDate();
            if ((Instant.now().toEpochMilli() - creationTime) > maxRetentionPeriod) {
                String indexToDelete = indexMetadata.getIndex().getName();
                // ensure index is not the current active index
                if (activeIndices.contains(indexToDelete) == false) {
                    indicesToDelete.add(indexToDelete);
                }
            }
        }
        return indicesToDelete;
    }


    /**
     * Helper function to retrieve a list of IOC indices to delete based on number of indices associated with the index pattern
     *
     * @param clusterState
     * @param totalNumIndicesDeleteByAge
     * @param activeIndices
     * @param concreteIndices
     * @return
     */
    private List<String> getIocIndicesToDeleteBySize(
            ClusterState clusterState,
            Integer totalNumIndicesDeleteByAge,
            Set<String> activeIndices,
            Set<String> concreteIndices
    ) {
        Integer numIndicesToDelete = numOfIndicesToDelete(concreteIndices.size(), totalNumIndicesDeleteByAge);
        List<String> indicesToDelete = new ArrayList<>();

        if (numIndicesToDelete > 0) {
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
            endIndex = Math.min(endIndex, concreteIndices.size());

            // grab names of indices from totalNumIndicesDeleteByAge to totalNumIndicesDeleteByAge + numIndicesToDelete
            for (int i = totalNumIndicesDeleteByAge; i < endIndex; i++) {
                // ensure index is not a current active index
                if (false == activeIndices.contains(sortedList.get(i).getKey())) {
                    indicesToDelete.add(sortedList.get(i).getKey());
                }
            }
        }
        return indicesToDelete;
    }

    /**
     * Helper function to determine how many indices should be deleted based on setting for number of indices per index pattern
     *
     * @param totalNumIndices
     * @param totalNumIndicesDeleteByAge
     * @return
     */
    private Integer numOfIndicesToDelete(Integer totalNumIndices, Integer totalNumIndicesDeleteByAge) {
        Integer maxIndicesPerIndexPattern = clusterService.getClusterSettings().get(SecurityAnalyticsSettings.IOC_MAX_INDICES_PER_INDEX_PATTERN);
        Integer numIndicesAfterDeletingByAge = totalNumIndices - totalNumIndicesDeleteByAge;
        if (numIndicesAfterDeletingByAge > maxIndicesPerIndexPattern) {
            return numIndicesAfterDeletingByAge - maxIndicesPerIndexPattern;
        }
        return 0;
    }

    private void deleteAllIocsAndSourceConfig(String saTifSourceConfigId, ActionListener<DeleteResponse> listener, SATIFSourceConfig saTifSourceConfig, Boolean isDeleted) {
        if (isDeleted == false) {
            listener.onFailure(new IllegalArgumentException("All threat intel monitors need to be deleted before deleting last threat intel source config"));
        } else {
            log.debug("All threat intel monitors are deleted or multiple threat intel source configs exist, can delete threat intel source config [{}]", saTifSourceConfigId);
            markSourceConfigAsAction(
                    saTifSourceConfig,
                    TIFJobState.DELETING,
                    ActionListener.wrap(
                            updateSaTifSourceConfigResponse -> {
                                Set<String> iocIndexPatterns = new HashSet<>();
                                if (saTifSourceConfig.getIocStoreConfig() instanceof DefaultIocStoreConfig) {
                                    // get all the index patterns
                                    DefaultIocStoreConfig defaultIocStoreConfig = (DefaultIocStoreConfig) saTifSourceConfig.getIocStoreConfig();
                                    defaultIocStoreConfig.getIocToIndexDetails().forEach(e -> iocIndexPatterns.add(e.getIndexPattern()));
                                }
                                saTifSourceConfigService.getClusterState(ActionListener.wrap(
                                        clusterStateResponse -> {
                                            Set<String> concreteIndices = SATIFSourceConfigService.getConcreteIndices(clusterStateResponse);
                                            saTifSourceConfigService.deleteAllIocIndices(concreteIndices, false, ActionListener.wrap(
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
                                            log.error("Failed to get the cluster metadata");
                                            listener.onFailure(e);
                                        }
                                ), iocIndexPatterns.toArray(new String[0]));
                            }, e -> {
                                log.error("Failed to update threat intel source config with state as {}", TIFJobState.DELETING);
                                listener.onFailure(e);
                            }
                    ));
        }
    }

    public void markSourceConfigAsAction(final SATIFSourceConfig saTifSourceConfig, TIFJobState state, ActionListener<SATIFSourceConfig> actionListener) {
        TIFJobState previousState = saTifSourceConfig.getState();
        saTifSourceConfig.setState(state);
        try {
            internalUpdateTIFSourceConfig(saTifSourceConfig, actionListener);
        } catch (Exception e) {
            log.error("Failed to mark threat intel source config from {} to {} for [{}]", previousState, state, saTifSourceConfig.getId(), e);
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

        // remove duplicates from iocTypes
        Set<String> iocTypes = new LinkedHashSet<>(saTifSourceConfigDto.getIocTypes());

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
                new ArrayList<>(iocTypes),
                saTifSourceConfigDto.isEnabledForScan()
        );
    }

    private SATIFSourceConfig updateSaTifSourceConfig(SATIFSourceConfigDto saTifSourceConfigDto, SATIFSourceConfig saTifSourceConfig) {
        // currently url download is only for default tif configs and supports only activate/deactivate. Ideally should be via an activate API
        if (URL_DOWNLOAD.equals(saTifSourceConfig.getType())) {
            return new SATIFSourceConfig(
                    saTifSourceConfig.getId(),
                    saTifSourceConfig.getVersion(),
                    saTifSourceConfig.getName(),
                    saTifSourceConfig.getFormat(),
                    saTifSourceConfig.getType(),
                    saTifSourceConfig.getDescription(),
                    saTifSourceConfig.getCreatedByUser(),
                    saTifSourceConfig.getCreatedAt(),
                    saTifSourceConfig.getSource(),
                    saTifSourceConfig.getEnabledTime(),
                    saTifSourceConfig.getLastUpdateTime(),
                    saTifSourceConfig.getSchedule(),
                    saTifSourceConfig.getState(),
                    saTifSourceConfig.getRefreshType(),
                    saTifSourceConfig.getLastRefreshedTime(),
                    saTifSourceConfig.getLastRefreshedUser(),
                    saTifSourceConfig.isEnabled(),
                    saTifSourceConfig.getIocStoreConfig(),
                    saTifSourceConfig.getIocTypes(),
                    saTifSourceConfigDto.isEnabledForScan()
            );
        }
        if (false == saTifSourceConfig.getSource().getClass().equals(saTifSourceConfigDto.getSource().getClass())) {
            throw new IllegalArgumentException("");
        }
        // remove duplicates from iocTypes
        Set<String> iocTypes = new LinkedHashSet<>(saTifSourceConfigDto.getIocTypes());
        return new SATIFSourceConfig(
                saTifSourceConfig.getId(),
                saTifSourceConfig.getVersion(),
                saTifSourceConfigDto.getName(),
                saTifSourceConfigDto.getFormat(),
                saTifSourceConfig.getType(),
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
                new ArrayList<>(iocTypes),
                saTifSourceConfigDto.isEnabledForScan()
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
