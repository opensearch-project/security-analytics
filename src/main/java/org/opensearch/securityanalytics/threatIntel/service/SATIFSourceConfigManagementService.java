package org.opensearch.securityanalytics.threatIntel.service;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.opensearch.OpenSearchException;
import org.opensearch.ResourceNotFoundException;
import org.opensearch.action.delete.DeleteResponse;
import org.opensearch.action.search.SearchRequest;
import org.opensearch.action.search.SearchResponse;
import org.opensearch.common.inject.Inject;
import org.opensearch.core.action.ActionListener;
import org.opensearch.jobscheduler.spi.LockModel;
import org.opensearch.rest.RestRequest;
import org.opensearch.securityanalytics.services.STIX2IOCFetchService;
import org.opensearch.securityanalytics.threatIntel.common.TIFJobState;
import org.opensearch.securityanalytics.threatIntel.common.TIFLockService;
import org.opensearch.securityanalytics.threatIntel.model.IocStoreConfig;
import org.opensearch.securityanalytics.threatIntel.model.SATIFSourceConfig;
import org.opensearch.securityanalytics.threatIntel.model.SATIFSourceConfigDto;
import org.opensearch.securityanalytics.util.SecurityAnalyticsException;

import java.time.Instant;

/**
 * Service class for threat intel feed source config object
 */
public class SATIFSourceConfigManagementService {
    private static final Logger log = LogManager.getLogger(SATIFSourceConfigManagementService.class);
    private final SATIFSourceConfigService saTifSourceConfigService;
    private final TIFLockService lockService; //TODO: change to js impl lock
    private final STIX2IOCFetchService stix2IOCFetchService;

    /**
     * Default constructor
     *
     * @param saTifSourceConfigService the tif source config dao
     * @param lockService              the lock service
     * @param stix2IOCFetchService the service to download, and store IOCs
     */
    @Inject
    public SATIFSourceConfigManagementService(
            final SATIFSourceConfigService saTifSourceConfigService,
            final TIFLockService lockService,
            final STIX2IOCFetchService stix2IOCFetchService
    ) {
        this.saTifSourceConfigService = saTifSourceConfigService;
        this.lockService = lockService;
        this.stix2IOCFetchService = stix2IOCFetchService;
    }

    public void createOrUpdateTifSourceConfig(
            final SATIFSourceConfigDto saTifSourceConfigDto,
            final LockModel lock,
            final RestRequest.Method restMethod,
            final ActionListener<SATIFSourceConfigDto> listener
    ) {
        if (restMethod == RestRequest.Method.POST) {
            createIocAndTIFSourceConfig(saTifSourceConfigDto, lock, listener);
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
            final ActionListener<SATIFSourceConfigDto> listener
    ) {
        try {
            SATIFSourceConfig saTifSourceConfig = convertToSATIFConfig(saTifSourceConfigDto, null);

            if (TIFJobState.CREATING.equals(saTifSourceConfig.getState()) == false) {
                log.error("Invalid threat intel source config state. Expecting {} but received {}", TIFJobState.CREATING, saTifSourceConfig.getState());
                markSourceConfigAsAction(saTifSourceConfig, TIFJobState.CREATE_FAILED, ActionListener.wrap(
                        r -> {
                            log.info("Set threat intel source config as CREATE_FAILED for [{}]", saTifSourceConfig.getId());
                        }, e -> {
                            log.error("Failed to set threat intel source config as CREATE_FAILED for [{}]", saTifSourceConfig.getId());
                            listener.onFailure(e);
                        }
                ));
                return;
            }

            // Index threat intel source config as creating
            saTifSourceConfigService.indexTIFSourceConfig(
                    saTifSourceConfig,
                    lock,
                    ActionListener.wrap(
                            indexSaTifSourceConfigResponse -> {
                                log.debug("Indexed threat intel source config as CREATED for [{}]", saTifSourceConfig.getId());
                                // Call to download and save IOCS's, update state as AVAILABLE on success
                                saTifSourceConfig.setLastRefreshedTime(Instant.now());
                                downloadAndSaveIOCs(indexSaTifSourceConfigResponse, ActionListener.wrap(
                                        r -> {
                                            markSourceConfigAsAction(
                                                    saTifSourceConfig,
                                                    TIFJobState.AVAILABLE,
                                                    ActionListener.wrap(
                                                            updateSaTifSourceConfigResponse -> {
                                                                log.debug("Updated threat intel source config as AVAILABLE for [{}]", saTifSourceConfig.getId());
                                                                SATIFSourceConfigDto returnedSaTifSourceConfigDto = new SATIFSourceConfigDto(updateSaTifSourceConfigResponse);
                                                                listener.onResponse(returnedSaTifSourceConfigDto);
                                                            }, e -> {
                                                                log.error("Failed to index threat intel source config with id [{}]", saTifSourceConfig.getId());
                                                                listener.onFailure(e);
                                                            }
                                                    ));
                                        },
                                        e -> {
                                            log.error("Failed to download and save IOCs for source config [{}]", saTifSourceConfig.getId());
                                            // TODO: DELETE associated IOCS then mark the source config as create failed <- mapping
                                            markSourceConfigAsAction(saTifSourceConfig, TIFJobState.CREATE_FAILED, ActionListener.wrap(
                                                    r -> {
                                                        log.info("Set threat intel source config as CREATE_FAILED for [{}]", saTifSourceConfig.getId());
                                                    }, ex -> {
                                                        log.error("Failed to set threat intel source config as CREATE_FAILED for [{}]", saTifSourceConfig.getId());
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

    // Temp function to download and save IOCs (i.e. refresh)
    public void downloadAndSaveIOCs(SATIFSourceConfig saTifSourceConfig, ActionListener<STIX2IOCFetchService.STIX2IOCFetchResponse> actionListener) {
        // call to update or create IOCs - state can be either creating or refreshing here
            // on success, change state back to available
            // on failure, change state to refresh failed and mark source config as refresh failed
        stix2IOCFetchService.fetchIocs(saTifSourceConfig, actionListener);
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
            final SearchRequest searchRequest,
            final ActionListener<SearchResponse> listener
    ) {
        try {
            saTifSourceConfigService.searchTIFSourceConfigs(searchRequest, listener);
        } catch (Exception e) {
            listener.onFailure(e);
        }
    }

    public void updateIocAndTIFSourceConfig(
            final SATIFSourceConfigDto saTifSourceConfigDto,
            final LockModel lock,
            final ActionListener<SATIFSourceConfigDto> listener
    ) {
        try {
            saTifSourceConfigService.getTIFSourceConfig(saTifSourceConfigDto.getId(), ActionListener.wrap(
                    retrievedSaTifSourceConfig -> {
                        if (retrievedSaTifSourceConfig == null) {
                            log.info("Threat intel source config [{}] does not exist", saTifSourceConfigDto.getName());
                            return;
                        }

                        if (TIFJobState.AVAILABLE.equals(retrievedSaTifSourceConfig.getState()) == false) {
                            log.error("Invalid TIF job state. Expecting {} but received {}", TIFJobState.AVAILABLE, retrievedSaTifSourceConfig.getState());
                            // update source config and log error
                            return;
                        }

                        SATIFSourceConfig updatedSaTifSourceConfig = updateSaTifSourceConfig(saTifSourceConfigDto, retrievedSaTifSourceConfig);

                        // Call to download and save IOCS's based on new threat intel source config
                        retrievedSaTifSourceConfig.setState(TIFJobState.REFRESHING);
                        retrievedSaTifSourceConfig.setLastRefreshedTime(Instant.now());
                        downloadAndSaveIOCs(updatedSaTifSourceConfig, ActionListener.wrap(
                                r -> {
                                    updatedSaTifSourceConfig.setState(TIFJobState.AVAILABLE);
                                    updatedSaTifSourceConfig.setLastUpdateTime(Instant.now());
                                    saTifSourceConfigService.updateTIFSourceConfig(
                                            updatedSaTifSourceConfig,
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
                                            }, ex -> {
                                                log.error("Failed to set threat intel source config as REFRESH_FAILED for [{}]", updatedSaTifSourceConfig.getId());
                                                listener.onFailure(ex);
                                            }
                                    ));
                                    listener.onFailure(e);
                                })
                        );
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

    public void internalUpdateTIFSourceConfig(
            final SATIFSourceConfig saTifSourceConfig,
            final ActionListener<SATIFSourceConfig> listener //TODO: remove this if not needed
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
            final ActionListener<SATIFSourceConfigDto> listener
    ) {
        saTifSourceConfigService.getTIFSourceConfig(saTifSourceConfigId, ActionListener.wrap(
                saTifSourceConfig -> {
                    if (saTifSourceConfig == null) {
                        log.info("Threat intel source config [{}] does not exist", saTifSourceConfigId);
                        return;
                    }

                    if (TIFJobState.AVAILABLE.equals(saTifSourceConfig.getState()) == false) {
                        log.error("Invalid TIF job state. Expecting {} but received {}", TIFJobState.AVAILABLE, saTifSourceConfig.getState());
                        // update source config and log error
                        return;
                    }

                    // REFRESH FLOW
                    log.info("Refreshing IOCs and updating threat intel source config"); // place holder
                    saTifSourceConfig.setState(TIFJobState.REFRESHING);
                    saTifSourceConfig.setLastRefreshedTime(Instant.now());
                    downloadAndSaveIOCs(saTifSourceConfig, ActionListener.wrap(
                            // 1. call refresh IOC method (download and save IOCs)
                            // 1a. set state to refreshing
                            // 1b. delete old indices
                            // 1c. update or create iocs
                            r -> {
                                // 2. update source config as succeeded
                                saTifSourceConfig.setState(TIFJobState.AVAILABLE);
                                saTifSourceConfigService.updateTIFSourceConfig(saTifSourceConfig, ActionListener.wrap(
                                        saTifSourceConfigResponse -> {
                                            SATIFSourceConfigDto returnedSaTifSourceConfigDto = new SATIFSourceConfigDto(saTifSourceConfigResponse);
                                            listener.onResponse(returnedSaTifSourceConfigDto);
                                        }, e -> {
                                            log.error("Failed to update threat intel source config [{}]", saTifSourceConfig.getId());
                                            listener.onFailure(e);
                                        }
                                ));
                            }, e -> {
                                // 3. update source config as failed
                                log.error("Failed to download and save IOCs for threat intel source config [{}]", saTifSourceConfig.getId());
                                markSourceConfigAsAction(saTifSourceConfig, TIFJobState.REFRESH_FAILED, ActionListener.wrap(
                                        r -> {
                                            log.info("Set threat intel source config as REFRESH_FAILED for [{}]", saTifSourceConfig.getId());
                                        }, ex -> {
                                            log.error("Failed to set threat intel source config as REFRESH_FAILED for [{}]", saTifSourceConfig.getId());
                                            listener.onFailure(ex);
                                        }
                                ));
                                listener.onFailure(e);
                            }
                    ));
                }, e -> {
                    log.error("Failed to get threat intel source config [{}]", saTifSourceConfigId);
                    listener.onFailure(e);
                }
        ));
    }

    public void deleteTIFSourceConfig(
            final String saTifSourceConfigId,
            final ActionListener<DeleteResponse> listener
    ) {
        // TODO: Delete all IOCs associated with source config
        saTifSourceConfigService.getTIFSourceConfig(saTifSourceConfigId, ActionListener.wrap(
                saTifSourceConfig -> {
                    if (saTifSourceConfig == null) {
                        throw new ResourceNotFoundException("No threat intel source config exists [{}]", saTifSourceConfigId);
                    }

                    // Check if all threat intel monitors are deleted
                    saTifSourceConfigService.checkAndEnsureThreatIntelMonitorsDeleted(ActionListener.wrap(
                            isDeleted -> {
                                if (isDeleted == false) {
                                    throw SecurityAnalyticsException.wrap(new OpenSearchException("All threat intel monitors need to be deleted before deleting last threat intel source config"));
                                } else {
                                    log.debug("All threat intel monitors are deleted or multiple threat intel source configs exist, can delete threat intel source config [{}]", saTifSourceConfigId);
                                }
                            }, e -> {
                                log.error("Failed to check if all threat intel monitors are deleted or if multiple threat intel source configs exist");
                                listener.onFailure(e);
                            }
                    ));

                    TIFJobState previousState = saTifSourceConfig.getState();
                    saTifSourceConfig.setState(TIFJobState.DELETING);
                    saTifSourceConfigService.deleteTIFSourceConfig(saTifSourceConfig, ActionListener.wrap(
                            deleteResponse -> {
                                log.debug("Successfully deleted threat intel source config [{}]", saTifSourceConfig.getId());
                                listener.onResponse(deleteResponse);
                            }, e -> {
                                log.error("Failed to delete threat intel source config [{}]", saTifSourceConfigId);
                                if (previousState.equals(saTifSourceConfig.getState()) == false) {
                                    saTifSourceConfig.setState(previousState);
                                    internalUpdateTIFSourceConfig(saTifSourceConfig, ActionListener.wrap(
                                            r -> {
                                                log.debug("Updated threat intel source config [{}]", saTifSourceConfig.getId());
                                            }, ex -> {
                                                log.error("Failed to update threat intel source config for [{}]", saTifSourceConfigId);
                                                listener.onFailure(ex);
                                            }
                                    ));
                                }
                                listener.onFailure(e);
                            }
                    ));
                }, e -> {
                    log.error("Failed to get threat intel source config for [{}]", saTifSourceConfigId);
                    listener.onFailure(e);
                }
        ));
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
     * Converts the DTO to entity
     *
     * @param saTifSourceConfigDto
     * @return saTifSourceConfig
     */
    public SATIFSourceConfig convertToSATIFConfig(SATIFSourceConfigDto saTifSourceConfigDto, IocStoreConfig iocStoreConfig) {
        return new SATIFSourceConfig(
                saTifSourceConfigDto.getId(),
                saTifSourceConfigDto.getVersion(),
                saTifSourceConfigDto.getName(),
                saTifSourceConfigDto.getFormat(),
                saTifSourceConfigDto.getType(),
                saTifSourceConfigDto.getDescription(),
                saTifSourceConfigDto.getCreatedByUser(),
                saTifSourceConfigDto.getCreatedAt(),
                saTifSourceConfigDto.getSource(),
                saTifSourceConfigDto.getEnabledTime(),
                saTifSourceConfigDto.getLastUpdateTime(),
                saTifSourceConfigDto.getSchedule(),
                saTifSourceConfigDto.getState(),
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

}
