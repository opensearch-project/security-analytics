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
import org.opensearch.extensions.AcknowledgedResponse;
import org.opensearch.jobscheduler.spi.LockModel;
import org.opensearch.rest.RestRequest;
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
    private final SATIFSourceConfigService SaTifSourceConfigService;
    private final TIFLockService lockService; //TODO: change to js impl lock

    /**
     * Default constructor
     *
     * @param SaTifSourceConfigService the tif source config dao
     * @param lockService              the lock service
     */
    @Inject
    public SATIFSourceConfigManagementService(
            final SATIFSourceConfigService SaTifSourceConfigService,
            final TIFLockService lockService
    ) {
        this.SaTifSourceConfigService = SaTifSourceConfigService;
        this.lockService = lockService;
    }

    public void createOrUpdateTifSourceConfig(
            final SATIFSourceConfigDto SaTifSourceConfigDto,
            final LockModel lock,
            final RestRequest.Method restMethod,
            final ActionListener<SATIFSourceConfigDto> listener
    ) {
        if (restMethod == RestRequest.Method.POST) {
            createIocAndTIFSourceConfig(SaTifSourceConfigDto, lock, listener);
        } else if (restMethod == RestRequest.Method.PUT) {
            updateIocAndTIFSourceConfig(SaTifSourceConfigDto, lock, listener);
        }
    }

    /**
     * Creates the job index if it doesn't exist and indexes the tif source config object
     *
     * @param SaTifSourceConfigDto the tif source config dto
     * @param lock                 the lock object
     * @param listener             listener that accepts a tif source config if successful
     */
    public void createIocAndTIFSourceConfig(
            final SATIFSourceConfigDto SaTifSourceConfigDto,
            final LockModel lock,
            final ActionListener<SATIFSourceConfigDto> listener
    ) {
        try {
            SATIFSourceConfig SaTifSourceConfig = convertToSATIFConfig(SaTifSourceConfigDto, null);

            if (TIFJobState.CREATING.equals(SaTifSourceConfig.getState()) == false) {
                log.error("Invalid threat intel source config state. Expecting {} but received {}", TIFJobState.CREATING, SaTifSourceConfig.getState());
                markSourceConfigAsActionFailed(SaTifSourceConfig, TIFJobState.CREATE_FAILED, ActionListener.wrap(
                        r -> {
                            log.info("Set threat intel source config as CREATE_FAILED for [{}]", SaTifSourceConfig.getId());
                        }, e -> {
                            log.error("Failed to set threat intel source config as CREATE_FAILED for [{}]", SaTifSourceConfig.getId());
                            listener.onFailure(e);
                        }
                ));
                return;
            }

            // Call to download and save IOCS's, pass in Action Listener
            downloadAndSaveIOCs(SaTifSourceConfig, ActionListener.wrap(
                    r -> {
                        SaTifSourceConfig.setState(TIFJobState.AVAILABLE);
                        SaTifSourceConfigService.indexTIFSourceConfig(
                                SaTifSourceConfig,
                                lock,
                                ActionListener.wrap(
                                        SaTifSourceConfigResponse -> {
                                            SATIFSourceConfigDto returnedSaTifSourceConfigDto = new SATIFSourceConfigDto(SaTifSourceConfigResponse);
                                            listener.onResponse(returnedSaTifSourceConfigDto);
                                        }, e -> {
                                            log.error("Failed to index threat intel source config with id [{}]", SaTifSourceConfig.getId());
                                            listener.onFailure(e);
                                        }
                                ));
                    },
                    e -> {
                        log.error("Failed to download and save IOCs for source config [{}]", SaTifSourceConfig.getId());
                        markSourceConfigAsActionFailed(SaTifSourceConfig, TIFJobState.CREATE_FAILED, ActionListener.wrap(
                                r -> {
                                    log.info("Set threat intel source config as CREATE_FAILED for [{}]", SaTifSourceConfig.getId());
                                }, ex -> {
                                    log.error("Failed to set threat intel source config as CREATE_FAILED for [{}]", SaTifSourceConfig.getId());
                                    listener.onFailure(ex);
                                }
                        ));
                        listener.onFailure(e);
                    })
            );
        } catch (Exception e) {
            log.error("Failed to create IOCs and threat intel source config");
            listener.onFailure(e);
        }
    }

    // Temp function to download and save IOCs (i.e. refresh)
    public void downloadAndSaveIOCs(SATIFSourceConfig SaTifSourceConfig, ActionListener<AcknowledgedResponse> actionListener) {
        if (SaTifSourceConfig.getState() != TIFJobState.CREATING) {
            SaTifSourceConfig.setState(TIFJobState.REFRESHING);
        }
        SaTifSourceConfig.setLastRefreshedTime(Instant.now());

        // call to update or create IOCs - state can be either creating or refreshing here
        // on success, change state back to available
        // on failure, change state to refresh failed and mark source config as refresh failed
        actionListener.onResponse(null); // TODO: remove once method is called with actionListener
    }

    public void getTIFSourceConfig(
            final String SaTifSourceConfigId,
            final ActionListener<SATIFSourceConfigDto> listener
    ) {
        SaTifSourceConfigService.getTIFSourceConfig(SaTifSourceConfigId, ActionListener.wrap(
                SaTifSourceConfigResponse -> {
                    SATIFSourceConfigDto returnedSaTifSourceConfigDto = new SATIFSourceConfigDto(SaTifSourceConfigResponse);
                    listener.onResponse(returnedSaTifSourceConfigDto);
                }, e -> {
                    log.error("Failed to get threat intel source config for [{}]", SaTifSourceConfigId);
                    listener.onFailure(e);
                }
        ));
    }

    public void searchTIFSourceConfigs(
            final SearchRequest searchRequest,
            final ActionListener<SearchResponse> listener
    ) {
        try {
            SaTifSourceConfigService.searchTIFSourceConfigs(searchRequest, listener);
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
            SaTifSourceConfigService.getTIFSourceConfig(saTifSourceConfigDto.getId(), ActionListener.wrap(
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
                        downloadAndSaveIOCs(updatedSaTifSourceConfig, ActionListener.wrap(
                                r -> {
                                    updatedSaTifSourceConfig.setState(TIFJobState.AVAILABLE);
                                    updatedSaTifSourceConfig.setLastUpdateTime(Instant.now());
                                    SaTifSourceConfigService.updateTIFSourceConfig(
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
                                    markSourceConfigAsActionFailed(updatedSaTifSourceConfig, TIFJobState.REFRESH_FAILED, ActionListener.wrap(
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
                    }, e-> {
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
            final SATIFSourceConfig SaTifSourceConfig,
            final ActionListener<SATIFSourceConfig> listener //TODO: remove this if not needed
    ) {
        try {
            SaTifSourceConfig.setLastUpdateTime(Instant.now());
            SaTifSourceConfigService.updateTIFSourceConfig(SaTifSourceConfig, listener);
        } catch (Exception e) {
            log.error("Failed to update threat intel source config [{}]", SaTifSourceConfig.getId());
            listener.onFailure(e);
        }
    }

    public void refreshTIFSourceConfig(
            final String SaTifSourceConfigId,
            final ActionListener<SATIFSourceConfigDto> listener
    ) {
        SaTifSourceConfigService.getTIFSourceConfig(SaTifSourceConfigId, ActionListener.wrap(
                SaTifSourceConfig -> {
                    if (SaTifSourceConfig == null) {
                        log.info("Threat intel source config [{}] does not exist", SaTifSourceConfigId);
                        return;
                    }

                    if (TIFJobState.AVAILABLE.equals(SaTifSourceConfig.getState()) == false) {
                        log.error("Invalid TIF job state. Expecting {} but received {}", TIFJobState.AVAILABLE, SaTifSourceConfig.getState());
                        // update source config and log error
                        return;
                    }

                    // REFRESH FLOW
                    log.info("Refreshing IOCs and updating threat intel source config"); // place holder
                    downloadAndSaveIOCs(SaTifSourceConfig, ActionListener.wrap(
                            // 1. call refresh IOC method (download and save IOCs)
                            // 1a. set state to refreshing
                            // 1b. delete old indices
                            // 1c. update or create iocs
                            r -> {
                                // 2. update source config as succeeded
                                SaTifSourceConfig.setState(TIFJobState.AVAILABLE);
                                SaTifSourceConfigService.updateTIFSourceConfig(SaTifSourceConfig, ActionListener.wrap(
                                        SaTifSourceConfigResponse -> {
                                            SATIFSourceConfigDto returnedSaTifSourceConfigDto = new SATIFSourceConfigDto(SaTifSourceConfigResponse);
                                            listener.onResponse(returnedSaTifSourceConfigDto);
                                        }, e-> {
                                            log.error("Failed to update threat intel source config [{}]", SaTifSourceConfig.getId());
                                            listener.onFailure(e);
                                        }
                                ));
                            }, e -> {
                                // 3. update source config as failed
                                log.error("Failed to download and save IOCs for threat intel source config [{}]", SaTifSourceConfig.getId());
                                markSourceConfigAsActionFailed(SaTifSourceConfig, TIFJobState.REFRESH_FAILED, ActionListener.wrap(
                                        r -> {
                                            log.info("Set threat intel source config as REFRESH_FAILED for [{}]", SaTifSourceConfig.getId());
                                        }, ex -> {
                                            log.error("Failed to set threat intel source config as REFRESH_FAILED for [{}]", SaTifSourceConfig.getId());
                                            listener.onFailure(ex);
                                        }
                                ));
                                listener.onFailure(e);
                            }
                    ));
                }, e -> {
                    log.error("Failed to get threat intel source config [{}]", SaTifSourceConfigId);
                    listener.onFailure(e);
                }
        ));
    }

    public void deleteTIFSourceConfig(
            final String SaTifSourceConfigId,
            final ActionListener<DeleteResponse> listener
    ) {
        // TODO: Delete all IOCs associated with source config
        SaTifSourceConfigService.getTIFSourceConfig(SaTifSourceConfigId, ActionListener.wrap(
                SaTifSourceConfig -> {
                    if (SaTifSourceConfig == null) {
                        throw new ResourceNotFoundException("No threat intel source config exists [{}]", SaTifSourceConfigId);
                    }

                    // Check if all threat intel monitors are deleted
                    SaTifSourceConfigService.checkAndEnsureThreatIntelMonitorsDeleted(ActionListener.wrap(
                            isDeleted -> {
                                if (isDeleted == false) {
                                    throw SecurityAnalyticsException.wrap(new OpenSearchException("All threat intel monitors need to be deleted before deleting last threat intel source config"));
                                } else {
                                    log.debug("All threat intel monitors are deleted or multiple threat intel source configs exist, can delete threat intel source config [{}]", SaTifSourceConfigId);
                                }
                            }, e-> {
                                log.error("Failed to check if all threat intel monitors are deleted or if multiple threat intel source configs exist");
                                listener.onFailure(e);
                            }
                    ));

                    TIFJobState previousState = SaTifSourceConfig.getState();
                    SaTifSourceConfig.setState(TIFJobState.DELETING);
                    SaTifSourceConfigService.deleteTIFSourceConfig(SaTifSourceConfig, ActionListener.wrap(
                            deleteResponse -> {
                                log.debug("Successfully deleted threat intel source config [{}]", SaTifSourceConfig.getId());
                                listener.onResponse(deleteResponse);
                            }, e -> {
                                log.error("Failed to delete threat intel source config [{}]", SaTifSourceConfigId);
                                if (previousState.equals(SaTifSourceConfig.getState()) == false) {
                                    SaTifSourceConfig.setState(previousState);
                                    internalUpdateTIFSourceConfig(SaTifSourceConfig, ActionListener.wrap(
                                            r -> {
                                                log.debug("Updated threat intel source config [{}]", SaTifSourceConfig.getId());
                                            }, ex -> {
                                                log.error("Failed to update threat intel source config for [{}]", SaTifSourceConfigId);
                                                listener.onFailure(ex);
                                            }
                                    ));
                                }
                                listener.onFailure(e);
                            }
                    ));
                }, e -> {
                    log.error("Failed to get threat intel source config for [{}]", SaTifSourceConfigId);
                    listener.onFailure(e);
                }
        ));
    }

    public void markSourceConfigAsActionFailed(final SATIFSourceConfig SaTifSourceConfig, TIFJobState state, ActionListener<SATIFSourceConfig> actionListener) {
        SaTifSourceConfig.setState(state);
        try {
            internalUpdateTIFSourceConfig(SaTifSourceConfig, actionListener);
        } catch (Exception e) {
            log.error("Failed to mark threat intel source config as {} for [{}]", state, SaTifSourceConfig.getId(), e);
            actionListener.onFailure(e);
        }
    }

    /**
     * Converts the DTO to entity
     *
     * @param SaTifSourceConfigDto
     * @return SaTifSourceConfig
     */
    public SATIFSourceConfig convertToSATIFConfig(SATIFSourceConfigDto SaTifSourceConfigDto, IocStoreConfig iocStoreConfig) {
        return new SATIFSourceConfig(
                SaTifSourceConfigDto.getId(),
                SaTifSourceConfigDto.getVersion(),
                SaTifSourceConfigDto.getName(),
                SaTifSourceConfigDto.getFeedFormat(),
                SaTifSourceConfigDto.getSourceConfigType(),
                SaTifSourceConfigDto.getDescription(),
                SaTifSourceConfigDto.getCreatedByUser(),
                SaTifSourceConfigDto.getCreatedAt(),
                SaTifSourceConfigDto.getSource(),
                SaTifSourceConfigDto.getEnabledTime(),
                SaTifSourceConfigDto.getLastUpdateTime(),
                SaTifSourceConfigDto.getSchedule(),
                SaTifSourceConfigDto.getState(),
                SaTifSourceConfigDto.getRefreshType(),
                SaTifSourceConfigDto.getLastRefreshedTime(),
                SaTifSourceConfigDto.getLastRefreshedUser(),
                SaTifSourceConfigDto.isEnabled(),
                iocStoreConfig,
                SaTifSourceConfigDto.getIocTypes()
        );
    }

    private SATIFSourceConfig updateSaTifSourceConfig(SATIFSourceConfigDto SaTifSourceConfigDto, SATIFSourceConfig saTifSourceConfig) {
        return new SATIFSourceConfig(
                saTifSourceConfig.getId(),
                saTifSourceConfig.getVersion(),
                SaTifSourceConfigDto.getName(),
                SaTifSourceConfigDto.getFeedFormat(),
                SaTifSourceConfigDto.getSourceConfigType(),
                SaTifSourceConfigDto.getDescription(),
                saTifSourceConfig.getCreatedByUser(),
                saTifSourceConfig.getCreatedAt(),
                SaTifSourceConfigDto.getSource(),
                saTifSourceConfig.getEnabledTime(),
                saTifSourceConfig.getLastUpdateTime(),
                SaTifSourceConfigDto.getSchedule(),
                saTifSourceConfig.getState(),
                SaTifSourceConfigDto.getRefreshType(),
                saTifSourceConfig.getLastRefreshedTime(),
                saTifSourceConfig.getLastRefreshedUser(),
                SaTifSourceConfigDto.isEnabled(),
                saTifSourceConfig.getIocStoreConfig(),
                SaTifSourceConfigDto.getIocTypes()
        );
    }

}
