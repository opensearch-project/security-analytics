package org.opensearch.securityanalytics.threatIntel.service;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
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
            SATIFSourceConfig saTifSourceConfig = convertToSATIFConfig(saTifSourceConfigDto, null, TIFJobState.CREATING);

            // Index threat intel source config as creating
            saTifSourceConfigService.indexTIFSourceConfig(
                    saTifSourceConfig,
                    lock,
                    ActionListener.wrap(
                            indexSaTifSourceConfigResponse -> {
                                log.debug("Indexed threat intel source config as CREATING for [{}]", saTifSourceConfig.getId());
                                // Call to download and save IOCS's, update state as AVAILABLE on success
                                saTifSourceConfig.setLastRefreshedTime(Instant.now());
                                downloadAndSaveIOCs(indexSaTifSourceConfigResponse, ActionListener.wrap(
                                        r -> {
                                            // TODO: Update the IOC map to store list of indices, sync up with @hurneyt
                                            // TODO: Only return list of ioc indices if no errors occur (no partial iocs)
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
                                            // TODO: Try to delete source config, if delete fails, return error and log
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
            // TODO: Convert response to source config dto
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
                            // TODO: listener.onFailure();
                            return;
                        }

                        if (TIFJobState.AVAILABLE.equals(retrievedSaTifSourceConfig.getState()) == false) {
                            log.error("Invalid TIF job state. Expecting {} but received {}", TIFJobState.AVAILABLE, retrievedSaTifSourceConfig.getState());
                            // TODO: listener.onFailure();
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
                                                // TODO listener.onFailure();
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
            final ActionListener<SATIFSourceConfigDto> listener
    ) {
        saTifSourceConfigService.getTIFSourceConfig(saTifSourceConfigId, ActionListener.wrap(
                saTifSourceConfig -> {
                    if (saTifSourceConfig == null) {
                        log.info("Threat intel source config [{}] does not exist", saTifSourceConfigId);
                        // TODO: listener.onfailure();
                        return;
                    }

                    // TODO: State should be either available or refresh_failed
                    if (TIFJobState.AVAILABLE.equals(saTifSourceConfig.getState()) == false) {
                        log.error("Invalid TIF job state. Expecting {} but received {}", TIFJobState.AVAILABLE, saTifSourceConfig.getState());
                        // TODO: listener.onfailure();
                        return;
                    }

                    // REFRESH FLOW
                    log.info("Refreshing IOCs and updating threat intel source config"); // place holder
                    saTifSourceConfig.setState(TIFJobState.REFRESHING);
                    saTifSourceConfig.setLastRefreshedTime(Instant.now());
                    // TODO: Index the source config
                    // TODO: download and save iocs listener should return the source config,
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
                                            // TODO: delete ioc indices that were created by this refresh
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

    /**
     *
     * @param saTifSourceConfigId
     * @param listener
     */
    public void deleteTIFSourceConfig(
            final String saTifSourceConfigId,
            final ActionListener<DeleteResponse> listener
    ) {
        saTifSourceConfigService.getTIFSourceConfig(saTifSourceConfigId, ActionListener.wrap(
                saTifSourceConfig -> {
                    if (saTifSourceConfig == null) {
                        throw new ResourceNotFoundException("No threat intel source config exists [{}]", saTifSourceConfigId);
                        // TODO: listener.onFailure(), this check may not be needed
                    }
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
                    // TODO: if error is index not found, throw exception to return docId not found instead
                    listener.onFailure(e);
                }
        ));
    }

    private void onDeleteThreatIntelMonitors(String saTifSourceConfigId, ActionListener<DeleteResponse> listener, SATIFSourceConfig saTifSourceConfig, Boolean isDeleted) {
        if (isDeleted == false) {
            listener.onFailure(new IllegalArgumentException("All threat intel monitors need to be deleted before deleting last threat intel source config"));
        } else {
            log.debug("All threat intel monitors are deleted or multiple threat intel source configs exist, can delete threat intel source config [{}]", saTifSourceConfigId);
            saTifSourceConfig.setState(TIFJobState.DELETING);
            // TODO: Index source config with new state
            // TODO: Delete all IOCs associated with source config then delete source config
            saTifSourceConfigService.deleteTIFSourceConfig(saTifSourceConfig, ActionListener.wrap(
                    deleteResponse -> {
                        log.debug("Successfully deleted threat intel source config [{}]", saTifSourceConfig.getId());
                        listener.onResponse(deleteResponse);
                    }, e -> {
                        log.error("Failed to delete threat intel source config [{}]", saTifSourceConfigId);
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
    public SATIFSourceConfig convertToSATIFConfig(SATIFSourceConfigDto saTifSourceConfigDto, IocStoreConfig iocStoreConfig, TIFJobState state) {
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

}
