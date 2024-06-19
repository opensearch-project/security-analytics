package org.opensearch.securityanalytics.threatIntel.service;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.opensearch.OpenSearchException;
import org.opensearch.OpenSearchStatusException;
import org.opensearch.ResourceNotFoundException;
import org.opensearch.action.delete.DeleteResponse;
import org.opensearch.action.search.SearchRequest;
import org.opensearch.action.search.SearchResponse;
import org.opensearch.cluster.routing.Preference;
import org.opensearch.common.inject.Inject;
import org.opensearch.common.xcontent.LoggingDeprecationHandler;
import org.opensearch.common.xcontent.XContentFactory;
import org.opensearch.common.xcontent.XContentType;
import org.opensearch.core.action.ActionListener;
import org.opensearch.core.common.bytes.BytesReference;
import org.opensearch.core.rest.RestStatus;
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
import org.opensearch.securityanalytics.SecurityAnalyticsPlugin;
import org.opensearch.securityanalytics.services.STIX2IOCFetchService;
import org.opensearch.securityanalytics.threatIntel.common.TIFJobState;
import org.opensearch.securityanalytics.threatIntel.common.TIFLockService;
import org.opensearch.securityanalytics.threatIntel.model.IocStoreConfig;
import org.opensearch.securityanalytics.threatIntel.model.SATIFSourceConfig;
import org.opensearch.securityanalytics.threatIntel.model.SATIFSourceConfigDto;

import java.time.Instant;
import java.util.Locale;

/**
 * Service class for threat intel feed source config object
 */
public class SATIFSourceConfigManagementService {
    private static final Logger log = LogManager.getLogger(SATIFSourceConfigManagementService.class);
    private final SATIFSourceConfigService saTifSourceConfigService;
    private final TIFLockService lockService; //TODO: change to js impl lock
    private final STIX2IOCFetchService stix2IOCFetchService;
    private final NamedXContentRegistry xContentRegistry;

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
            NamedXContentRegistry xContentRegistry

    ) {
        this.saTifSourceConfigService = saTifSourceConfigService;
        this.lockService = lockService;
        this.stix2IOCFetchService = stix2IOCFetchService;
        this.xContentRegistry = xContentRegistry;
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
                                log.debug("Indexed threat intel source config as CREATING for [{}]", indexSaTifSourceConfigResponse.getId());
                                // Call to download and save IOCS's, update state as AVAILABLE on success
                                indexSaTifSourceConfigResponse.setLastRefreshedTime(Instant.now());
                                downloadAndSaveIOCs(indexSaTifSourceConfigResponse, ActionListener.wrap(
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

    // Temp function to download and save IOCs (i.e. refresh)
    public void downloadAndSaveIOCs(SATIFSourceConfig saTifSourceConfig, ActionListener<STIX2IOCFetchService.STIX2IOCFetchResponse> actionListener) {
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
            SearchRequest newSearchRequest = getSearchRequest(searchRequest);

            // convert search response to threat intel source config dtos
            saTifSourceConfigService.searchTIFSourceConfigs(newSearchRequest, ActionListener.wrap(
                    searchResponse -> {
                        for (SearchHit hit: searchResponse.getHits()) {
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
                        log.error("Failed to fetch all threat intel source configs for search request [{}]", searchRequest, e);
                        listener.onFailure(e);
                    }
            ));
        } catch (Exception e) {
            log.error("Failed to search and parse all threat intel source configs");
            listener.onFailure(e);
        }
    }

    private static SearchRequest getSearchRequest(SearchRequest searchRequest) {
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
                                                listener.onFailure(new OpenSearchException("Set threat intel source config as REFRESH_FAILED for [{}]", saTifSourceConfigDto.getId()));
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
                    if (TIFJobState.AVAILABLE.equals(saTifSourceConfig.getState()) == false && TIFJobState.REFRESH_FAILED.equals(saTifSourceConfig.getState()) == false) {
                        log.error("Invalid TIF job state. Expecting {} or {} but received {}", TIFJobState.AVAILABLE, TIFJobState.REFRESH_FAILED, saTifSourceConfig.getState());
                        listener.onFailure(new OpenSearchException("Invalid TIF job state. Expecting {} or {} but received {}", TIFJobState.AVAILABLE, TIFJobState.REFRESH_FAILED, saTifSourceConfig.getState()));
                        return;
                    }

                    // REFRESH FLOW
                    log.info("Refreshing IOCs and updating threat intel source config"); // place holder
                    markSourceConfigAsAction(saTifSourceConfig, TIFJobState.REFRESHING, ActionListener.wrap(
                            updatedSourceConfig -> {
                                // TODO: download and save iocs listener should return the source config, sync up with @hurneyt
                                downloadAndSaveIOCs(updatedSourceConfig, ActionListener.wrap(
                                        // 1. call refresh IOC method (download and save IOCs)
                                        // 1a. set state to refreshing
                                        // 1b. delete old indices
                                        // 1c. update or create iocs
                                        response -> {
                                            // 2. update source config as succeeded
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
                                        }, e -> {
                                            // 3. update source config as failed
                                            log.error("Failed to download and save IOCs for threat intel source config [{}]", updatedSourceConfig.getId());
                                            markSourceConfigAsAction(updatedSourceConfig, TIFJobState.REFRESH_FAILED, ActionListener.wrap(
                                                    r -> {
                                                        log.debug("Set threat intel source config as REFRESH_FAILED for [{}]", updatedSourceConfig.getId());
                                                        listener.onFailure(new OpenSearchException("Set threat intel source config as REFRESH_FAILED for [{}]", updatedSourceConfig.getId()));
                                                    }, ex -> {
                                                        log.error("Failed to set threat intel source config as REFRESH_FAILED for [{}]", updatedSourceConfig.getId());
                                                        listener.onFailure(ex);
                                                    }
                                            ));
                                            listener.onFailure(e);
                                        }));
                                }, ex -> {
                                log.error("Failed to set threat intel source config as REFRESHING for [{}]", saTifSourceConfig.getId());
                                listener.onFailure(ex);
                            }
                    ));
                }, e -> {
                    log.error("Failed to get threat intel source config [{}]", saTifSourceConfigId);
                    listener.onFailure(e);
                }
        ));
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
                                // TODO: Delete all IOCs associated with source config then delete source config, sync up with @hurneyt
                                saTifSourceConfigService.deleteTIFSourceConfig(saTifSourceConfig, ActionListener.wrap(
                                        deleteResponse -> {
                                            log.debug("Successfully deleted threat intel source config [{}]", saTifSourceConfig.getId());
                                            listener.onResponse(deleteResponse);
                                        }, e -> {
                                            log.error("Failed to delete threat intel source config [{}]", saTifSourceConfigId);
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
