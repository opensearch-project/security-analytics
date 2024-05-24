package org.opensearch.securityanalytics.threatIntel.service;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.opensearch.action.StepListener;
import org.opensearch.action.support.WriteRequest;
import org.opensearch.common.inject.Inject;
import org.opensearch.common.unit.TimeValue;
import org.opensearch.core.action.ActionListener;
import org.opensearch.jobscheduler.spi.LockModel;
import org.opensearch.securityanalytics.threatIntel.common.TIFJobState;
import org.opensearch.securityanalytics.threatIntel.common.TIFLockService;
import org.opensearch.securityanalytics.threatIntel.dao.SATIFSourceConfigDao;
import org.opensearch.securityanalytics.threatIntel.model.SATIFSourceConfig;
import org.opensearch.securityanalytics.threatIntel.model.SATIFSourceConfigDto;

/**
 * Service class for threat intel feed source config object
 */
public class SATIFSourceConfigService {
    private static final Logger log = LogManager.getLogger(SATIFSourceConfigService.class);
    private final SATIFSourceConfigDao satifSourceConfigDao;
    private final TIFLockService lockService;

    /**
     * Default constructor
     * @param satifSourceConfigDao the tif source config dao
     * @param lockService the lock service
     */
    @Inject
    public SATIFSourceConfigService(
            final SATIFSourceConfigDao satifSourceConfigDao,
            final TIFLockService lockService
    ) {
        this.satifSourceConfigDao = satifSourceConfigDao;
        this.lockService = lockService;
    }

    /**
     *
     * Creates the job index if it doesn't exist and indexes the tif source config object
     *
     * @param satifSourceConfigDto the tif source config dto
     * @param lock the lock object
     * @param indexTimeout the index time out
     * @param refreshPolicy the refresh policy
     * @param listener listener that accepts a tif source config if successful
     */
    public void createIndexAndSaveTIFSourceConfig(
            final SATIFSourceConfigDto satifSourceConfigDto,
            final LockModel lock,
            final TimeValue indexTimeout,
            WriteRequest.RefreshPolicy refreshPolicy,
            final ActionListener<SATIFSourceConfig> listener
    ) {
        StepListener<Void> createIndexStepListener = new StepListener<>();
        createIndexStepListener.whenComplete(v -> {
            try {
                SATIFSourceConfig satifSourceConfig = convertToSATIFConfig(satifSourceConfigDto);
                satifSourceConfig.setState(TIFJobState.AVAILABLE);
                satifSourceConfigDao.indexTIFSourceConfig(satifSourceConfig, indexTimeout, refreshPolicy, new ActionListener<>() {
                    @Override
                    public void onResponse(SATIFSourceConfig response) {
                        satifSourceConfig.setId(response.getId());
                        satifSourceConfig.setVersion(response.getVersion());
                        listener.onResponse(satifSourceConfig);
                    }
                    @Override
                    public void onFailure(Exception e) {
                        listener.onFailure(e);
                    }
                });
            } catch (Exception e) {
                listener.onFailure(e);
            }
        }, exception -> {
            lockService.releaseLock(lock);
            log.error("failed to release lock", exception);
            listener.onFailure(exception);
        });
        satifSourceConfigDao.createJobIndexIfNotExists(createIndexStepListener);
    }

    /**
     * Converts the DTO to entity
     * @param satifSourceConfigDto
     * @return satifSourceConfig
     */
    public SATIFSourceConfig convertToSATIFConfig(SATIFSourceConfigDto satifSourceConfigDto) {
        return new SATIFSourceConfig(
                satifSourceConfigDto.getId(),
                satifSourceConfigDto.getVersion(),
                satifSourceConfigDto.getName(),
                satifSourceConfigDto.getFeedFormat(),
                satifSourceConfigDto.getFeedType(),
                satifSourceConfigDto.getCreatedByUser(),
                satifSourceConfigDto.getCreatedAt(),
                satifSourceConfigDto.getEnabledTime(),
                satifSourceConfigDto.getLastUpdateTime(),
                satifSourceConfigDto.getSchedule(),
                satifSourceConfigDto.getState(),
                satifSourceConfigDto.getRefreshType(),
                satifSourceConfigDto.getLastRefreshedTime(),
                satifSourceConfigDto.getLastRefreshedUser(),
                satifSourceConfigDto.isEnabled(),
                satifSourceConfigDto.getIocMapStore(),
                satifSourceConfigDto.getIocTypes()
        );
    }

}
