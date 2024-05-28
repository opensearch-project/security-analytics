package org.opensearch.securityanalytics.threatIntel.service;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.opensearch.action.StepListener;
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
    private final SATIFSourceConfigDao SaTifSourceConfigDao;
    private final TIFLockService lockService;

    /**
     * Default constructor
     * @param SaTifSourceConfigDao the tif source config dao
     * @param lockService the lock service
     */
    @Inject
    public SATIFSourceConfigService(
            final SATIFSourceConfigDao SaTifSourceConfigDao,
            final TIFLockService lockService
    ) {
        this.SaTifSourceConfigDao = SaTifSourceConfigDao;
        this.lockService = lockService;
    }

    /**
     *
     * Creates the job index if it doesn't exist and indexes the tif source config object
     *
     * @param SaTifSourceConfigDto the tif source config dto
     * @param lock the lock object
     * @param indexTimeout the index time out
     * @param listener listener that accepts a tif source config if successful
     */
    public void createIndexAndSaveTIFSourceConfig(
            final SATIFSourceConfigDto SaTifSourceConfigDto,
            final LockModel lock,
            final TimeValue indexTimeout,
            final ActionListener<SATIFSourceConfig> listener
    ) {
        try {
            SATIFSourceConfig SaTifSourceConfig = convertToSATIFConfig(SaTifSourceConfigDto);
            SaTifSourceConfig.setState(TIFJobState.AVAILABLE);
            SaTifSourceConfigDao.indexTIFSourceConfig(SaTifSourceConfig, indexTimeout, lock, new ActionListener<>() {
                @Override
                public void onResponse(SATIFSourceConfig response) {
                    SaTifSourceConfig.setId(response.getId());
                    SaTifSourceConfig.setVersion(response.getVersion());
                    listener.onResponse(SaTifSourceConfig);
                }
                @Override
                public void onFailure(Exception e) {
                    listener.onFailure(e);
                }
            });
        } catch (Exception e) {
            listener.onFailure(e);
        }
    }

    /**
     * Converts the DTO to entity
     * @param SaTifSourceConfigDto
     * @return SaTifSourceConfig
     */
    public SATIFSourceConfig convertToSATIFConfig(SATIFSourceConfigDto SaTifSourceConfigDto) {
        return new SATIFSourceConfig(
                SaTifSourceConfigDto.getId(),
                SaTifSourceConfigDto.getVersion(),
                SaTifSourceConfigDto.getName(),
                SaTifSourceConfigDto.getFeedFormat(),
                SaTifSourceConfigDto.getFeedType(),
                SaTifSourceConfigDto.getCreatedByUser(),
                SaTifSourceConfigDto.getCreatedAt(),
                SaTifSourceConfigDto.getEnabledTime(),
                SaTifSourceConfigDto.getLastUpdateTime(),
                SaTifSourceConfigDto.getSchedule(),
                SaTifSourceConfigDto.getState(),
                SaTifSourceConfigDto.getRefreshType(),
                SaTifSourceConfigDto.getLastRefreshedTime(),
                SaTifSourceConfigDto.getLastRefreshedUser(),
                SaTifSourceConfigDto.isEnabled(),
                SaTifSourceConfigDto.getIocMapStore(),
                SaTifSourceConfigDto.getIocTypes()
        );
    }

}
