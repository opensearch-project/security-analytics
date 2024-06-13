package org.opensearch.securityanalytics.threatIntel.sacommons;

import org.opensearch.jobscheduler.spi.schedule.IntervalSchedule;
import org.opensearch.securityanalytics.threatIntel.common.SourceConfigType;
import org.opensearch.securityanalytics.threatIntel.common.TIFJobState;
import org.opensearch.securityanalytics.threatIntel.model.IocStoreConfig;

import java.time.Instant;
import java.util.List;

/**
 * Threat intel config dto interface
 */
public interface TIFSourceConfigDto {

    public String getId();

    public void setId(String id);

    Long getVersion();

    void setVersion(Long version);

    String getName();

    void setName(String feedName);

    String getFeedFormat();

    void setFeedFormat(String feedFormat);

    SourceConfigType getFeedType();

    void setFeedType(SourceConfigType sourceConfigType);

    String getCreatedByUser();

    void setCreatedByUser(String createdByUser);

    Instant getCreatedAt();

    void setCreatedAt(Instant createdAt);

    Instant getEnabledTime();

    void setEnabledTime(Instant enabledTime);

    Instant getLastUpdateTime();

    void setLastUpdateTime(Instant lastUpdateTime);

    IntervalSchedule getSchedule();

    void setSchedule(IntervalSchedule schedule);

    TIFJobState getState();

    void setState(TIFJobState previousState);

    void enable();

    void disable();

    public List<String> getIocTypes();

    public void setIocTypes(List<String> iocTypes);
}