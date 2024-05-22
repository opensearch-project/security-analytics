package org.opensearch.securityanalytics.threatIntel.sacommons;

import org.opensearch.jobscheduler.spi.schedule.Schedule;
import org.opensearch.securityanalytics.threatIntel.common.FeedType;
import org.opensearch.securityanalytics.threatIntel.common.TIFJobState;

import java.time.Instant;
import java.util.Map;

/**
 * Threat intel config interface
 */
public interface TIFSourceConfig {
    String getId();

    void setId(String id);

    Long getVersion();

    void setVersion(Long version);

    String getName();

    void setName(String feedName);

    String getFeedFormat();

    void setFeedFormat(String feedFormat);

    FeedType getFeedType();

    void setFeedType(FeedType feedType);

    String getCreatedByUser();

    void setCreatedByUser(String createdByUser);

    Instant getCreatedAt();

    void setCreatedAt(Instant createdAt);

    Instant getEnabledTime();

    void setEnabledTime(Instant enabledTime);

    Instant getLastUpdateTime();

    void setLastUpdateTime(Instant lastUpdateTime);

    Schedule getSchedule();

    void setSchedule(Schedule schedule);

    TIFJobState getState();

    void setState(TIFJobState previousState);

    void enable();

    void disable();

    Map<String, Object> getIocMapStore();

    void setIocMapStore(Map<String, Object> iocMapStore);

}