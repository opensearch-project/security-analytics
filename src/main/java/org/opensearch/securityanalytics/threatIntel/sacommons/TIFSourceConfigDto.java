package org.opensearch.securityanalytics.threatIntel.sacommons;

import org.opensearch.commons.authuser.User;
import org.opensearch.jobscheduler.spi.schedule.IntervalSchedule;
import org.opensearch.jobscheduler.spi.schedule.Schedule;
import org.opensearch.securityanalytics.threatIntel.common.SourceConfigType;
import org.opensearch.securityanalytics.threatIntel.common.TIFJobState;

import java.time.Instant;
import java.util.List;

/**
 * Threat intel config dto interface
 */
public interface TIFSourceConfigDto {

    public String getId();

    Long getVersion();

    String getName();

    String getFormat();

    SourceConfigType getType();

    User getCreatedByUser();

    Instant getCreatedAt();

    Instant getEnabledTime();

    Instant getLastUpdateTime();

    Schedule getSchedule();

    TIFJobState getState();

    public List<String> getIocTypes();

    public void setIocTypes(List<String> iocTypes);
}