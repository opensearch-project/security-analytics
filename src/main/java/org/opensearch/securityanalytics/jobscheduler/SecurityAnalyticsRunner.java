package org.opensearch.securityanalytics.jobscheduler;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.opensearch.jobscheduler.spi.JobExecutionContext;
import org.opensearch.jobscheduler.spi.ScheduledJobParameter;
import org.opensearch.jobscheduler.spi.ScheduledJobRunner;
import org.opensearch.securityanalytics.threatIntel.jobscheduler.TIFSourceConfigRunner;
import org.opensearch.securityanalytics.threatIntel.sacommons.TIFSourceConfig;

public class SecurityAnalyticsRunner implements ScheduledJobRunner {
    private static final Logger log = LogManager.getLogger(SecurityAnalyticsRunner.class);

    private static SecurityAnalyticsRunner INSTANCE;
    public static SecurityAnalyticsRunner getJobRunnerInstance() {
        if (INSTANCE != null) {
            return INSTANCE;
        }
        synchronized (SecurityAnalyticsRunner.class) {
            if (INSTANCE != null) {
                return INSTANCE;
            }
            INSTANCE = new SecurityAnalyticsRunner();
            return INSTANCE;
        }
    }
    private SecurityAnalyticsRunner() {}

    @Override
    public void runJob(ScheduledJobParameter job, JobExecutionContext context) {
        if (job instanceof TIFSourceConfig) {
            TIFSourceConfigRunner.getJobRunnerInstance().runJob(job, context);
        } else {
            String errorMessage = "Invalid job type, found " + job.getClass().getSimpleName() + "with id: " + context.getJobId();
            log.error(errorMessage);
            throw new IllegalArgumentException(errorMessage);
        }
    }
}
