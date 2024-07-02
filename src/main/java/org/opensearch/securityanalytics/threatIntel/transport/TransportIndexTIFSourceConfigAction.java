/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package org.opensearch.securityanalytics.threatIntel.transport;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.opensearch.OpenSearchStatusException;
import org.opensearch.action.support.ActionFilters;
import org.opensearch.action.support.HandledTransportAction;
import org.opensearch.common.inject.Inject;
import org.opensearch.common.settings.Settings;
import org.opensearch.commons.authuser.User;
import org.opensearch.core.action.ActionListener;
import org.opensearch.core.rest.RestStatus;
import org.opensearch.securityanalytics.settings.SecurityAnalyticsSettings;
import org.opensearch.securityanalytics.threatIntel.action.SAIndexTIFSourceConfigAction;
import org.opensearch.securityanalytics.threatIntel.action.SAIndexTIFSourceConfigRequest;
import org.opensearch.securityanalytics.threatIntel.action.SAIndexTIFSourceConfigResponse;
import org.opensearch.securityanalytics.threatIntel.common.TIFLockService;
import org.opensearch.securityanalytics.threatIntel.model.SATIFSourceConfigDto;
import org.opensearch.securityanalytics.threatIntel.service.SATIFSourceConfigManagementService;
import org.opensearch.securityanalytics.transport.SecureTransportAction;
import org.opensearch.securityanalytics.util.SecurityAnalyticsException;
import org.opensearch.tasks.Task;
import org.opensearch.threadpool.ThreadPool;
import org.opensearch.transport.TransportService;

import java.util.ConcurrentModificationException;

import static org.opensearch.securityanalytics.threatIntel.common.TIFLockService.LOCK_DURATION_IN_SECONDS;

/**
 * Transport action to create threat intel feeds source config object and save IoCs
 */
public class TransportIndexTIFSourceConfigAction extends HandledTransportAction<SAIndexTIFSourceConfigRequest, SAIndexTIFSourceConfigResponse> implements SecureTransportAction {
    private static final Logger log = LogManager.getLogger(TransportIndexTIFSourceConfigAction.class);
    private final SATIFSourceConfigManagementService saTifSourceConfigManagementService;
    private final TIFLockService lockService;
    private final ThreadPool threadPool;
    private final Settings settings;
    private volatile Boolean filterByEnabled;

    /**
     * Default constructor
     *
     * @param transportService the transport service
     * @param actionFilters    the action filters
     * @param threadPool       the thread pool
     * @param lockService      the lock service
     */
    @Inject
    public TransportIndexTIFSourceConfigAction(
            final TransportService transportService,
            final ActionFilters actionFilters,
            final ThreadPool threadPool,
            final SATIFSourceConfigManagementService saTifSourceConfigManagementService,
            final TIFLockService lockService,
            final Settings settings
    ) {
        super(SAIndexTIFSourceConfigAction.NAME, transportService, actionFilters, SAIndexTIFSourceConfigRequest::new);
        this.threadPool = threadPool;
        this.saTifSourceConfigManagementService = saTifSourceConfigManagementService;
        this.lockService = lockService;
        this.settings = settings;
        this.filterByEnabled = SecurityAnalyticsSettings.FILTER_BY_BACKEND_ROLES.get(this.settings);
    }


    @Override
    protected void doExecute(final Task task, final SAIndexTIFSourceConfigRequest request, final ActionListener<SAIndexTIFSourceConfigResponse> listener) {
        // validate user
        User user = readUserFromThreadContext(this.threadPool);
        String validateBackendRoleMessage = validateUserBackendRoles(user, this.filterByEnabled);

        if (!"".equals(validateBackendRoleMessage)) {
            listener.onFailure(SecurityAnalyticsException.wrap(new OpenSearchStatusException(validateBackendRoleMessage, RestStatus.FORBIDDEN)));
            return;
        }
        retrieveLockAndCreateTIFConfig(request, listener, user);
    }

    private void retrieveLockAndCreateTIFConfig(SAIndexTIFSourceConfigRequest request, ActionListener<SAIndexTIFSourceConfigResponse> listener, User user) {
        try {
            lockService.acquireLock(request.getTIFConfigDto().getId(), LOCK_DURATION_IN_SECONDS, ActionListener.wrap(lock -> {
                if (lock == null) {
                    listener.onFailure(
                            new ConcurrentModificationException("another processor is holding a lock on the resource. Try again later")
                    );
                    log.error("another processor is a lock, BAD_REQUEST error", RestStatus.BAD_REQUEST);
                    return;
                }
                try {
                    SATIFSourceConfigDto saTifSourceConfigDto = request.getTIFConfigDto();
                    saTifSourceConfigManagementService.createOrUpdateTifSourceConfig(
                            saTifSourceConfigDto,
                            lock,
                            request.getMethod(),
                            user,
                            ActionListener.wrap(
                                    saTifSourceConfigDtoResponse -> {
                                        lockService.releaseLock(lock);
                                        listener.onResponse(new SAIndexTIFSourceConfigResponse(
                                                saTifSourceConfigDtoResponse.getId(),
                                                saTifSourceConfigDtoResponse.getVersion(),
                                                RestStatus.OK,
                                                saTifSourceConfigDtoResponse
                                        ));
                                    }, e -> {
                                        lockService.releaseLock(lock);
                                        log.error("Failed to create IOCs and threat intel source config");
                                        listener.onFailure(e);
                                    }

                            )
                    );
                } catch (Exception e) {
                    lockService.releaseLock(lock);
                    listener.onFailure(e);
                    log.error("listener failed when executing", e);
                }
            }, exception -> {
                listener.onFailure(exception);
                log.error("execution failed", exception);
            }));
        } catch (Exception e) {
            log.error("Failed to acquire lock for job", e);
            listener.onFailure(e);
        }
    }
}

