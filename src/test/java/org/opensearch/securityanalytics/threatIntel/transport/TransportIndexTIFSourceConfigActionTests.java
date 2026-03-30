package org.opensearch.securityanalytics.threatIntel.transport;

import org.junit.Test;
import org.opensearch.action.support.ActionFilters;
import org.opensearch.common.settings.Settings;
import org.opensearch.core.action.ActionListener;
import org.opensearch.rest.RestRequest;
import org.opensearch.securityanalytics.threatIntel.action.SAIndexTIFSourceConfigRequest;
import org.opensearch.securityanalytics.threatIntel.action.SAIndexTIFSourceConfigResponse;
import org.opensearch.securityanalytics.threatIntel.common.SourceConfigType;
import org.opensearch.securityanalytics.threatIntel.common.TIFLockService;
import org.opensearch.securityanalytics.threatIntel.model.SATIFSourceConfigDto;
import org.opensearch.securityanalytics.threatIntel.service.SATIFSourceConfigManagementService;
import org.opensearch.tasks.Task;
import org.opensearch.test.OpenSearchTestCase;
import org.opensearch.threadpool.ThreadPool;
import org.opensearch.common.util.concurrent.ThreadContext;
import org.opensearch.transport.TransportService;

import java.util.concurrent.atomic.AtomicReference;

import static org.mockito.Mockito.*;

public class TransportIndexTIFSourceConfigActionTests extends OpenSearchTestCase {

    @Test
    public void testDoExecute_blockUrlDownloadCreate() {
        TransportService transportService = mock(TransportService.class);
        ActionFilters actionFilters = mock(ActionFilters.class);
        ThreadPool threadPool = mock(ThreadPool.class);
        SATIFSourceConfigManagementService managementService = mock(SATIFSourceConfigManagementService.class);
        TIFLockService lockService = mock(TIFLockService.class);
        Settings settings = Settings.EMPTY;

        ThreadContext threadContext = new ThreadContext(Settings.EMPTY);
        when(threadPool.getThreadContext()).thenReturn(threadContext);

        TransportIndexTIFSourceConfigAction action = new TransportIndexTIFSourceConfigAction(
                transportService, actionFilters, threadPool, managementService, lockService, settings
        );

        SATIFSourceConfigDto configDto = mock(SATIFSourceConfigDto.class);
        when(configDto.getType()).thenReturn(SourceConfigType.URL_DOWNLOAD);

        SAIndexTIFSourceConfigRequest request = new SAIndexTIFSourceConfigRequest(
                "test-id", RestRequest.Method.POST, configDto
        );

        Task task = mock(Task.class);
        AtomicReference<Exception> failure = new AtomicReference<>();

        ActionListener<SAIndexTIFSourceConfigResponse> listener = ActionListener.wrap(
                r -> fail("Expected failure but got success"),
                failure::set
        );

        // Execute
        action.doExecute(task, request, listener);

        // Assert
        assertNotNull(failure.get());
        assertTrue(failure.get() instanceof UnsupportedOperationException);
        UnsupportedOperationException ex = (UnsupportedOperationException) failure.get();
        assertTrue(ex.getMessage().contains("URL_DOWNLOAD"));

        verifyNoInteractions(managementService);
        verifyNoInteractions(lockService);
    }
}
