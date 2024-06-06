/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.securityanalytics;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.opensearch.action.ActionRequest;
import org.opensearch.client.Client;
import org.opensearch.cluster.metadata.IndexMetadata;
import org.opensearch.cluster.metadata.IndexNameExpressionResolver;
import org.opensearch.cluster.node.DiscoveryNode;
import org.opensearch.cluster.node.DiscoveryNodes;
import org.opensearch.cluster.service.ClusterService;
import org.opensearch.common.lifecycle.LifecycleComponent;
import org.opensearch.common.settings.ClusterSettings;
import org.opensearch.common.settings.IndexScopedSettings;
import org.opensearch.common.settings.Setting;
import org.opensearch.common.settings.Settings;
import org.opensearch.common.settings.SettingsFilter;
import org.opensearch.commons.alerting.action.AlertingActions;
import org.opensearch.core.action.ActionListener;
import org.opensearch.core.action.ActionResponse;
import org.opensearch.core.common.io.stream.NamedWriteableRegistry;
import org.opensearch.core.xcontent.NamedXContentRegistry;
import org.opensearch.core.xcontent.XContentParser;
import org.opensearch.core.xcontent.XContentParserUtils;
import org.opensearch.env.Environment;
import org.opensearch.env.NodeEnvironment;
import org.opensearch.index.IndexSettings;
import org.opensearch.index.codec.CodecServiceFactory;
import org.opensearch.index.engine.EngineFactory;
import org.opensearch.index.mapper.Mapper;
import org.opensearch.indices.SystemIndexDescriptor;
import org.opensearch.jobscheduler.spi.JobSchedulerExtension;
import org.opensearch.jobscheduler.spi.ScheduledJobParser;
import org.opensearch.jobscheduler.spi.ScheduledJobRunner;
import org.opensearch.plugins.ActionPlugin;
import org.opensearch.plugins.ClusterPlugin;
import org.opensearch.plugins.EnginePlugin;
import org.opensearch.plugins.MapperPlugin;
import org.opensearch.plugins.Plugin;
import org.opensearch.plugins.SearchPlugin;
import org.opensearch.plugins.SystemIndexPlugin;
import org.opensearch.repositories.RepositoriesService;
import org.opensearch.rest.RestController;
import org.opensearch.rest.RestHandler;
import org.opensearch.script.ScriptService;
import org.opensearch.securityanalytics.action.AckAlertsAction;
import org.opensearch.securityanalytics.action.CorrelatedFindingAction;
import org.opensearch.securityanalytics.action.CreateIndexMappingsAction;
import org.opensearch.securityanalytics.action.DeleteCorrelationRuleAction;
import org.opensearch.securityanalytics.action.DeleteCustomLogTypeAction;
import org.opensearch.securityanalytics.action.DeleteDetectorAction;
import org.opensearch.securityanalytics.action.DeleteRuleAction;
import org.opensearch.securityanalytics.action.GetAlertsAction;
import org.opensearch.securityanalytics.action.GetAllRuleCategoriesAction;
import org.opensearch.securityanalytics.action.GetDetectorAction;
import org.opensearch.securityanalytics.action.GetFindingsAction;
import org.opensearch.securityanalytics.action.GetIndexMappingsAction;
import org.opensearch.securityanalytics.action.GetMappingsViewAction;
import org.opensearch.securityanalytics.action.IndexCorrelationRuleAction;
import org.opensearch.securityanalytics.action.IndexCustomLogTypeAction;
import org.opensearch.securityanalytics.action.IndexDetectorAction;
import org.opensearch.securityanalytics.action.IndexRuleAction;
import org.opensearch.securityanalytics.action.ListCorrelationsAction;
import org.opensearch.securityanalytics.action.SearchCorrelationRuleAction;
import org.opensearch.securityanalytics.action.SearchCustomLogTypeAction;
import org.opensearch.securityanalytics.action.SearchDetectorAction;
import org.opensearch.securityanalytics.action.SearchRuleAction;
import org.opensearch.securityanalytics.action.UpdateIndexMappingsAction;
import org.opensearch.securityanalytics.action.ValidateRulesAction;
import org.opensearch.securityanalytics.correlation.index.codec.CorrelationCodecService;
import org.opensearch.securityanalytics.correlation.index.mapper.CorrelationVectorFieldMapper;
import org.opensearch.securityanalytics.correlation.index.query.CorrelationQueryBuilder;
import org.opensearch.securityanalytics.indexmanagment.DetectorIndexManagementService;
import org.opensearch.securityanalytics.logtype.BuiltinLogTypeLoader;
import org.opensearch.securityanalytics.logtype.LogTypeService;
import org.opensearch.securityanalytics.mapper.IndexTemplateManager;
import org.opensearch.securityanalytics.mapper.MapperService;
import org.opensearch.securityanalytics.model.CustomLogType;
import org.opensearch.securityanalytics.model.Detector;
import org.opensearch.securityanalytics.model.DetectorInput;
import org.opensearch.securityanalytics.model.IocDao;
import org.opensearch.securityanalytics.model.Rule;
import org.opensearch.securityanalytics.model.ThreatIntelFeedData;
import org.opensearch.securityanalytics.resthandler.RestAcknowledgeAlertsAction;
import org.opensearch.securityanalytics.resthandler.RestCreateIndexMappingsAction;
import org.opensearch.securityanalytics.resthandler.RestDeleteCorrelationRuleAction;
import org.opensearch.securityanalytics.resthandler.RestDeleteCustomLogTypeAction;
import org.opensearch.securityanalytics.resthandler.RestDeleteDetectorAction;
import org.opensearch.securityanalytics.resthandler.RestDeleteRuleAction;
import org.opensearch.securityanalytics.resthandler.RestGetAlertsAction;
import org.opensearch.securityanalytics.resthandler.RestGetAllRuleCategoriesAction;
import org.opensearch.securityanalytics.resthandler.RestGetDetectorAction;
import org.opensearch.securityanalytics.resthandler.RestGetFindingsAction;
import org.opensearch.securityanalytics.resthandler.RestGetIndexMappingsAction;
import org.opensearch.securityanalytics.resthandler.RestGetMappingsViewAction;
import org.opensearch.securityanalytics.resthandler.RestIndexCorrelationRuleAction;
import org.opensearch.securityanalytics.resthandler.RestIndexCustomLogTypeAction;
import org.opensearch.securityanalytics.resthandler.RestIndexDetectorAction;
import org.opensearch.securityanalytics.resthandler.RestIndexRuleAction;
import org.opensearch.securityanalytics.resthandler.RestListCorrelationAction;
import org.opensearch.securityanalytics.resthandler.RestSearchCorrelationAction;
import org.opensearch.securityanalytics.resthandler.RestSearchCorrelationRuleAction;
import org.opensearch.securityanalytics.resthandler.RestSearchCustomLogTypeAction;
import org.opensearch.securityanalytics.resthandler.RestSearchDetectorAction;
import org.opensearch.securityanalytics.resthandler.RestSearchRuleAction;
import org.opensearch.securityanalytics.resthandler.RestUpdateIndexMappingsAction;
import org.opensearch.securityanalytics.resthandler.RestValidateRulesAction;
import org.opensearch.securityanalytics.settings.SecurityAnalyticsSettings;
import org.opensearch.securityanalytics.threatIntel.action.PutTIFJobAction;
import org.opensearch.securityanalytics.threatIntel.action.SAGetTIFSourceConfigAction;
import org.opensearch.securityanalytics.threatIntel.action.SAIndexTIFSourceConfigAction;
import org.opensearch.securityanalytics.threatIntel.action.monitor.IndexThreatIntelMonitorAction;
import org.opensearch.securityanalytics.threatIntel.action.monitor.SearchThreatIntelMonitorAction;
import org.opensearch.securityanalytics.threatIntel.common.TIFLockService;
import org.opensearch.securityanalytics.threatIntel.feedMetadata.BuiltInTIFMetadataLoader;
import org.opensearch.securityanalytics.threatIntel.jobscheduler.TIFJobRunner;
import org.opensearch.securityanalytics.threatIntel.model.SATIFSourceConfig;
import org.opensearch.securityanalytics.threatIntel.resthandler.RestGetTIFSourceConfigAction;
import org.opensearch.securityanalytics.threatIntel.resthandler.RestIndexTIFSourceConfigAction;
import org.opensearch.securityanalytics.threatIntel.resthandler.monitor.RestIndexThreatIntelMonitorAction;
import org.opensearch.securityanalytics.threatIntel.resthandler.monitor.RestSearchThreatIntelMonitorAction;
import org.opensearch.securityanalytics.threatIntel.service.DetectorThreatIntelService;
import org.opensearch.securityanalytics.threatIntel.service.SATIFSourceConfigManagementService;
import org.opensearch.securityanalytics.threatIntel.service.SATIFSourceConfigService;
import org.opensearch.securityanalytics.threatIntel.service.TIFJobParameterService;
import org.opensearch.securityanalytics.threatIntel.service.TIFJobUpdateService;
import org.opensearch.securityanalytics.threatIntel.service.ThreatIntelFeedDataService;
import org.opensearch.securityanalytics.threatIntel.transport.TransportGetTIFSourceConfigAction;
import org.opensearch.securityanalytics.threatIntel.transport.TransportIndexTIFSourceConfigAction;
import org.opensearch.securityanalytics.threatIntel.transport.TransportPutTIFJobAction;
import org.opensearch.securityanalytics.threatIntel.transport.monitor.TransportIndexThreatIntelMonitorAction;
import org.opensearch.securityanalytics.threatIntel.transport.monitor.TransportSearchThreatIntelMonitorAction;
import org.opensearch.securityanalytics.transport.TransportAcknowledgeAlertsAction;
import org.opensearch.securityanalytics.transport.TransportCorrelateFindingAction;
import org.opensearch.securityanalytics.transport.TransportCreateIndexMappingsAction;
import org.opensearch.securityanalytics.transport.TransportDeleteCorrelationRuleAction;
import org.opensearch.securityanalytics.transport.TransportDeleteCustomLogTypeAction;
import org.opensearch.securityanalytics.transport.TransportDeleteDetectorAction;
import org.opensearch.securityanalytics.transport.TransportDeleteRuleAction;
import org.opensearch.securityanalytics.transport.TransportGetAlertsAction;
import org.opensearch.securityanalytics.transport.TransportGetAllRuleCategoriesAction;
import org.opensearch.securityanalytics.transport.TransportGetDetectorAction;
import org.opensearch.securityanalytics.transport.TransportGetFindingsAction;
import org.opensearch.securityanalytics.transport.TransportGetIndexMappingsAction;
import org.opensearch.securityanalytics.transport.TransportGetMappingsViewAction;
import org.opensearch.securityanalytics.transport.TransportIndexCorrelationRuleAction;
import org.opensearch.securityanalytics.transport.TransportIndexCustomLogTypeAction;
import org.opensearch.securityanalytics.transport.TransportIndexDetectorAction;
import org.opensearch.securityanalytics.transport.TransportIndexRuleAction;
import org.opensearch.securityanalytics.transport.TransportListCorrelationAction;
import org.opensearch.securityanalytics.transport.TransportSearchCorrelationAction;
import org.opensearch.securityanalytics.transport.TransportSearchCorrelationRuleAction;
import org.opensearch.securityanalytics.transport.TransportSearchCustomLogTypeAction;
import org.opensearch.securityanalytics.transport.TransportSearchDetectorAction;
import org.opensearch.securityanalytics.transport.TransportSearchRuleAction;
import org.opensearch.securityanalytics.transport.TransportUpdateIndexMappingsAction;
import org.opensearch.securityanalytics.transport.TransportValidateRulesAction;
import org.opensearch.securityanalytics.util.CorrelationIndices;
import org.opensearch.securityanalytics.util.CorrelationRuleIndices;
import org.opensearch.securityanalytics.util.CustomLogTypeIndices;
import org.opensearch.securityanalytics.util.DetectorIndices;
import org.opensearch.securityanalytics.util.RuleIndices;
import org.opensearch.securityanalytics.util.RuleTopicIndices;
import org.opensearch.threadpool.ThreadPool;
import org.opensearch.watcher.ResourceWatcherService;

import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;
import java.util.function.Supplier;

import static org.opensearch.securityanalytics.threatIntel.model.SATIFSourceConfig.FEED_SOURCE_CONFIG_FIELD;
import static org.opensearch.securityanalytics.threatIntel.model.TIFJobParameter.THREAT_INTEL_DATA_INDEX_NAME_PREFIX;

public class SecurityAnalyticsPlugin extends Plugin implements ActionPlugin, MapperPlugin, SearchPlugin, EnginePlugin, ClusterPlugin, SystemIndexPlugin, JobSchedulerExtension {

    private static final Logger log = LogManager.getLogger(SecurityAnalyticsPlugin.class);

    public static final String PLUGINS_BASE_URI = "/_plugins/_security_analytics";
    public static final String MAPPER_BASE_URI = PLUGINS_BASE_URI + "/mappings";
    public static final String MAPPINGS_VIEW_BASE_URI = MAPPER_BASE_URI + "/view";
    public static final String FINDINGS_BASE_URI = PLUGINS_BASE_URI + "/findings";
    public static final String ALERTS_BASE_URI = PLUGINS_BASE_URI + "/alerts";
    public static final String DETECTOR_BASE_URI = PLUGINS_BASE_URI + "/detectors";
    public static final String RULE_BASE_URI = PLUGINS_BASE_URI + "/rules";
    public static final String FINDINGS_CORRELATE_URI = FINDINGS_BASE_URI + "/correlate";
    public static final String LIST_CORRELATIONS_URI = PLUGINS_BASE_URI + "/correlations";
    public static final String CORRELATION_RULES_BASE_URI = PLUGINS_BASE_URI + "/correlation/rules";
    public static final String THREAT_INTEL_BASE_URI = PLUGINS_BASE_URI + "/threat_intel";
    public static final String THREAT_INTEL_SOURCE_URI = PLUGINS_BASE_URI + "/threat_intel/source";
    public static final String THREAT_INTEL_MONITOR_URI = PLUGINS_BASE_URI + "/threat_intel/monitor";
    public static final String IOC_BASE_URI = PLUGINS_BASE_URI + "/ioc";
    public static final String IOC_FETCH_BASE_URI = IOC_BASE_URI + "/fetch";

    public static final String CUSTOM_LOG_TYPE_URI = PLUGINS_BASE_URI + "/logtype";
    public static final String JOB_INDEX_NAME = ".opensearch-sap--job";
    public static final String JOB_TYPE = "opensearch_sap_job";

    public static final Map<String, Object> TIF_JOB_INDEX_SETTING = Map.of(IndexMetadata.SETTING_NUMBER_OF_SHARDS, 1, IndexMetadata.SETTING_AUTO_EXPAND_REPLICAS, "0-all", IndexMetadata.SETTING_INDEX_HIDDEN, true);
    public static final String IOC_INDEX_NAME_BASE = ".opensearch-sap-ioc";
    public static final String IOC_ALL_INDEX_PATTERN = IOC_INDEX_NAME_BASE + "-*";
    public static final String IOC_DOMAIN_INDEX_NAME = IOC_INDEX_NAME_BASE + IocDao.IocType.DOMAIN.name().toLowerCase(Locale.ROOT);
    public static final String IOC_HASH_INDEX_NAME = IOC_INDEX_NAME_BASE + IocDao.IocType.HASH.name().toLowerCase(Locale.ROOT);
    public static final String IOC_IP_INDEX_NAME = IOC_INDEX_NAME_BASE + IocDao.IocType.IP.name().toLowerCase(Locale.ROOT);

    private CorrelationRuleIndices correlationRuleIndices;

    private DetectorIndices detectorIndices;

    private RuleTopicIndices ruleTopicIndices;

    private CorrelationIndices correlationIndices;

    private CustomLogTypeIndices customLogTypeIndices;

    private MapperService mapperService;

    private RuleIndices ruleIndices;

    private DetectorIndexManagementService detectorIndexManagementService;

    private IndexTemplateManager indexTemplateManager;

    private BuiltinLogTypeLoader builtinLogTypeLoader;

    private LogTypeService logTypeService;

    private SATIFSourceConfigService saTifSourceConfigService;

    @Override
    public Collection<SystemIndexDescriptor> getSystemIndexDescriptors(Settings settings){
        return Collections.singletonList(new SystemIndexDescriptor(THREAT_INTEL_DATA_INDEX_NAME_PREFIX, "System index used for threat intel data"));
    }



    @Override
    public Collection<Object> createComponents(Client client,
                                               ClusterService clusterService,
                                               ThreadPool threadPool,
                                               ResourceWatcherService resourceWatcherService,
                                               ScriptService scriptService,
                                               NamedXContentRegistry xContentRegistry,
                                               Environment environment,
                                               NodeEnvironment nodeEnvironment,
                                               NamedWriteableRegistry namedWriteableRegistry,
                                               IndexNameExpressionResolver indexNameExpressionResolver,
                                               Supplier<RepositoriesService> repositoriesServiceSupplier) {

        builtinLogTypeLoader = new BuiltinLogTypeLoader();
        BuiltInTIFMetadataLoader builtInTIFMetadataLoader = new BuiltInTIFMetadataLoader();
        logTypeService = new LogTypeService(client, clusterService, xContentRegistry, builtinLogTypeLoader);
        detectorIndices = new DetectorIndices(client.admin(), clusterService, threadPool);
        ruleTopicIndices = new RuleTopicIndices(client, clusterService, logTypeService);
        correlationIndices = new CorrelationIndices(client, clusterService);
        customLogTypeIndices = new CustomLogTypeIndices(client.admin(), clusterService);
        indexTemplateManager = new IndexTemplateManager(client, clusterService, indexNameExpressionResolver, xContentRegistry);
        mapperService = new MapperService(client, clusterService, indexNameExpressionResolver, indexTemplateManager, logTypeService);
        ruleIndices = new RuleIndices(logTypeService, client, clusterService, threadPool);
        correlationRuleIndices = new CorrelationRuleIndices(client, clusterService);
        ThreatIntelFeedDataService threatIntelFeedDataService = new ThreatIntelFeedDataService(clusterService, client, indexNameExpressionResolver, xContentRegistry);
        DetectorThreatIntelService detectorThreatIntelService = new DetectorThreatIntelService(threatIntelFeedDataService, client, xContentRegistry);
        TIFJobParameterService tifJobParameterService = new TIFJobParameterService(client, clusterService);
        TIFJobUpdateService tifJobUpdateService = new TIFJobUpdateService(clusterService, tifJobParameterService, threatIntelFeedDataService, builtInTIFMetadataLoader);
        TIFLockService threatIntelLockService = new TIFLockService(clusterService, client);
        saTifSourceConfigService = new SATIFSourceConfigService(client, clusterService, threadPool, xContentRegistry, threatIntelLockService);
        SATIFSourceConfigManagementService saTifSourceConfigManagementService = new SATIFSourceConfigManagementService(saTifSourceConfigService, threatIntelLockService);


        TIFJobRunner.getJobRunnerInstance().initialize(clusterService, tifJobUpdateService, tifJobParameterService, threatIntelLockService, threadPool, detectorThreatIntelService);

        return List.of(
                detectorIndices, correlationIndices, correlationRuleIndices, ruleTopicIndices, customLogTypeIndices, ruleIndices,
                mapperService, indexTemplateManager, builtinLogTypeLoader, builtInTIFMetadataLoader, threatIntelFeedDataService, detectorThreatIntelService,
                tifJobUpdateService, tifJobParameterService, threatIntelLockService, saTifSourceConfigService, saTifSourceConfigManagementService);
    }

    @Override
    public Collection<Class<? extends LifecycleComponent>> getGuiceServiceClasses() {
        return List.of(DetectorIndexManagementService.class, BuiltinLogTypeLoader.class);
    }

    @Override
    public List<RestHandler> getRestHandlers(Settings settings,
                                             RestController restController,
                                             ClusterSettings clusterSettings,
                                             IndexScopedSettings indexScopedSettings,
                                             SettingsFilter settingsFilter,
                                             IndexNameExpressionResolver indexNameExpressionResolver,
                                             Supplier<DiscoveryNodes> nodesInCluster) {
        return List.of(
                new RestAcknowledgeAlertsAction(),
                new RestUpdateIndexMappingsAction(),
                new RestCreateIndexMappingsAction(),
                new RestGetIndexMappingsAction(),
                new RestIndexDetectorAction(),
                new RestGetDetectorAction(),
                new RestSearchDetectorAction(),
                new RestDeleteDetectorAction(),
                new RestGetFindingsAction(),
                new RestGetMappingsViewAction(),
                new RestGetAlertsAction(),
                new RestIndexRuleAction(),
                new RestSearchRuleAction(),
                new RestDeleteRuleAction(),
                new RestValidateRulesAction(),
                new RestGetAllRuleCategoriesAction(),
                new RestSearchCorrelationAction(),
                new RestIndexCorrelationRuleAction(),
                new RestDeleteCorrelationRuleAction(),
                new RestListCorrelationAction(),
                new RestSearchCorrelationRuleAction(),
                new RestIndexCustomLogTypeAction(),
                new RestSearchCustomLogTypeAction(),
                new RestDeleteCustomLogTypeAction(),
                new RestIndexTIFSourceConfigAction(),
                new RestGetTIFSourceConfigAction(),
                new RestIndexThreatIntelMonitorAction(),
                new RestSearchThreatIntelMonitorAction()
        );
    }

    @Override
    public String getJobType() {
        return JOB_TYPE;
    }

    @Override
    public String getJobIndex() {
        return JOB_INDEX_NAME;
    }

    @Override
    public ScheduledJobRunner getJobRunner() {
        return TIFJobRunner.getJobRunnerInstance();
    }

    @Override
    public ScheduledJobParser getJobParser() {
        return (xcp, id, jobDocVersion) -> {
            XContentParserUtils.ensureExpectedToken(XContentParser.Token.START_OBJECT, xcp.nextToken(), xcp);
            while (xcp.nextToken() != XContentParser.Token.END_OBJECT) {
                String fieldName = xcp.currentName();
                xcp.nextToken();
                switch (fieldName) {
                    case FEED_SOURCE_CONFIG_FIELD:
                        return SATIFSourceConfig.parse(xcp, id, null);
                    default:
                        log.error("Job parser failed for [{}] in security analytics job registration", fieldName);
                        xcp.skipChildren();
                }
            }
            return null;
        };
    }

    @Override
    public List<NamedXContentRegistry.Entry> getNamedXContent() {
        return List.of(
                Detector.XCONTENT_REGISTRY,
                DetectorInput.XCONTENT_REGISTRY,
                Rule.XCONTENT_REGISTRY,
                CustomLogType.XCONTENT_REGISTRY,
                ThreatIntelFeedData.XCONTENT_REGISTRY
        );
    }

    @Override
    public Map<String, Mapper.TypeParser> getMappers() {
        return Collections.singletonMap(
                CorrelationVectorFieldMapper.CONTENT_TYPE,
                new CorrelationVectorFieldMapper.TypeParser()
        );
    }

    @Override
    public Optional<EngineFactory> getEngineFactory(IndexSettings indexSettings) {
        return Optional.empty();
    }

    @Override
    public Optional<CodecServiceFactory> getCustomCodecServiceFactory(IndexSettings indexSettings) {
        if (indexSettings.getValue(SecurityAnalyticsSettings.IS_CORRELATION_INDEX_SETTING)) {
            return Optional.of(config -> new CorrelationCodecService(config, indexSettings));
        }
        return Optional.empty();
    }

    @Override
    public List<QuerySpec<?>> getQueries() {
        return Collections.singletonList(new QuerySpec<>(CorrelationQueryBuilder.NAME, CorrelationQueryBuilder::new, CorrelationQueryBuilder::fromXContent));
    }

    @Override
    public List<Setting<?>> getSettings() {
        return List.of(
                SecurityAnalyticsSettings.INDEX_TIMEOUT,
                SecurityAnalyticsSettings.FILTER_BY_BACKEND_ROLES,
                SecurityAnalyticsSettings.ALERT_HISTORY_ENABLED,
                SecurityAnalyticsSettings.ALERT_HISTORY_ROLLOVER_PERIOD,
                SecurityAnalyticsSettings.ALERT_HISTORY_INDEX_MAX_AGE,
                SecurityAnalyticsSettings.ALERT_HISTORY_MAX_DOCS,
                SecurityAnalyticsSettings.ALERT_HISTORY_RETENTION_PERIOD,
                SecurityAnalyticsSettings.REQUEST_TIMEOUT,
                SecurityAnalyticsSettings.MAX_ACTION_THROTTLE_VALUE,
                SecurityAnalyticsSettings.FINDING_HISTORY_ENABLED,
                SecurityAnalyticsSettings.FINDING_HISTORY_MAX_DOCS,
                SecurityAnalyticsSettings.FINDING_HISTORY_INDEX_MAX_AGE,
                SecurityAnalyticsSettings.FINDING_HISTORY_ROLLOVER_PERIOD,
                SecurityAnalyticsSettings.FINDING_HISTORY_RETENTION_PERIOD,
                SecurityAnalyticsSettings.CORRELATION_HISTORY_MAX_DOCS,
                SecurityAnalyticsSettings.CORRELATION_HISTORY_INDEX_MAX_AGE,
                SecurityAnalyticsSettings.CORRELATION_HISTORY_ROLLOVER_PERIOD,
                SecurityAnalyticsSettings.CORRELATION_HISTORY_RETENTION_PERIOD,
                SecurityAnalyticsSettings.IS_CORRELATION_INDEX_SETTING,
                SecurityAnalyticsSettings.CORRELATION_TIME_WINDOW,
                SecurityAnalyticsSettings.ENABLE_AUTO_CORRELATIONS,
                SecurityAnalyticsSettings.DEFAULT_MAPPING_SCHEMA,
                SecurityAnalyticsSettings.ENABLE_WORKFLOW_USAGE,
                SecurityAnalyticsSettings.TIF_UPDATE_INTERVAL,
                SecurityAnalyticsSettings.BATCH_SIZE,
                SecurityAnalyticsSettings.THREAT_INTEL_TIMEOUT
        );
    }

    @Override
    public List<ActionHandler<? extends ActionRequest, ? extends ActionResponse>> getActions() {
        return List.of(
                new ActionPlugin.ActionHandler<>(AckAlertsAction.INSTANCE, TransportAcknowledgeAlertsAction.class),
                new ActionPlugin.ActionHandler<>(UpdateIndexMappingsAction.INSTANCE, TransportUpdateIndexMappingsAction.class),
                new ActionPlugin.ActionHandler<>(CreateIndexMappingsAction.INSTANCE, TransportCreateIndexMappingsAction.class),
                new ActionPlugin.ActionHandler<>(GetIndexMappingsAction.INSTANCE, TransportGetIndexMappingsAction.class),
                new ActionPlugin.ActionHandler<>(IndexDetectorAction.INSTANCE, TransportIndexDetectorAction.class),
                new ActionPlugin.ActionHandler<>(DeleteDetectorAction.INSTANCE, TransportDeleteDetectorAction.class),
                new ActionPlugin.ActionHandler<>(GetMappingsViewAction.INSTANCE, TransportGetMappingsViewAction.class),
                new ActionPlugin.ActionHandler<>(GetDetectorAction.INSTANCE, TransportGetDetectorAction.class),
                new ActionPlugin.ActionHandler<>(SearchDetectorAction.INSTANCE, TransportSearchDetectorAction.class),
                new ActionPlugin.ActionHandler<>(GetFindingsAction.INSTANCE, TransportGetFindingsAction.class),
                new ActionPlugin.ActionHandler<>(GetAlertsAction.INSTANCE, TransportGetAlertsAction.class),
                new ActionPlugin.ActionHandler<>(IndexRuleAction.INSTANCE, TransportIndexRuleAction.class),
                new ActionPlugin.ActionHandler<>(SearchRuleAction.INSTANCE, TransportSearchRuleAction.class),
                new ActionPlugin.ActionHandler<>(DeleteRuleAction.INSTANCE, TransportDeleteRuleAction.class),
                new ActionPlugin.ActionHandler<>(ValidateRulesAction.INSTANCE, TransportValidateRulesAction.class),
                new ActionPlugin.ActionHandler<>(GetAllRuleCategoriesAction.INSTANCE, TransportGetAllRuleCategoriesAction.class),
                new ActionPlugin.ActionHandler<>(CorrelatedFindingAction.INSTANCE, TransportSearchCorrelationAction.class),
                new ActionPlugin.ActionHandler<>(IndexCorrelationRuleAction.INSTANCE, TransportIndexCorrelationRuleAction.class),
                new ActionPlugin.ActionHandler<>(DeleteCorrelationRuleAction.INSTANCE, TransportDeleteCorrelationRuleAction.class),
                new ActionPlugin.ActionHandler<>(AlertingActions.SUBSCRIBE_FINDINGS_ACTION_TYPE, TransportCorrelateFindingAction.class),
                new ActionPlugin.ActionHandler<>(ListCorrelationsAction.INSTANCE, TransportListCorrelationAction.class),
                new ActionPlugin.ActionHandler<>(SearchCorrelationRuleAction.INSTANCE, TransportSearchCorrelationRuleAction.class),
                new ActionHandler<>(IndexCustomLogTypeAction.INSTANCE, TransportIndexCustomLogTypeAction.class),
                new ActionHandler<>(SearchCustomLogTypeAction.INSTANCE, TransportSearchCustomLogTypeAction.class),
                new ActionHandler<>(DeleteCustomLogTypeAction.INSTANCE, TransportDeleteCustomLogTypeAction.class),
                new ActionHandler<>(PutTIFJobAction.INSTANCE, TransportPutTIFJobAction.class),
                new ActionHandler<>(IndexThreatIntelMonitorAction.INSTANCE, TransportIndexThreatIntelMonitorAction.class),
                new ActionHandler<>(SearchThreatIntelMonitorAction.INSTANCE, TransportSearchThreatIntelMonitorAction.class),
                new ActionHandler<>(SAIndexTIFSourceConfigAction.INSTANCE, TransportIndexTIFSourceConfigAction.class),
                new ActionHandler<>(SAGetTIFSourceConfigAction.INSTANCE, TransportGetTIFSourceConfigAction.class)
        );
    }

    @Override
    public void onNodeStarted(DiscoveryNode localNode) {
//      Trigger initialization of log types
        logTypeService.ensureConfigIndexIsInitialized(new ActionListener<>() {
            @Override
            public void onResponse(Void unused) {
                log.info("LogType config index successfully created and builtin log types loaded");
            }

            @Override
            public void onFailure(Exception e) {
                log.warn("Failed to initialize LogType config index and builtin log types");
            }
        });
    }
}