/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.securityanalytics.index;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.apache.http.entity.ContentType;
import org.apache.http.entity.StringEntity;
import org.opensearch.OpenSearchStatusException;
import org.opensearch.action.admin.indices.alias.Alias;
import org.opensearch.action.admin.indices.alias.IndicesAliasesRequest;
import org.opensearch.action.admin.indices.alias.get.GetAliasesRequest;
import org.opensearch.action.admin.indices.delete.DeleteIndexRequest;
import org.opensearch.action.admin.indices.template.delete.DeleteIndexTemplateRequest;
import org.opensearch.action.bulk.BulkRequest;
import org.opensearch.action.bulk.BulkResponse;
import org.opensearch.action.support.IndicesOptions;
import org.opensearch.client.GetAliasesResponse;
import org.opensearch.client.Request;
import org.opensearch.client.RequestOptions;
import org.opensearch.client.Response;
import org.opensearch.client.ResponseException;
import org.opensearch.client.RestHighLevelClient;
import org.opensearch.client.indices.CreateIndexRequest;
import org.opensearch.client.indices.DeleteAliasRequest;
import org.opensearch.client.indices.GetIndexRequest;
import org.opensearch.client.indices.PutComposableIndexTemplateRequest;
import org.opensearch.client.indices.PutIndexTemplateRequest;
import org.opensearch.cluster.metadata.AliasMetadata;
import org.opensearch.cluster.metadata.ComposableIndexTemplate;
import org.opensearch.cluster.metadata.Template;
import org.opensearch.common.settings.Settings;
import org.opensearch.index.query.QueryBuilder;
import org.opensearch.index.reindex.BulkByScrollResponse;
import org.opensearch.index.reindex.DeleteByQueryRequest;
import org.opensearch.rest.RestRequest;
import org.opensearch.securityanalytics.exceptions.IndexAccessorException;
import org.opensearch.securityanalytics.util.ResourceReader;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.EnumSet;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

public class RHLCIndexAccessor implements IndexAccessor {
    private static final Logger log = LoggerFactory.getLogger(RHLCIndexAccessor.class);

    private static final String ROLLOVER_TEMPLATE_PATH = "ISM-policies/rollover-template.txt";
    private static final String ISM_POLICY_PATH_FORMAT = "_plugins/_ism/policies/%s";
    private static final String ISM_ATTACH_POLICY_PATH_FORMAT = "_plugins/_ism/add/%s";
    private static final String POLICY_ID_FORMAT = "{\"policy_id\":\"%s\"}";

    private final RestHighLevelClient client;
    private final ResourceReader resourceReader;
    private final ObjectMapper objectMapper;

    public RHLCIndexAccessor(final RestHighLevelClient client, final ResourceReader resourceReader, final ObjectMapper objectMapper) {
        this.client = client;
        this.resourceReader = resourceReader;
        this.objectMapper = objectMapper;
    }

    @Override
    public void createRolloverAlias(final String aliasName, final Settings settings, final Map<String, Object> rolloverConfiguration) {
        final boolean doesAliasExist = doesAliasExist(aliasName);
        if (doesAliasExist) {
            log.debug("Alias with name {} already exists. Skipping rollover alias creation", aliasName);
            return;
        }

        final String initialWriteIndex = String.format(IndexAccessor.ROLLOVER_INDEX_FORMAT, aliasName);
        final boolean doesIndexExist = doesIndexExist(initialWriteIndex);
        if (doesIndexExist) {
            log.debug("Index with name {} already exists. Skipping rollover alias creation", initialWriteIndex);
            return;
        }

        putIndexTemplate(aliasName, settings);
        createRolloverPolicyIfNotPresent(aliasName, rolloverConfiguration);
        doCreateIndex(initialWriteIndex, aliasName);
        attachPolicyToWriteIndex(aliasName);
    }

    private boolean doesAliasExist(final String aliasName) {
        if (aliasName == null) {
            return false;
        }

        final GetAliasesRequest getAliasesRequest = new GetAliasesRequest(aliasName);
        try {
            return client.indices().existsAlias(getAliasesRequest, RequestOptions.DEFAULT);
        } catch (final Exception e) {
            throw new IndexAccessorException("Failed to check if alias exists with name: " + aliasName, e);
        }
    }

    private boolean doesIndexExist(final String indexName) {
        final GetIndexRequest getIndexRequest = new GetIndexRequest(indexName);
        try {
            return client.indices().exists(getIndexRequest, RequestOptions.DEFAULT);
        } catch (final Exception e) {
            throw new IndexAccessorException("Failed to check if index exists with name: " + indexName, e);
        }
    }

    private void putIndexTemplate(final String aliasName, final Settings settings) {
        final String indexPattern = String.format(IndexAccessor.INDEX_PATTERN_FORMAT, aliasName);

        try {
            final Template template = new Template(settings, null, null);
            final ComposableIndexTemplate composableIndexTemplate = new ComposableIndexTemplate(List.of(indexPattern), template, null, null, null, null);
            final PutComposableIndexTemplateRequest putIndexTemplateRequest = new PutComposableIndexTemplateRequest()
                    .name(aliasName)
                    .indexTemplate(composableIndexTemplate);
            client.indices().putIndexTemplate(putIndexTemplateRequest, RequestOptions.DEFAULT);
        } catch (final Exception e) {
            throw new IndexAccessorException("Failed to create index template for alias: " + aliasName, e);
        }
    }

    private void createRolloverPolicyIfNotPresent(final String policyName, final Map<String, Object> rolloverConfiguration) {
        final boolean doesISMPolicyExist = doesISMPolicyExist(policyName);
        if (doesISMPolicyExist) {
            log.debug("ISM policy with name {} already exists. Skipping ISM policy creation", policyName);
        } else {
            createRolloverPolicy(policyName, rolloverConfiguration);
        }
    }

    private boolean doesISMPolicyExist(final String policyName) {
        final Request checkExistsRequest = new Request(RestRequest.Method.HEAD.name(), String.format(ISM_POLICY_PATH_FORMAT, policyName));
        final Response checkExistsResponse;
        try {
            checkExistsResponse = client.getLowLevelClient().performRequest(checkExistsRequest);
            return checkExistsResponse.getStatusLine().getStatusCode() == 200;
        } catch (final Exception e) {
            throw new IndexAccessorException("Exception checking if ISM policy exists with name: " + policyName, e);
        }
    }

    private void createRolloverPolicy(final String policyName, final Map<String, Object> rolloverConfiguration) {
        final Request createRequest = new Request(RestRequest.Method.PUT.name(), String.format(ISM_POLICY_PATH_FORMAT, policyName));
        try {
            final String rolloverPolicy = getISMPolicy(policyName, rolloverConfiguration);
            final StringEntity stringEntity = new StringEntity(rolloverPolicy, ContentType.APPLICATION_JSON);
            createRequest.setEntity(stringEntity);
            client.getLowLevelClient().performRequest(createRequest);
        } catch (final Exception e) {
            throw new IndexAccessorException("Exception creating rollover policy: " + policyName, e);
        }
    }

    private String getISMPolicy(final String policyName, final Map<String, Object> rolloverConfiguration) {
        final String policyTemplate = resourceReader.readResourceAsString(ROLLOVER_TEMPLATE_PATH);
        final String rolloverConfigurationAsString = getRolloverConfigurationAsString(rolloverConfiguration);
        return String.format(policyTemplate, policyName, rolloverConfigurationAsString, policyName);
    }

    private String getRolloverConfigurationAsString(final Map<String, Object> rolloverConfiguration) {
        try {
            return objectMapper.writeValueAsString(rolloverConfiguration);
        } catch (final Exception e) {
            throw new IndexAccessorException("Failed to serialize rollover configuration: " + rolloverConfiguration, e);
        }
    }

    private void doCreateIndex(final String indexName, final String aliasName) {
        final CreateIndexRequest createIndexRequest = new CreateIndexRequest(indexName)
                .alias(new Alias(aliasName).writeIndex(true));

        try {
            client.indices().create(createIndexRequest, RequestOptions.DEFAULT);
        } catch (final Exception e) {
            throw new IndexAccessorException("Exception creating index: " + indexName, e);
        }
    }

    // ISM ignores hidden and system indices so we must manually attach the policy to the alias
    private void attachPolicyToWriteIndex(final String aliasName) {
        System.out.println(aliasName);

        final GetAliasesRequest getAliasesRequest = new GetAliasesRequest();
        final String writeIndex;
        try {
            final GetAliasesResponse getAliasesResponse = client.indices().getAlias(getAliasesRequest, RequestOptions.DEFAULT);
            System.out.println(getAliasesResponse.getError());
            System.out.println(getAliasesResponse.getAliases().size());
            final Optional<String> optionalWriteIndex = getAliasesResponse.getAliases().entrySet().stream()
                    .peek(mapEntry -> System.out.println("eval " + mapEntry.getKey()))
                    .filter(mapEntry -> isWriteIndex(mapEntry.getValue(), aliasName))
                    .map(Map.Entry::getKey)
                    .findFirst();

            if (optionalWriteIndex.isEmpty()) {
                throw new IndexAccessorException("No write index found for alias: " + aliasName);
            }

            writeIndex = optionalWriteIndex.get();
        } catch (final Exception e) {
            throw new IndexAccessorException("Failed to determine write index for alias: " + aliasName, e);
        }

        final Request attachPolicyRequest = new Request(RestRequest.Method.POST.name(), String.format(ISM_ATTACH_POLICY_PATH_FORMAT, writeIndex));

        try {
            final String policyValue = String.format(POLICY_ID_FORMAT, aliasName);
            final StringEntity stringEntity = new StringEntity(policyValue, ContentType.APPLICATION_JSON);
            attachPolicyRequest.setEntity(stringEntity);
            client.getLowLevelClient().performRequest(attachPolicyRequest);
        } catch (final Exception e) {
            throw new IndexAccessorException("Failed to attach policy to alias: " + aliasName, e);
        }
    }

    private boolean isWriteIndex(final Set<AliasMetadata> aliasMetadata, final String aliasName) {
        final Optional<AliasMetadata> optionalRelevantAliasMetadata = aliasMetadata.stream()
                .filter(alias -> alias.getAlias().equals(aliasName))
                .findFirst();

        if (optionalRelevantAliasMetadata.isEmpty()) {
            return false;
        }

        final AliasMetadata relevantAliasMetadata = optionalRelevantAliasMetadata.get();
        return relevantAliasMetadata.writeIndex();
    }

    @Override
    public void deleteRolloverAlias(final String aliasName) {
        deleteAlias(aliasName);
        deleteRolloverPolicy(aliasName);
        deleteIndexTemplate(aliasName);

        final String indexPattern = String.format(IndexAccessor.INDEX_PATTERN_FORMAT, aliasName);
        deleteIndex(indexPattern);
    }

    private void deleteAlias(final String aliasName) {
        final DeleteAliasRequest deleteAliasRequest = new DeleteAliasRequest(String.format(ROLLOVER_INDEX_FORMAT, aliasName), aliasName);

        try {
            client.indices().deleteAlias(deleteAliasRequest, RequestOptions.DEFAULT);
        } catch (final Exception e) {
            if (e instanceof OpenSearchStatusException &&
                    (e.getMessage().contains("aliases_not_found_exception") || e.getMessage().contains("index_not_found_exception"))) {
                log.info("Alias with name {} not found, assuming it was already deleted", aliasName);
                return;
            }

            throw new IndexAccessorException("Exception deleting alias: " + aliasName, e);
        }
    }

    private void deleteRolloverPolicy(final String policyName) {
        final Request deleteRequest = new Request(RestRequest.Method.DELETE.name(), String.format(ISM_POLICY_PATH_FORMAT, policyName));

        try {
            client.getLowLevelClient().performRequest(deleteRequest);
        } catch (final Exception e) {
            if (e instanceof ResponseException && ((ResponseException) e).getResponse().getStatusLine().getStatusCode() == 404) {
                log.info("Policy with name {} was not found. Assuming it was already deleted", policyName);
                return;
            }
            throw new IndexAccessorException("Exception deleting rollover policy: " + policyName, e);
        }
    }

    private void deleteIndexTemplate(final String templateName) {
        final DeleteIndexTemplateRequest deleteIndexTemplateRequest = new DeleteIndexTemplateRequest(templateName);

        try {
            client.indices().deleteTemplate(deleteIndexTemplateRequest, RequestOptions.DEFAULT);
        } catch (final Exception e) {
            if (e instanceof OpenSearchStatusException && e.getMessage().contains("index_template_missing_exception")) {
                log.info("Template with name {} not found, assuming it was already deleted", templateName);
                return;
            }
            throw new IndexAccessorException("Exception deleting index template: " + templateName, e);
        }
    }

    private void deleteIndex(final String indexName) {
        final DeleteIndexRequest deleteIndexRequest = new DeleteIndexRequest(indexName);

        try {
            client.indices().delete(deleteIndexRequest, RequestOptions.DEFAULT);
        } catch (final Exception e) {
            if (e instanceof OpenSearchStatusException && e.getMessage().contains("index_not_found_exception")) {
                log.info("Index with name {} not found, assuming it was already deleted", indexName);
                return;
            }

            throw new IndexAccessorException("Exception deleting index: " + indexName, e);
        }
    }

    @Override
    public BulkByScrollResponse deleteByQuery(final String indexName, final QueryBuilder queryBuilder) {
        final DeleteByQueryRequest deleteByQueryRequest = new DeleteByQueryRequest(indexName)
                .setQuery(queryBuilder)
                .setRefresh(true);

        try {
            return client.deleteByQuery(deleteByQueryRequest, RequestOptions.DEFAULT);
        } catch (final Exception e) {
            throw new IndexAccessorException("Exception deleting by query for index: " + indexName, e);
        }
    }

    @Override
    public BulkResponse bulk(final BulkRequest bulkRequest) {
        try {
            return client.bulk(bulkRequest, RequestOptions.DEFAULT);
        } catch (final Exception e) {
            throw new IndexAccessorException("Exception making bulk request", e);
        }
    }
}
