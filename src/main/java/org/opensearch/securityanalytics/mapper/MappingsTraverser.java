/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package org.opensearch.securityanalytics.mapper;

import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.ListIterator;
import org.apache.commons.lang3.tuple.Pair;
import org.opensearch.cluster.metadata.MappingMetadata;
import org.opensearch.common.xcontent.json.JsonXContent;
import org.opensearch.core.xcontent.DeprecationHandler;
import org.opensearch.core.xcontent.NamedXContentRegistry;
import org.opensearch.core.xcontent.XContentParser;
import org.opensearch.index.mapper.MapperService;
import org.opensearch.securityanalytics.rules.condition.ConditionListener;

import java.io.IOException;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.HashSet;
import java.util.HashMap;
import java.util.Stack;

import static org.opensearch.securityanalytics.mapper.MapperUtils.NESTED;
import static org.opensearch.securityanalytics.mapper.MapperUtils.PROPERTIES;
import static org.opensearch.securityanalytics.mapper.MapperUtils.TYPE;
import static org.opensearch.securityanalytics.mapper.MapperUtils.ALIAS;

/**
 * This class implementats traversal of index mappings returned by core's GET _mapping.
 * {@link MappingsTraverserListener} can be setup to process all leaves. Also {@link MappingsTraverser#propertiesToSkip}
 * can be setup, to skip any nodes which contains them, during traversal
 */
public class MappingsTraverser {

    /**
     * Traverser listener used to process leaves
     */
    public interface MappingsTraverserListener {
        void onLeafVisited(Node node);
        void onError(String error);
    }

    private Map<String, Object> mappingsMap;

    private Set<String> typesToSkip = new HashSet<>();
    private List<Pair<String, String>> propertiesToSkip = new ArrayList<>();

    Stack<Node> nodeStack = new Stack<>();

    private List<MappingsTraverserListener> mappingsTraverserListeners = new ArrayList<>();

    /**
     * @param mappingMetadata Index mappings as {@link MappingMetadata}
     */
    public MappingsTraverser(MappingMetadata mappingMetadata) {
        this.mappingsMap = mappingMetadata.getSourceAsMap();
    }

    /**
     * @param mappingsMap Index mappings as {@link MappingMetadata} as Map
     * @param typesToSkip Field types which are going to be skipped during traversal
     */
    public MappingsTraverser(Map<String, Object> mappingsMap, Set<String> typesToSkip) {
        this.mappingsMap = mappingsMap;
        for(String typeValue : typesToSkip) {
            propertiesToSkip.add(Pair.of(TYPE, typeValue));
        }
    }

    /**
     * @param mappings Mappings as String. It is expected that mappings start with root element "properties"
     * @param typesToSkip Field types which are going to be skipped during traversal
     * @throws IOException
     */
    public MappingsTraverser(String mappings, Set<String> typesToSkip) throws IOException {

        for(String typeValue : typesToSkip) {
            propertiesToSkip.add(Pair.of(TYPE, typeValue));
        }
        try (
                XContentParser parser = JsonXContent.jsonXContent
                        .createParser(
                                NamedXContentRegistry.EMPTY,
                                DeprecationHandler.THROW_UNSUPPORTED_OPERATION,
                                mappings)
        ) {
            this.mappingsMap = parser.map();
        }
    }

    /**
     * @param mappings Index Mappings as String JSON
     * @param propertiesToSkip List of properties as Pair propertyName --&gt; propertyValue to skip during traversal
     * @throws IOException
     */
    public MappingsTraverser(String mappings, List<Pair<String, String>> propertiesToSkip) throws IOException {

        this.propertiesToSkip = propertiesToSkip;

        try (
                XContentParser parser = JsonXContent.jsonXContent
                        .createParser(
                                NamedXContentRegistry.EMPTY,
                                DeprecationHandler.THROW_UNSUPPORTED_OPERATION,
                                mappings)
        ) {
            this.mappingsMap = parser.map();
        }
    }

    /**
     * Adds traverser listener. This is used to process all leaves.
     * @param l Traverser listener
     */
    public void addListener(MappingsTraverserListener l) {
        this.mappingsTraverserListeners.add(l);
    }

    /**
     * Traverses mappings tree and collects all fields that are not of type "alias".
     * Nested fields are flattened.
     * @return list of fields in mappings.
     */
    public List<String> extractFlatNonAliasFields() {
        List<String> flatProperties = new ArrayList<>();
        // Setup
        this.propertiesToSkip.add(Pair.of(TYPE, ALIAS));
        this.mappingsTraverserListeners.add(new MappingsTraverserListener() {
            @Override
            public void onLeafVisited(Node node) {
                flatProperties.add(node.currentPath);
            }

            @Override
            public void onError(String error) {
                throw new IllegalArgumentException(error);
            }
        });
        // Do traverse
        traverse();

        return flatProperties;
    }

    /**
    * Traverses index mappings tree and notifies {@link MappingsTraverserListener}s when leaf is visited.
    * Before calling this function listener(s) should be setup and optionally field types to skip during traversal
    * */
    public void traverse() {
        try {

            Map<String, Object> rootProperties = (Map<String, Object>) this.mappingsMap.get(PROPERTIES);
            rootProperties.forEach((k, v) -> nodeStack.push(new Node(Map.of(k, v), null, rootProperties, "", "")));

            while (nodeStack.size() > 0) {
                Node node = nodeStack.pop();
                // visit node
                if (node.isLeaf()) {
                    Map.Entry<String, Object> elem = node.node.entrySet().iterator().next();
                    Map<String, Object> properties = (Map<String, Object>) elem.getValue();
                    // check if we should skip this node based on its property's values
                    if (shouldSkipNode(properties)) {
                        continue;
                    }
                    String fullPath = node.currentPath;
                    fullPath += (
                            fullPath.length() > 0 ?
                                    "." + elem.getKey() :
                                    "" + elem.getKey()
                    );
                    node.currentPath = fullPath;
                    notifyLeafVisited(node);
                } else {
                    Map<String, Object> children = node.getChildren();
                    String currentNodeName = node.getNodeName();
                    children.forEach((k, v) -> {
                        String currentPath =
                                node.currentPath.length() > 0 ?
                                        node.currentPath + "." + currentNodeName :
                                        currentNodeName;
                        nodeStack.push(new Node(Map.of(k, v), node, children, currentNodeName, currentPath));
                    });
                }
            }
        } catch (IllegalArgumentException e) {
            // This is coming from listeners.
            throw e;
        } catch (Exception e) {
            notifyError("Error traversing mappings tree");
        }
    }

    /**
     * Checks if node has any properties which we want to skip.
     * Properties to skip are defined as KV Pair: propertyName -> propertyValue
     * @param properties properties of node to check
     * @return boolean indicating if node contains properties from {@link MappingsTraverser#propertiesToSkip} list or not
     * */
    private boolean shouldSkipNode(Map<String, Object> properties) {
        for(Pair<String, String> e : this.propertiesToSkip) {
            String k = e.getKey();
            Object v = e.getValue();
            if (properties.containsKey(k) && properties.get(k).equals(v)) {
                return true;
            }
        }
        return false;
    }

    public Map<String, Object> traverseAndCopyWithFilter(Set<String> nodePathsToCopy) {

        Map<String, Object> outRoot = new LinkedHashMap<>(Map.of(PROPERTIES, new LinkedHashMap()));
        this.addListener(new MappingsTraverserListener() {
            @Override
            public void onLeafVisited(Node node) {
                if (nodePathsToCopy.contains(node.currentPath) == false) {
                    return;
                }
                // Collect all nodes from root to this leaf.
                List<Node> nodes = new ArrayList<>();
                Node n = node;
                nodes.add(n);
                while (n.parent != null) {
                    n = n.parent;
                    nodes.add(n);
                }
                // Iterate from root node up to this leaf and copy node in each iteration to "out" tree
                ListIterator<Node> nodesIterator = nodes.listIterator(nodes.size());
                Map<String, Object> outNode = outRoot;
                while (nodesIterator.hasPrevious()) {
                    Node currentNode = nodesIterator.previous();

                    appendNode(currentNode, outNode, !nodesIterator.hasPrevious());
                    // Move to next output node
                    outNode = (Map<String, Object>) ((Map<?, ?>) outNode.get(PROPERTIES)).get(currentNode.getNodeName());
                }
            }

            @Override
            public void onError(String error) {
                throw new IllegalArgumentException("");
            }
        });
        traverse();
        return outRoot;
    }

    /**
     * Appends src node to dst node's properties
     * @param srcNode source node
     * @param dstNode destination node where source node is appended
     * @param isSourceLeaf flag which indicated if source node is leaf
     */
    private void appendNode(Node srcNode, Map<String, Object> dstNode, boolean isSourceLeaf) {
        Map<String, Object> existingProps = (Map<String, Object>) ((Map) dstNode.get(PROPERTIES)).get(srcNode.getNodeName());
        if (existingProps == null) {
            Map<String, Object> srcNodeProps =  srcNode.getProperties();
            Map<String, Object> newProps = isSourceLeaf ?
                                            srcNodeProps :
                                            new LinkedHashMap();
            // In case of type="nested" node, we need to copy that type field too, beside properties
            if (srcNodeProps.containsKey(TYPE) && srcNodeProps.get(TYPE).equals(NESTED)) {
                ((Map) dstNode.get(PROPERTIES)).put(srcNode.getNodeName(), new LinkedHashMap(Map.of(PROPERTIES, newProps, TYPE, NESTED)));
            } else {
                // Append src node to dst node's properties
                ((Map) dstNode.get(PROPERTIES)).put(
                        srcNode.getNodeName(),
                        isSourceLeaf ? newProps : new LinkedHashMap(Map.of(PROPERTIES, newProps))
                );
            }
        }
    }

    /**
     * Traverses index mappings tree and copies it into 1-level tree with flatten nodes. (level1.level2.level3) Listeners are notified when leaves are visited,
     * just like during {@link #traverse()} call.
     * Nodes which should be skipped({@link MappingsTraverser#propertiesToSkip}) will not be copied to a new tree
     * @return Copied tree
     * */
    public Map<String, Object> traverseAndCopyAsFlat() {

        Map<String, Object> properties = new HashMap<>();

        this.addListener(new MappingsTraverserListener() {
            @Override
            public void onLeafVisited(Node node) {
                properties.put(node.currentPath, node.getProperties());
            }

            @Override
            public void onError(String error) {
                throw new IllegalArgumentException("");
            }
        });
        traverse();
        return Map.of(PROPERTIES, properties);
    }

    /**
     * Notifies {@link MappingsTraverserListener}s when error happend
     * */
    private void notifyError(String error) {
        this.mappingsTraverserListeners.forEach(
                e -> e.onError(error)
        );
    }

    /**
     * Notifies {@link MappingsTraverserListener}s when leaf is visited
     * */
    private void notifyLeafVisited(Node node) {
        this.mappingsTraverserListeners.forEach(
                e -> e.onLeafVisited(node)
        );
    }

    public Map<String, Object> getMappingsMap() {
        return mappingsMap;
    }

    static class Node {
        Map<String, Object> node;
        Node parent;
        Map<String, Object> properties;
        Map<String, Object> parentProperties;
        String parentKey;
        String currentPath;
        String name;

        public Node(Map<String, Object> node, String currentPath) {
            this.node = node;
            this.currentPath = currentPath;
        }
        public Node(Map<String, Object> node, Node parent, Map<String, Object> parentProperties, String parentKey, String currentPath) {
            this.node = node;
            this.parent = parent;
            this.parentProperties = parentProperties;
            this.currentPath = currentPath;
        }
        /**
         * @return Node name. If there is no nesting, this is equal to currentPath
         */
        public String getNodeName() {
            if (this.name == null) {
                this.name = this.node.entrySet().iterator().next().getKey();
            }
            return this.name;
        }

        /**
         * @return All children nodes of current node
         */
        public Map<String, Object> getChildren() {
            Map.Entry<String, Object> entry = this.node.entrySet().iterator().next();
            Map<String, Object> properties = (Map<String, Object>) entry.getValue();
            if (properties.containsKey(PROPERTIES)) {
                return (Map<String, Object>) properties.get(PROPERTIES);
            } else if (properties.containsKey(NESTED)) {
                return (Map<String, Object>) properties.get(NESTED);
            } else {
                return null;
            }
        }

        /**
         * @return Properties of node. This is useful to call on leaf node to get properties like "type" or others
         */
        public Map<String, Object> getProperties() {
            if (this.properties == null) {
                this.properties = (Map<String, Object>) this.node.entrySet().iterator().next().getValue();
            }
            return this.properties;
        }

        /**
         * @return True if node is a leaf node
         */
        public boolean isLeaf() {
            Map.Entry<String, Object> entry = this.node.entrySet().iterator().next();
            Map<String, Object> properties = (Map<String, Object>) entry.getValue();
            return properties.containsKey(PROPERTIES) == false &&
                    properties.containsKey(NESTED) == false;
        }

        /**
         * @return True if node is a alias
         */
        public boolean isAlias() {
            if (!isLeaf()) {
                return false;
            }
            return getProperties().containsKey(TYPE) && properties.get(TYPE).equals(ALIAS);
        }
    }

}
