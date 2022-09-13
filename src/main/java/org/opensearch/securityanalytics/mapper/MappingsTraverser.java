package org.opensearch.securityanalytics.mapper;

import org.opensearch.cluster.metadata.MappingMetadata;
import org.opensearch.common.xcontent.DeprecationHandler;
import org.opensearch.common.xcontent.NamedXContentRegistry;
import org.opensearch.common.xcontent.XContentParser;
import org.opensearch.common.xcontent.json.JsonXContent;
import org.opensearch.securityanalytics.rules.condition.ConditionListener;

import java.io.IOException;
import java.util.*;

import static org.opensearch.securityanalytics.mapper.MapperUtils.NESTED;
import static org.opensearch.securityanalytics.mapper.MapperUtils.PROPERTIES;
import static org.opensearch.securityanalytics.mapper.MapperUtils.TYPE;
import static org.opensearch.securityanalytics.mapper.MapperUtils.ALIAS;

/**
 * This class implementats traversal of index mappings returned by core's GetMapping {@link ConditionListener},
 * which can be extended to create a listener which only needs to handle a subset
 * of the available methods.
 */
public class MappingsTraverser {

    /**
     * Traverser listener used to process leaves
     */
    public interface MappingsTraverserListener {
        void onLeafVisited(Node node);
    }

    private Map<String, Object> mappingsMap;

    private Set<String> typesToSkip = new HashSet<>();

    Stack<Node> nodeStack = new Stack<>();

    private List<MappingsTraverserListener> mappingsTraverserListeners = new ArrayList<>();

    /**
     * @param mappingMetadata Index mappings as {@link MappingMetadata}
     */
    public MappingsTraverser(MappingMetadata mappingMetadata) {
        this.mappingsMap = mappingMetadata.getSourceAsMap();
    }

    /**
     * @param mappingsMap Index mappings as {@link MappingMetadata}
     * @param typesToSkip Field types which are going to be skipped during traversal
     */
    public MappingsTraverser(Map<String, Object> mappingsMap, Set<String> typesToSkip) {
        this.mappingsMap = mappingsMap;
        this.typesToSkip = typesToSkip;
    }

    /**
     * @param mappings Mappings as String. It is expected that mappings start with root element "properties"
     * @param typesToSkip Field types which are going to be skipped during traversal
     * @throws IOException
     */
    public MappingsTraverser(String mappings, Set<String> typesToSkip) throws IOException {

        this.typesToSkip = typesToSkip;

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
        this.typesToSkip.add(ALIAS);
        this.mappingsTraverserListeners.add((node) -> flatProperties.add(node.currentPath));
        // Do traverse
        traverse();

        return flatProperties;
    }

    /**
    * Traverses index mappings tree and notifies {@link MappingsTraverserListener}s when leaf is visited.
    * Before calling this function listener(s) should be setup and optionally field types to skip during traversal
    * */
    public void traverse() {
        Map<String, Object> rootProperties = (Map<String, Object>) this.mappingsMap.get(PROPERTIES);
        rootProperties.forEach((k, v) -> nodeStack.push(new Node(Map.of(k, v), "")));

        while (nodeStack.size() > 0) {
            Node node = nodeStack.pop();
            // visit node
            if (node.isLeaf()) {
                Map.Entry<String, Object> elem = node.node.entrySet().iterator().next();
                Map<String, Object> properties = (Map<String, Object>) elem.getValue();
                // check if we should skip this property type
                if (typesToSkip.contains(properties.get(TYPE))) {
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
                    nodeStack.push(new Node(Map.of(k, v), currentPath));
                });
            }
        }
    }
    /**
     * Notifies {@link MappingsTraverserListener}s when leaf is visited
     * */
    private void notifyLeafVisited(Node node) {
        this.mappingsTraverserListeners.forEach(
                e -> e.onLeafVisited(node)
        );
    }

    static class Node {
        Map<String, Object> node;
        Map<String, Object> properties;
        String currentPath;
        String name;

        public Node(Map<String, Object> node, String currentPath) {
            this.node = node;
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
    }

}
