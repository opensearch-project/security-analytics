ARG DOCKER_VERSION_ARG
FROM opensearchstaging/opensearch:${DOCKER_VERSION_ARG}
SHELL ["/bin/bash","-x","-e","-c"]
ARG PLUGIN_ARG
ENV PLUGIN ${PLUGIN_ARG}
RUN if [ -d /usr/share/opensearch/plugins/opensearch-security-analytics ]; then /usr/share/opensearch/bin/opensearch-plugin remove opensearch-security-analytics; fi;

ADD build/distributions/$PLUGIN /tmp/

RUN /usr/share/opensearch/bin/opensearch-plugin install --batch file:/tmp/$PLUGIN
