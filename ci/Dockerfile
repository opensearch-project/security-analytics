ARG DOCKER_VERSION_ARG
FROM opensearchstaging/opensearch:${DOCKER_VERSION_ARG}

ARG PLUGIN_ARG
ENV PLUGIN ${PLUGIN_ARG}
ARG ALERTING_PLUGIN_ARG
ENV ALERTING_PLUGIN ${ALERTING_PLUGIN_ARG}
RUN if [ -d /usr/share/opensearch/plugins/opensearch-security-analytics ]; then \
      /usr/share/opensearch/bin/opensearch-plugin remove opensearch-security-analytics; \
    fi \
    if [ -d /usr/share/opensearch/plugins/opensearch-alerting ]; then \
      /usr/share/opensearch/bin/opensearch-plugin remove opensearch-alerting; \
    fi

ADD build/distributions/$PLUGIN /tmp/
ADD alerting/alerting/build/distributions/$ALERTING_PLUGIN /tmp/

RUN /usr/share/opensearch/bin/opensearch-plugin install --batch file:/tmp/$PLUGIN
RUN /usr/share/opensearch/bin/opensearch-plugin install --batch file:/tmp/$ALERTING_PLUGIN
