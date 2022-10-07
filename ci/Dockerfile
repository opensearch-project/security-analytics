ARG DOCKER_VERSION_ARG
FROM phaseshiftstudio/opensearch-alerting:2.4.0

ARG PLUGIN_ARG
ENV PLUGIN ${PLUGIN_ARG}

RUN if [ -d /usr/share/opensearch/plugins/opensearch-security-analytics ]; then \
      /usr/share/opensearch/bin/opensearch-plugin remove opensearch-security-analytics; \
    fi
ADD build/distributions/$PLUGIN /tmp/
RUN /usr/share/opensearch/bin/opensearch-plugin install --batch file:/tmp/$PLUGIN
