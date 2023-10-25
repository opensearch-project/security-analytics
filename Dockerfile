FROM opensearchstaging/opensearch:2.11.0
ADD build/distributions/opensearch-security-analytics-2.11.0.0-SNAPSHOT.zip /tmp/
RUN if [ -d /usr/share/opensearch/plugins/opensearch-security-analytics ]; then /usr/share/opensearch/bin/opensearch-plugin remove opensearch-security-analytics; fi
RUN /usr/share/opensearch/bin/opensearch-plugin install --batch file:/tmp/opensearch-security-analytics-2.11.0.0-SNAPSHOT.zip