plugin=`basename $(ls build/distributions/*.zip)`
list_of_files=`ls`
list_of_all_files=`ls build/distributions/`
version=`echo $plugin|awk -F- '{print $3}'| cut -d. -f 1-3`
plugin_version=`echo $plugin | cut -d '-' -f 4 | cut -d '.' -f 1-3`
qualifier=`echo $plugin|awk -F- '{print $4}'| cut -d. -f 1-1`
candidate_version=`echo $plugin|awk -F- '{print $5}'| cut -d. -f 1-1`
docker_version=2.4.0

[[ -z $candidate_version ]] && candidate_version=$qualifier && qualifier=""

echo plugin version plugin_version qualifier candidate_version docker_version
echo "($plugin) ($version) ($plugin_version) ($qualifier) ($candidate_version) ($docker_version)"
echo $ls $list_of_all_files

docker pull opensearchstaging/opensearch:$docker_version
docker build -t opensearch-alerting-security-analytics:$docker_version \
   --build-arg DOCKER_VERSION_ARG="$docker_version" \
   --build-arg PLUGIN_ARG="$plugin" \
   -f ci/Dockerfile .
