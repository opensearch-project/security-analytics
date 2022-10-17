alerting_plugin=`basename $(ls alerting/alerting/build/distributions/*.zip)`
alerting_list_of_files=`ls alerting/`
alerting_list_of_all_files=`ls alerting/alerting/build/distributions/`
alerting_version=`echo $alerting_plugin|awk -F- '{print $3}'| cut -d. -f 1-3`
alerting_plugin_version=`echo $alerting_plugin|awk -F- '{print $3}'| cut -d. -f 1-4`
alerting_qualifier=`echo $alerting_plugin|awk -F- '{print $4}'| cut -d. -f 1-1`
alerting_candidate_version=`echo $alerting_plugin|awk -F- '{print $5}'| cut -d. -f 1-1`

plugin=`basename $(ls build/distributions/*.zip)`
list_of_files=`ls`
list_of_all_files=`ls build/distributions/`
version=`echo $plugin|awk -F- '{print $3}'| cut -d. -f 1-3`
plugin_version=`echo $plugin|awk -F- '{print $3}'| cut -d. -f 1-4`
qualifier=`echo $plugin|awk -F- '{print $4}'| cut -d. -f 1-1`
candidate_version=`echo $plugin|awk -F- '{print $5}'| cut -d. -f 1-1`
docker_version=$version-$qualifier

[[ -z $candidate_version ]] && candidate_version=$qualifier && qualifier=""

echo plugin version plugin_version qualifier candidate_version docker_version
echo "($plugin) ($version) ($plugin_version) ($qualifier) ($candidate_version) ($docker_version)"
echo $ls $list_of_all_files

if docker pull opensearchstaging/opensearch:$docker_version
then
      docker build -t opensearch-alerting-security-analytics:$docker_version \
         --build-arg DOCKER_VERSION_ARG="$docker_version" \
         --build-arg PLUGIN_ARG="$plugin_version" \
         --build-arg ALERTING_PLUGIN_ARG="$alerting_plugin_version" \
         -f ci/Dockerfile .
#  echo "imagePresent=true" >> $GITHUB_ENV
else
   echo
#  echo "imagePresent=false" >> $GITHUB_ENV
fi
