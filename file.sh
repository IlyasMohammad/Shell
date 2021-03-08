#!/bin/bash

get_s3_list_by_last_modified() {
  local endpoint=$1
  local bucket=${2}
  local prefix=${3}
  local max_items=${4}
  if [[ ${endpoint} != "no-endpoint" ]]; then
    echo $(aws s3api list-objects-v2 \
      "${endpoint}" \
      --bucket "${bucket}" \
      --prefix "${prefix}" \
      --max-items ${max_items} \
      --query 'reverse(sort_by(Contents[].{Key: Key, LastMod: LastModified},&LastMod))' |
      sed -n 's|.*"Key": "\([^"]*\)".*|\1|p')
  else
    echo $(aws s3api list-objects-v2 \
      --bucket "${bucket}" \
      --prefix "${prefix}" \
      --max-items ${max_items} \
      --query 'reverse(sort_by(Contents[].{Key: Key, LastMod: LastModified},&LastMod))' |
      sed -n 's|.*"Key": "\([^"]*\)".*|\1|p')
  fi
}

unset_proxy() {
  export old_http_proxy=${http_proxy}
  export old_https_proxy=${https_proxy}
  export old_no_proxy=${no_proxy}
  echo "Proxy settings before unset: http: ${http_proxy} https: ${https_proxy}"
  export http_proxy=
  export https_proxy=
  export no_proxy=
  echo "New proxy settings: http: ${http_proxy} https: ${https_proxy}"
}

reset_proxy() {
  export http_proxy=${old_http_proxy}
  export https_proxy=${old_https_proxy}
  export no_proxy=${old_no_proxy}
  echo "Proxy settings after reset: http: ${http_proxy} https: ${https_proxy}"
}

get_s3_file() {
  local bucket=${1}
  local key=${2}
  local outfile=${3}

  echo "Copying: aws s3 cp s3://${bucket}/${key} ${outfile}" >&2
  #aws s3 cp "s3://${bucket}/${key}" "${outfile}"  --debug >&2
  aws s3 cp "s3://${bucket}/${key}" "${outfile}"
}

is_directory() {
  local FILE=$1
  case "$FILE" in
  */)
    echo 1
    ;;
  *)
    echo 0
    ;;
  esac
}

move_s3_files_to_out_folder() {
  local bucket=$1
  local in_folder=$2
  local out_folder=$3
  shift
  shift
  local files=("$@")

  for file in "${files[@]}"; do
    if [[ "$(is_directory ${file})" == "0" ]]; then
      outfile=${file/$in_folder/$out_folder}
      echo "Moving S3 file to out folder: ${bucket}/${file} to ${bucket}/${outfile}" >&2
      # Todo: actually move the S3 files
      # local ans=$(move_s3_file "${bucket}" "${file}" "${outfile}")
      # echo "Move response: ${ans}" >&2
    fi
  done
}

move_file_to_out_folder() {
  local in_folder=$1
  local out_folder=$2
  local file=$3

  outfile=${file/$in_folder/$out_folder}
  echo "Moving local file to out folder: ${file} to ${outfile}"
  local result=$(mv "${file}" "${outfile}")

  printf "${result}\n\n"
}

remove_local_file() {
  local file=$1

  echo "Removing local file: ${file} "
  local result=$(rm -rf "${file}")

  printf "${result}\n\n"
}

move_s3_file() {
  bucket=$1
  infile=$2
  outfile=$3

  echo $(aws s3 mv "s3://${bucket}/${infile}" "s3://${bucket}/${outfile}")
}

is_docker_image() {
  if [[ (-n "${1}") && ($(tar xfO "${1}" manifest.json 2>/dev/null) =~ "Config") ]]; then
    echo 1
  else
    echo 0
  fi
}

successful_docker_load_image() {
  if [[ $1 =~ sha256:[0-9a-z]{64} ]]; then
    echo 1
  else
    echo 0
  fi
}

extract_tag_from_load_response() {
  echo $1 | sed 's|.*sha256:\([0-9a-z]\{12\}\).*|\1|'
}

load_docker_image() {
  local model_file=$1
  local repo_url=$2
  local __load_docker_image_return_url=$3

  image_load_response=$(docker image load -i "${model_file}")

  if [[ "$(successful_docker_load_image "${image_load_response}")" == "1" ]]; then

    local ecr_tag=$(extract_tag_from_load_response "${image_load_response}")

    local ecr_url="${repo_url}:${ecr_tag}"

    docker tag "${ecr_tag}" "${ecr_url}" >&2
    if [[ $? -eq 0 ]]; then
      echo "${ecr_url}"
    fi
  fi
}

make_temp_model_folder() {
  local temp_model_folder=$1
  local model_in_folder=$2
  local model_out_folder=$3

  echo "Saving models to: ${temp_model_folder}" >&2
  mkdir -p "${temp_model_folder}/${model_in_folder}" &&
    mkdir -p "${temp_model_folder}/${model_out_folder}"
}

extract_ecs_url() {
  local lines=("$@")
  local url=${lines[-1]}
  #url="${url##*$'\n'}"
  if [[ "${lines[-1]}" =~ ^([0-9]+[0-9a-zA-Z./-]+:[0-9a-zA-Z]+)$ ]]; then
    echo "${BASH_REMATCH[0]}"
  else
    echo ""
  fi
}

watch_folder() {
  local folder=$1
  local sleep=$2
  sleep=${sleep:=1}
  local times=$3
  times=${times:=5}
  local i=0
  echo "Watching: ${folder} " >&2
  echo "Sleeping: ${sleep} seconds for ${times} times, if the folder is full" >&2

  while [[ ${i} < ${times} ]]; do
    if [[ "$(ls ${folder})" == "" ]]; then
      echo 0
      exit
    fi
    echo "Folder ${folder} contains items" >&2
    sleep ${sleep}
    i=$(($i + 1))
  done

  echo 1
}

empty_folder() {
  local folder=$1
  if [[ "${folder}" =~ ^/$ || ! -d "${folder}" ]]; then
    return "Cannot delete ${folder}"
  fi

  rm -rf ${folder}/* >&2
}

get_region() {
  set_proxy
  LOCAL_HOSTNAME=$(hostname -d)
  if [[ ${LOCAL_HOSTNAME} =~ .*\.amazonaws\.com ]]; then
    curl --silent http://169.254.169.254/latest/dynamic/instance-identity/document |
      python -c 'import json,sys; obj=json.load(sys.stdin); print(obj["region"]);'
  else
    echo "us-east-1"
  fi
}

print_login_to_ecr() {
  export AWS_REGION=$(get_region)
  #export ECR_PROFILE=$1
  set_proxy
  #&& "${ECR_PROFILE}"
  if [[ "${AWS_REGION}" ]]; then
    set +x
    result="set +x && "$(aws ecr get-login --region ${AWS_REGION} --no-include-email)" 2>/dev/null && set -x"
    echo ${result}
    set -x
  else
    echo "Set region and aws profile for which repo exists in environment variables!"
  fi
}

compose_up_or_down() {
  local cmd=$1
  local stack=$2
  if [[ "${COMPOSE_STACK_NAME}" && "${cmd}" ]]; then
    if [[ "${cmd}" == "up" ]]; then
      docker-compose -p ${COMPOSE_STACK_NAME} ${cmd} -d --build
    elif [[ "${cmd}" == "down" ]]; then
      docker-compose -p ${COMPOSE_STACK_NAME} ${cmd} --volumes
    else
      exit 1
    fi
  fi
}

compose_up() {
  local stack=$1
  local file_with_flag=$2
  docker-compose ${file_with_flag} -p ${stack} up -d --build
}

compose_down() {
  local stack=$1
  local file_with_flag=$2
  docker-compose ${file_with_flag} -p ${stack} down --volumes
}

compose_restart() {
  local stack=$1
  local service=$2
  local file_with_flag=$3
  docker-compose -p ${stack} restart ${service}
}

cmd_in_container() {
  local cmd=$1
  local container=$2
  if [[ "${cmd}" && "${COMPOSE_STACK_NAME}" && "${container}" ]]; then
    echo "docker-compose -p ${COMPOSE_STACK_NAME} run ${container} bash -c '${cmd}'"
    docker-compose -p ${COMPOSE_STACK_NAME} run -T ${container} bash -c '${cmd}'
  else
    echo "Parameters not passed!"
  fi
}

container_run_sh_command() {
  local stack_name=$1
  local container=$2
  shift
  shift
  local cmd="${@}"
  if [[ "${cmd}" && "${stack_name}" && "${container}" ]]; then
    docker-compose -p ${stack_name} run -T ${container} sh -c "${cmd}"
  else
    echo "Missing command or container in container_run_command!"
  fi
}

container_exec_sh_command() {
  local stack_name=$1
  local container=$2
  shift
  shift
  local cmd="${@}"
  if [[ "${cmd}" && "${stack_name}" && "${container}" ]]; then
    docker-compose -p ${stack_name} exec -T ${container} sh -c "${cmd}"
  else
    echo "Missing command or container in container_run_command!"
  fi
}

container_run_command() {
  local stack_name=$1
  local container=$2
  shift
  shift
  local cmd="${@}"
  if [[ "${cmd}" && "${stack_name}" && "${container}" ]]; then
    docker-compose -p ${stack_name} run -T ${container} bash -c "${cmd}"
  else
    echo "Missing command or container in container_run_command!"
  fi
}

container_exec_command() {
  local stack_name=$1
  local container=$2
  shift
  shift
  local cmd="${@}"
  if [[ "${cmd}" && "${stack_name}" && "${container}" ]]; then
    echo "Running command: ${cmd}"
    docker-compose -p ${stack_name} exec -T ${container} bash -c "${cmd}"
  else
    echo "Missing command or container in container_run_command!"
  fi
}

echo_to_file() {
  local file=$1
  local statement=$2
  if [[ ! -f "${file}" ]]; then
    touch "${file}"
    echo "${statement}" >"${file}"
  else
    echo "${statement}" >>"${file}"
  fi
  echo 0
}

get_ip_from_ping() {
  local host=$1
  echo $(ping -c1 -n "${host}" | head -n1 | sed "s/.*(\([0-9]*\.[0-9]*\.[0-9]*\.[0-9]*\)).*/\\1/g")
}

get_stack_name() {
  echo -n $(od -vAn -N4 -tu4 </dev/urandom | sed 's/ //g' | tr -d '\n')
}

set_proxy() {
  export http_proxy=http://webproxygo.fpl.com:8080
  export https_proxy=http://webproxygo.fpl.com:8080
  ## MUST HAVE NO PROXY FOR AWS META DATA!!!!!!!
  export no_proxy="169.254.169.254,*neeaws.local"
}

is_pull_request() {
  local credentials=$1
  local repo=$2
  local commit_id=$3
  local repo_ip=$(get_ip_from_ping neer-bitbucket.fplu.fpl.com)

  echo $(curl --silent -u "${credentials}" \
    http://${repo_ip}:7990/rest/api/1.0/projects/NNLP/repos/${repo}/commits/${commit_id}/pull-requests) |
    python -c 'import json,sys; obj=json.load(sys.stdin); [sys.stdout.write("FALSE") if len(obj["values"]) == 0 else sys.stdout.write(obj["values"][0]["state"])];'
}

cleanup_stopped_containers() {
  docker container prune --force
}

get_container_id_by_name() {
  local name=$1

  result=$(docker ps -aqf name=${name})

  if [[ result ]]; then
    echo -n "${result}"
  fi
}

# get_secrets_name() {
#   stack_name=$1
#   output_key=$2
#   aws cloudformation describe-stacks --stack-name $1 \
#     --output text --query "Stacks[0].Outputs[?OutputKey=='${output_key}'].{Value:OutputValue}[0].Value"
# }

get_output_from_stack_key() {
  stack_name=$1
  output_key=$2
  aws cloudformation describe-stacks --stack-name ${stack_name} \
    --output text --query "Stacks[0].Outputs[?OutputKey=='${output_key}'].{Value:OutputValue}[0].Value" 2>/dev/null
}

get_secrets() {
  secrets_name=$1
  secrets_file=$2
  lib_dir=$(dirname "${BASH_SOURCE[0]}")
  if [[ -z ${secrets_name} ]]; then
    echo "Please pass secrets name (id) for first argument"
    exit 1
  fi
  echo "set +x" >${secrets_file}
  aws secretsmanager get-secret-value --secret-id ${secrets_name} --region us-east-1 |
    ${lib_dir}/parse_secrets.py >>${secrets_file}
  echo "set -x" >>${secrets_file}
}

get_secrets_from_stack() {
  local stack_name=$1
  local output_key=$2
  local secrets_file=$3
  secrets_name=$(get_output_from_stack_key ${stack_name} ${output_key})
  if [[ -z ${secrets_name} ]]; then
    echo "Unable to get secrets name"
    exit 1
  fi
  get_secrets ${secrets_name} ${secrets_file}
}

set_image_scan_on_push() {
  local repository_name=$1
  local scan_on_push=$2
  aws ecr put-image-scanning-configuration \
    --repository-name ${repository_name} \
    --image-scanning-configuration scanOnPush=${scan_on_push}
}

get_image_scan_status() {
  local repository_name=$1
  local image_tag=$2
  aws ecr describe-image-scan-findings \
    --repository-name "${repository_name}" \
    --image-id imageTag=${image_tag} \
    --output json \
    --query 'imageScanStatus.status'
}

# returns the count if you capture the results bla=$() dies otherwise on positive counts
get_image_scan_severity_count() {
  local repository_name=$1
  local image_tag=$2
  local count=$(aws ecr describe-image-scan-findings \
    --repository-name "${repository_name}" \
    --image-id imageTag=${image_tag} \
    --output json \
    --query 'length(imageScanFindings.findingSeverityCounts)')

  printf ${count}

  if [[ $count > 0 ]]; then
    echo "Image ${repository_name}/${image_tag} has vulnerabilities" &>2
    exit 1
  fi

  echo "Image ${repository_name}/${image_tag} has no vulnerabilities" &>2
}

wait_for_image_scan_status() {
  repository_name=$1
  image_tag=$2
  for ((i = 1; i <= 30; i++)); do
    status=$(get_image_scan_status "${repository_name}" "${image_tag}")
    if [[ ${status} == *COMPLETE* ]]; then
      echo "${status}"
      exit
    fi

    echo "Checked image ${repository_name}:${image_tag} status: ${i} times. (${status})" >&2
    sleep 10
  done
  echo "Image scanning never completed or failed: ${status}" >&2
  exit 1
}

delete_change_set() {
  stack_name=$1
  change_set=$2
  echo "Removing change-set \"$change_set\" in stack \"$stack_name\"."
  aws cloudformation delete-change-set --stack-name $stack_name --change-set-name $change_set
}

analyze_change_set() {
  stack_name=$1
  output_name=$2
  environment=$3
  aws_dir=$4
  shift
  shift
  shift
  shift
  templates=("$@")

  NESTED_STACK=$(get_output_from_stack_key ${stack_name} ${output_name})
  echo "Stack: ${NESTED_STACK}" >&2

  if [[ -z ${NESTED_STACK} ]] || [[ "${NESTED_STACK}" == "None" ]]; then
    echo "No nested stack found for '${stack_name}' with output ${output_name}." >&2
    return 0
  fi

  echo "Analyzing stack '${NESTED_STACK}' for replacements." >&2
  STACK_PARAMETERS=$(aws cloudformation describe-stacks --stack-name ${NESTED_STACK} --output json --query "Stacks[0].Parameters")

  echo "Parsing parameters and setting environment vars." >&2
  PARAMETERS_CONFIG=$(cat "${aws_dir}/cft/parameters.${environment}.conf")
  TEMPLATE_YML=${templates[$output_name]}
  PARAMETERS=$(node ${aws_dir}/../deploy/helpers/parse-parameters.js "${PARAMETERS_CONFIG}" "${STACK_PARAMETERS}" "${aws_dir}/${TEMPLATE_YML}")

  CHANGESET=${NESTED_STACK}-$(date '+%Y%m%d%s')

  echo "Creating a change-set." >&2
  echo "  aws cloudformation create-change-set \
    --change-set-type UPDATE \
    --stack-name ${NESTED_STACK} \
    --change-set-name ${CHANGESET} \
    --template-body file://${aws_dir}/${TEMPLATE_YML} \
    --parameters ${PARAMETERS}" >&2

  #change_set_result=$(
  aws cloudformation create-change-set \
    --change-set-type UPDATE \
    --stack-name ${NESTED_STACK} \
    --change-set-name ${CHANGESET} \
    --template-body file://${aws_dir}/${TEMPLATE_YML} \
    --parameters ${PARAMETERS} >&2
  #)
  #echo "Changeset result: ${change_set_result}" >&2
  sleep 5

  #  change_set_arn=$(echo "${change_set_result}" | sed -En 's/.*"Id": "([^"]+)".*/\1/p')
  #  echo "Changeset arn: $change_set_arn" >&2

  change_set_status=$(aws cloudformation describe-change-set --stack-name ${NESTED_STACK} --change-set-name ${CHANGESET} --query 'StatusReason')
  echo "Changeset status: ${change_set_status}" >&2

  if [[ "${change_set_status}" =~ didn.t[[:space:]]contain[[:space:]]changes ]]; then
    echo "No changes to {$NESTED_STACK}." >&2
    REPLACEMENTS=0
  else
    echo "Wait for the change-set to be ready." >&2
    aws cloudformation wait change-set-create-complete --change-set-name ${CHANGESET} --stack-name ${NESTED_STACK} >&2
    # Amount of resources with Replacement==`True`
    REPLACEMENTS=$(aws cloudformation describe-change-set --stack-name ${NESTED_STACK} --change-set-name ${CHANGESET} \
      --output json --query 'length(Changes[?ResourceChange.Replacement==`True`])')
  fi

  echo "Replacements: ${REPLACEMENTS}" >&2

  if [[ ${REPLACEMENTS} -gt 0 ]]; then
    echo "WARNING: found ${REPLACEMENTS} resources marked for replacements in stack '${NESTED_STACK}'." >&2
    aws cloudformation describe-change-set --stack-name ${NESTED_STACK} --change-set-name ${CHANGESET} \
      --output table --query 'Changes[?ResourceChange.Replacement==`True`].ResourceChange.{Type:ResourceType,Resource:LogicalResourceId,Replace:Replacement}' >&2
  else
    echo "No resources found marked for replacements in stack '$NESTED_STACK'." >&2
  fi

  delete_change_set ${NESTED_STACK} ${CHANGESET} >&2

  if [[ ${REPLACEMENTS} =~ ^[0-9]+$ ]]; then
    echo ${REPLACEMENTS}
  else
    echo "There is a problem with the replacements query or the stack description"
    exit 1
  fi
}

check_for_error() {
  start_date=$1
  last_exit_code=$2
  shift
  shift
  if [[ ${last_exit_code} -gt 0 ]]; then
    echo
    echo "An error was return when updating the stack."
    echo
    for stack in "$@"; do
      if [[ "$stack" != "None" ]]; then
        echo "Errors in stack '$stack':"
        aws cloudformation describe-stack-events \
          --stack-name ${stack} \
          --max-items 50 \
          --output text \
          --query "StackEvents[?(contains(ResourceStatus, \`FAILED\`) || contains(ResourceStatus, \`ROLLBACK_IN_PROGRESS\`) || contains(ResourceStatus, \`DELETE\`)) && Timestamp>=\`${start_date}\`].[Timestamp,LogicalResourceId,ResourceStatus,ResourceStatusReason]"
        echo
      fi
    done
    echo
    exit 1
  fi
}

set_ifs() {
  export OLD_IFS=${IFS}
  export IFS=$'\n'
}
reset_ifs() {
  export IFS=${OLD_IFS}
}

get_ecr_tag() {
  main_stack_name=$1
  cluster_service_stack_name=$2
  image_tag_output_name=$3
  ecs_stack=$(get_output_from_stack_key ${main_stack_name} ${cluster_service_stack_name})
  echo "Stack: ${ecs_stack}" >&2

  if [[ -z ${ecs_stack} ]] || [[ "${ecs_stack}" == "None" ]]; then
    echo "No nested stack found for '${main_stack_name}' with output ${cluster_service_stack_name}." >&2
    return 0
  fi

  get_output_from_stack_key ${ecs_stack} ${image_tag_output_name}
}
