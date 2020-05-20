#!/usr/bin/env bash

IMAGE=$1
TAG=latest

ECR_REGISTRY="634503960501"
TEST_ECR=$(aws ecr describe-repositories \
  --registry-id ${ECR_REGISTRY} \
  --repository-names ${IMAGE} \
  --output json 2>/dev/null | jq ".repositories[0].registryId")

if [ "${TEST_ECR}" != "${ECR_REGISTRY}" ]; then
  echo Creating ECR repository
  TEST_ECR=$(aws ecr create-repository \
    --repository-name ${IMAGE} \
    --image-scanning-configuration scanOnPush=true \
    --output json 2>/dev/null | jq ".repositories[0].registryId")
  echo ECR repository ${TEST_ECR} created
else
  echo ECR repository ${TEST_ECR} already exists
fi

echo Pulling image
docker pull ${IMAGE}:${TAG}

echo Push image to ECR and start scan
aws ecr get-login-password --region eu-west-1 | \
  docker login --username AWS \
  --password-stdin 634503960501.dkr.ecr.eu-west-1.amazonaws.com

docker tag ${IMAGE}:${TAG} 634503960501.dkr.ecr.eu-west-1.amazonaws.com/${IMAGE}:${TAG}
docker push 634503960501.dkr.ecr.eu-west-1.amazonaws.com/${IMAGE}:${TAG}

echo Start Smart Check scan
docker run -v /var/run/docker.sock:/var/run/docker.sock \
  deepsecurity/smartcheck-scan-action \
  --image-name "${IMAGE}:${TAG}" \
  --findings-threshold "{\"malware\":0,\"vulnerabilities\":{\"defcon1\":0,\"critical\":0,\"high\":0},\"contents\":{\"defcon1\":0,\"critical\":0,\"high\":1},\"checklists\":{\"defcon1\":0,\"critical\":0,\"high\":0}}" \
  --preregistry-host="smartcheck-registry-108-129-65-162.nip.io" \
  --smartcheck-host="smartcheck-108-129-65-162.nip.io" \
  --smartcheck-user="admin" \
  --smartcheck-password="TrendM1cr0" \
  --insecure-skip-tls-verify \
  --preregistry-scan \
  --preregistry-user "reguser" \
  --preregistry-password "TrendM1cr0"
