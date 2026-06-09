# Use microservice-base image as starting point
FROM 755600509381.dkr.ecr.us-east-1.amazonaws.com/cxcd-automation/service-boot-base:4.x

MAINTAINER DevOps <devops@alight.com>
 
#Install Spring Boot Artifact
ARG ARTIFACT_VERSION=UPOINT-SNAPSHOT
COPY *-${ARTIFACT_VERSION}.jar /apps/service/app.jar
