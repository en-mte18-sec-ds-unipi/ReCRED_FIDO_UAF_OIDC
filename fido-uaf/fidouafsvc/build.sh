#!bin/bash

$MVN_HOME/mvn install && cp target/fidouafsvc-ci.war /usr/local/tomcat/apache-tomcat-8.5.5/webapps/published/artifacts/
