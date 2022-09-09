pipeline {
  agent any
  environment {
    DOCKER_TARGET = 'ssedevelopment/fake-oidc-server'
    DOCKER_REGISTRY = 'https://ghcr.io'
    JENKINS_DOCKER_CREDS = '2ad31065-44e1-4850-a3b1-548e17aa6757'
  }
  tools { maven 'Maven 3.8.6' }

  stages {
 
    stage ('Build') {
      steps {
		sh "mvn package"
        script {
          app = docker.build("${DOCKER_TARGET}")
        }
      }
    }

    stage ('Publish') {
      steps {
        script {
          docker.withRegistry("${DOCKER_REGISTRY}", "${JENKINS_DOCKER_CREDS}") {
            app.push("${env.BUILD_NUMBER}")
            app.push("latest")
          }
        }
      }
    }

  }
}
