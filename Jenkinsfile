pipeline {
  agent { label 'maven' }

  stages {
    stage ('Maven') {
      steps {
        withMaven(mavenSettingsConfig: 'mvn-elearn-repo-settings') {
          sh 'mvn spring-boot:build-image -Dspring-boot.build-image.publish=true'
        }
      }
    }
  }
}
