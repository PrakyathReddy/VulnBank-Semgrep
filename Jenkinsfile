
pipeline {
  agent any

  stages {
    stage("Clean workspace") {
      steps{
        cleanWs()
      }
    }
    stage("checkout code") {
      steps{
        echo "checking out code from github..."
        checkout scm
      }
    }
    stage("install dependencies") {
      steps{
        echo "installing dependencies..."
        sh """
          python3 -m venv venv
          . venv/bin/activate
          pip install -r requirements.txt
          pip install pytest semgrep
        """
      }
    }
    stage("Semgrep scan") {
      steps{
          echo "running semgrep security scan..."
          sh """
            pwd
            ls
            . venv/bin/activate 
            semgrep scan --config auto --severity ERROR --verbose .
          """
      }
    }
    stage("Check for exposed secrets") {
      steps{
        echo "checking for exposed secrets..."
        sh """
          . venv/bin/activate
          semgrep scan --config p/secrets --verbose .
        """
      }
    }
  }

}
