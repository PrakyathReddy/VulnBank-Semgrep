
pipeline {
  agent any

  stages {
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
          . venv/bin/activate semgrep scan --configure auto --severity ERROR app/
        """
      }
    }
  }

}
