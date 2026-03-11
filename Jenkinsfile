
pipeline {
  agent any
  environment {
    SEMGREP_APP_TOKEN = credentials("ae10ab18-f99d-4b66-998c-f1311275fde7")
  }

  stages {
    stage("Clean workspace") {
      steps {
        cleanWs()
      }
    }

    stage("Checkout code") {
      steps {
        echo "Checking out code from GitHub..."
        checkout scm
      }
    }

    stage("Install dependencies") {
      steps {
        echo "Installing dependencies..."
        sh """
          python3 -m venv venv
          . venv/bin/activate
          pip install -r requirements.txt
          pip install semgrep pip-audit
        """
      }
    }

    stage("SAST — Semgrep scan") {
      steps {
        echo "Running Semgrep SAST scan..."
        sh """
          . venv/bin/activate
          semgrep scan --config auto --severity ERROR --verbose .
        """
      }
    }

    stage("Secrets scan") {
      steps {
        echo "Checking for exposed secrets..."
        sh """
          . venv/bin/activate
          semgrep scan --config p/secrets --verbose .
        """
      }
    }

    stage("SCA — Dependency audit") {
      steps {
        echo "Running SCA with pip-audit..."
        sh """
          . venv/bin/activate
          pip-audit -r requirements.txt
        """
      }
    }

    stage("Security gate") {
      steps {
        echo "All security checks passed. Deployment approved."
      }
    }
  }

  post {
    failure {
      echo "SECURITY GATE FAILED — deployment blocked. Fix all findings before merging."
    }
    success {
      echo "SECURITY GATE PASSED — pipeline clean."
    }
  }

}
