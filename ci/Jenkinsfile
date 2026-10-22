// Aegis image scan — declarative Jenkins pipeline.
//
// Mirrors the GitHub Actions workflow: build, scan, gate, publish the report,
// and only push the image once the gate has passed.
pipeline {
  agent any

  options {
    timestamps()
    buildDiscarder(logRotator(numToKeepStr: '30'))
    timeout(time: 30, unit: 'MINUTES')
  }

  parameters {
    string(name: 'IMAGE', defaultValue: '', description: 'Image to scan (defaults to the image built here)')
    string(name: 'FAIL_ON', defaultValue: 'HIGH', description: 'Severity floor that fails the build')
    string(name: 'MAX_CRITICAL', defaultValue: '0', description: 'Tolerated CRITICAL findings')
    string(name: 'MAX_HIGH', defaultValue: '10', description: 'Tolerated HIGH findings')
    booleanParam(name: 'WARN_ONLY', defaultValue: false, description: 'Report breaches without failing')
  }

  environment {
    IMAGE_REF         = "${params.IMAGE ?: "registry.internal/${env.JOB_NAME}:${env.BUILD_NUMBER}"}"
    AEGIS_FAIL_ON     = "${params.FAIL_ON}"
    AEGIS_MAX_CRITICAL = "${params.MAX_CRITICAL}"
    AEGIS_MAX_HIGH    = "${params.MAX_HIGH}"
    AEGIS_WARN_ONLY   = "${params.WARN_ONLY}"
    // Shared across jobs on this agent so the ~700 MB CVE database is downloaded
    // once a day instead of once a build.
    AEGIS_CACHE_DIR   = "${env.JENKINS_HOME}/caches/trivy"
    AEGIS_DB          = "${env.JENKINS_HOME}/aegis/aegis.db"
    AEGIS_OUTPUT_DIR  = "${env.WORKSPACE}/reports"
  }

  stages {
    stage('Install Aegis') {
      steps {
        sh '''
          python3 -m venv .venv
          .venv/bin/pip install --quiet --upgrade pip
          .venv/bin/pip install --quiet -e .
          command -v trivy >/dev/null 2>&1 || \
            curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh \
              | sh -s -- -b "$WORKSPACE/bin" v0.76.1
        '''
      }
    }

    stage('Build image') {
      when { expression { return !params.IMAGE } }
      steps {
        sh 'docker build -t "$IMAGE_REF" .'
      }
    }

    stage('Scan and gate') {
      steps {
        withCredentials([string(credentialsId: 'slack-webhook-url', variable: 'SLACK_WEBHOOK_URL')]) {
          script {
            // Aegis exits 1 on a policy breach and 2 when the scan itself failed —
            // the two are reported differently below.
            env.AEGIS_EXIT = sh(
              returnStatus: true,
              script: '''
                export PATH="$WORKSPACE/bin:$PATH"
                export AEGIS_SLACK_ENABLED=true
                .venv/bin/aegis scan "$IMAGE_REF" --source jenkins
              '''
            ).toString()
          }
        }
      }
    }

    stage('Publish report') {
      steps {
        archiveArtifacts artifacts: 'reports/*', allowEmptyArchive: true, fingerprint: true
        publishHTML(target: [
          reportDir: 'reports', reportFiles: 'latest_*.html',
          reportName: 'Aegis vulnerability report',
          keepAll: true, alwaysLinkToLastBuild: true, allowMissing: true
        ])
      }
    }

    stage('Enforce gate') {
      steps {
        script {
          if (env.AEGIS_EXIT == '2') {
            error("Aegis could not complete the scan (exit 2) — see the console log.")
          }
          if (env.AEGIS_EXIT == '1') {
            error("Aegis gate failed — see the archived report.")
          }
          echo "Aegis gate passed."
        }
      }
    }

    stage('Push image') {
      when {
        allOf {
          expression { return !params.IMAGE }
          branch 'main'
        }
      }
      steps {
        sh 'docker push "$IMAGE_REF"'
      }
    }
  }

  post {
    always { cleanWs(deleteDirs: true, notFailBuild: true, patterns: [[pattern: 'reports/**', type: 'EXCLUDE']]) }
  }
}
