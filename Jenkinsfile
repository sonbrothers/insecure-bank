pipeline {
  agent any
 
  environment {
    SCM_OWNER="ozviper"
    REPOSITORY_NAME="insecure-bank"
    SCM_USERNAME = "ozviper"
    SCM_ACCESS_TOKEN = credentials('SCM_ACCESS_TOKEN')
    SCM_BRANCH_NAME = "master"
    IO_PROJECT_NAME = "${SCM_OWNER}/${REPOSITORY_NAME}"
    IO_SERVER_TOKEN = credentials('IO_SERVER_TOKEN')
    IO_PERSONA="devsecops"
    POLARIS_PROJECT_NAME = "${SCM_OWNER}/${REPOSITORY_NAME}"
    POLARIS_ACCESS_TOKEN = credentials('POLARIS_ACCESS_TOKEN')
    IS_SAST_ENABLED = "false"
    IS_SCA_ENABLED = "false"
    
    // Set following environment variables in Manage Jenkins section
    // IO_SERVER_URL
    // WORKFLOW_SERVER_URL
    // WORKFLOW_CLIENT_VERSION="2021.12.2"
    // POLARIS_SERVER_URL

    // secrets
    // IO_SERVER_TOKEN
    // POLARIS_ACCESS_TOKEN
    // SCM_ACCESS_TOKEN
  }
 
  stages {
//     stage('Build') {
//       steps {
//         sh 'mvn -e clean package -DskipTests'
//       }
//     }
    stage('IO Prescription') {
      steps {
        echo "Getting IO Prescription"
        sh '''
          rm -rf prescription.sh
          wget "https://raw.githubusercontent.com/synopsys-sig/io-artifacts/${WORKFLOW_CLIENT_VERSION}/prescription.sh"
          sed -i -e 's/\r$//' prescription.sh
          chmod a+x prescription.sh
          ./prescription.sh \
          --stage="IO" \
          --persona="${IO_PERSONA}" \
          --io.url="${IO_SERVER_URL}" \
          --io.token="${IO_SERVER_TOKEN}" \
          --manifest.type="json" \
          --project.name="${IO_PROJECT_NAME}" \
          --workflow.url="${WORKFLOW_SERVER_URL}" \
          --workflow.version="${WORKFLOW_CLIENT_VERSION}" \
          --scm.type="github" \
          --scm.owner="${SCM_OWNER}" \
          --scm.repo.name="${REPOSITORY_NAME}" \
          --scm.branch.name="${SCM_BRANCH_NAME}" \
          --github.username="${SCM_USERNAME}" \
          --github.token="${SCM_ACCESS_TOKEN}" \
          --polaris.url="${POLARIS_SERVER_URL}" \
          --polaris.token="${POLARIS_ACCESS_TOKEN}" \
          --polaris.project.name="${POLARIS_PROJECT_NAME}" \
          --jira.enable="false" \
          --IS_SAST_ENABLED="${IS_SAST_ENABLED}" \
          --IS_SCA_ENABLED="${IS_SCA_ENABLED}"
        '''
        sh 'mv result.json io-presciption.json'
        sh '''
          echo "==================================== IO Risk Score =======================================" > io-risk-score.txt
          echo "Business Criticality Score - $(jq -r '.riskScoreCard.bizCriticalityScore' io-presciption.json)" >> io-risk-score.txt
          echo "Data Class Score - $(jq -r '.riskScoreCard.dataClassScore' io-presciption.json)" >> io-risk-score.txt
          echo "Access Score - $(jq -r '.riskScoreCard.accessScore' io-presciption.json)" >> io-risk-score.txt
          echo "Open Vulnerability Score - $(jq -r '.riskScoreCard.openVulnScore' io-presciption.json)" >> io-risk-score.txt
          echo "Change Significance Score - $(jq -r '.riskScoreCard.changeSignificanceScore' io-presciption.json)" >> io-risk-score.txt
          export bizScore=$(jq -r '.riskScoreCard.bizCriticalityScore' io-presciption.json | cut -d'/' -f2)
          export dataScore=$(jq -r '.riskScoreCard.dataClassScore' io-presciption.json | cut -d'/' -f2)
          export accessScore=$(jq -r '.riskScoreCard.accessScore' io-presciption.json | cut -d'/' -f2)
          export vulnScore=$(jq -r '.riskScoreCard.openVulnScore' io-presciption.json | cut -d'/' -f2)
          export changeScore=$(jq -r '.riskScoreCard.changeSignificanceScore' io-presciption.json | cut -d'/' -f2)
          echo -n "Total Score - " >> io-risk-score.txt && echo "$bizScore + $dataScore + $accessScore + $vulnScore + $changeScore" | bc >> io-risk-score.txt
        '''
        sh 'cat io-risk-score.txt'
        sh '''
          echo "IS_SAST_ENABLED = $(jq -r '.security.activities.sast.enabled' io-presciption.json)" > io-prescription.txt
          echo "IS_SCA_ENABLED = $(jq -r '.security.activities.sca.enabled' io-presciption.json)" >> io-prescription.txt
        '''
        sh 'cat io-prescription.txt'
      }
    }
    stage('SAST - Static Analysis with Polaris') {
      steps {
        echo "SAST - Static Analysis with Polaris"
        sh '''
          IS_SAST_ENABLED=$(jq -r '.security.activities.sast.enabled' io-presciption.json)
          echo "IS_SAST_ENABLED = ${IS_SAST_ENABLED}"
          if [ ${IS_SAST_ENABLED} = "true" ]; then
            export POLARIS_SERVER_URL=${POLARIS_SERVER_URL}
            export POLARIS_ACCESS_TOKEN=${POLARIS_ACCESS_TOKEN}
            wget -q ${POLARIS_SERVER_URL}/api/tools/polaris_cli-linux64.zip
            unzip -j polaris_cli-linux64.zip -d /tmp
            /tmp/polaris analyze -w
          else
            echo "Skipping Polaris Scan based on IO Precription"
          fi
          '''
      }
    }
    stage('IO Workflow') {
      steps {
        echo "Preparing to run IO Workflow Engine"
        sh '''
          IS_SAST_ENABLED=$(jq -r '.security.activities.sast.enabled' io-presciption.json)
          IS_SCA_ENABLED=$(jq -r '.security.activities.sca.enabled' io-presciption.json)
          ./prescription.sh \
          --stage="WORKFLOW" \
          --persona="${IO_PERSONA}" \
          --io.url="${IO_SERVER_URL}" \
          --io.token="${IO_SERVER_TOKEN}" \
          --manifest.type="json" \
          --project.name="${IO_PROJECT_NAME}" \
          --workflow.url="${WORKFLOW_SERVER_URL}" \
          --workflow.version="${WORKFLOW_CLIENT_VERSION}" \
          --polaris.project.name="${POLARIS_PROJECT_NAME}" \
          --polaris.url="${POLARIS_SERVER_URL}" \
          --polaris.token="${POLARIS_ACCESS_TOKEN}" \
          --jira.enable="false" \
          --IS_SAST_ENABLED="${IS_SAST_ENABLED}" \
          --IS_SCA_ENABLED="${IS_SCA_ENABLED}"
        '''
        echo "Running IO Workflow Engine"
        sh '''
          java -jar WorkflowClient.jar --workflowengine.url="${WORKFLOW_SERVER_URL}" --io.manifest.path=synopsys-io.json
        '''
      }
    }
    
    stage('Break the Build') {
      steps {
        echo "add Build Breaker parts here"
        sh '''
          echo "Breaker Status - $(jq -r '.breaker.status' wf-output.json)"
          # Put code to break the build here
          IS_BREAKER_STATUS_ENABLED=$(jq -r '.breaker.status' wf-output.json)
          echo "Breaker Status - $(IS_BREAKER_STATUS_ENABLED)"
          if [ ${IS_BREAKER_STATUS_ENABLED} = "true" ]; then
              echo "$(jq -r '.breaker.criteria[0]' wf-output.json)"
          fi
        '''
      }
    }
    stage('Clean Workspace') {
      steps {
        cleanWs()
      }
    }
  }
}
