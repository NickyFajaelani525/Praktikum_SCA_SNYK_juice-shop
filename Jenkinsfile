
pipeline {
    agent any

    options {
        timestamps()
        disableConcurrentBuilds()
    }

    environment {
        SNYK_IMAGE = 'snyk/snyk:node'
        NODE_IMAGE = 'node:24-alpine'
    }

    stages {
        stage('Clean Workspace') {
            steps {
                deleteDir()
                echo 'Workspace cleaned.'
            }
        }
        
        stage('Checkout SCM') {
            steps {
                checkout scm
                echo 'Source code checked out.'
            }
        }
    
        stage('Preflight Check') {
            steps {
                sh '''
                    docker version
                    test -f package.json
                    test -f package-lock.json
                    echo "Preflight checks passed."
                '''
            }
        }

        stage('Snyk SCA Scan') {
            steps {
                script {
                    withCredentials([
                        string(
                            credentialsId: 'snyk-token',
                            variable: 'SNYK_TOKEN'
                        )
                    ]) {
                        int status = sh(
                            returnStatus: true,
                            script: '''
                                set +x

                                docker run --rm \
                                  -e SNYK_TOKEN \
                                  -v "$WORKSPACE:/app" \
                                  -w /app \
                                  "$SNYK_IMAGE" \
                                  test \
                                  --json-file-output=snyk-report.json \
                                  > snyk-report.txt 2>&1

                                cat snyk-report.txt
                            '''
                        )

                        if (status == 0) {
                            echo 'No vulnerabilities found.'
                        } else if (status == 1) {
                            echo 'Vulnerabilities detected.'
                            currentBuild.result = 'UNSTABLE'
                        } else {
                            error("Snyk scan failed. Exit code: ${status}")
                        }
                    }
                }
            }
        }

        stage('Generate SBOM') {
            steps {
                script {
                    withCredentials([
                        string(
                            credentialsId: 'snyk-token',
                            variable: 'SNYK_TOKEN'
                        )
                    ]) {
                        int snykStatus = sh(
                            returnStatus: true,
                            script: '''
                                set +x

                                docker run --rm \
                                  -e SNYK_TOKEN \
                                  -v "$WORKSPACE:/app" \
                                  -w /app \
                                  "$SNYK_IMAGE" \
                                  sbom \
                                  --format=cyclonedx1.4+json \
                                  --json-file-output=sbom.json
                            '''
                        )

                        if (snykStatus == 0) {
                            echo 'SBOM generated using Snyk.'
                        } else {
                            echo 'Snyk SBOM unavailable. Using CycloneDX npm fallback.'

                            sh '''
                                docker run --rm \
                                  -v "$WORKSPACE:/app" \
                                  -w /app \
                                  "$NODE_IMAGE" \
                                  sh -c '
                                    npm install -g @cyclonedx/cyclonedx-npm &&
                                    cyclonedx-npm \
                                      --package-lock-only \
                                      --spec-version 1.4 \
                                      --output-format JSON \
                                      --output-file sbom.json
                                  '
                            '''
                        }
                    }
                }
            }
        }
    }

    post {
        always {
            archiveArtifacts(
                artifacts: 'snyk-report.txt,snyk-report.json,sbom.json',
                allowEmptyArchive: true
            )
        }
    }
}
