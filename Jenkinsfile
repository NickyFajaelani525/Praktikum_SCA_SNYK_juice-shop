
pipeline {
    agent any

    options {
        timestamps()
        disableConcurrentBuilds()
        skipDefaultCheckout(true)
    }

    environment {
        SNYK_IMAGE = 'snyk/snyk:node'
        NODE_IMAGE = 'node:24-alpine'
        SNYK_BLOCKER = 'false'
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
                    echo "Checking Docker connection..."
                    docker version

                    echo "Checking project files..."
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
                                  -v "/var/lib/docker/volumes/jenkins_home/_data/workspace/Pipeline_SCA_SNYK:/app" \
                                  -w /app \
                                  "$SNYK_IMAGE" \
                                  test \
                                  --severity-threshold=high \
                                  > snyk-report.txt 2>&1

                                cat snyk-report.txt
                            '''
                        )

                        if (status == 0) {
                            echo 'No HIGH/CRITICAL vulnerabilities found.'
                        } else if (status == 1) {
                            echo 'HIGH/CRITICAL vulnerabilities detected.'
                            env.SNYK_BLOCKER = 'true'
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
                                  -v "/var/lib/docker/volumes/jenkins_home/_data/workspace/Pipeline_SCA_SNYK:/app" \
                                  -w /app \
                                  "$SNYK_IMAGE" \
                                  sbom \
                                  --format=cyclonedx1.4+json \
                                  --json-file-output=sbom.json \
                                  > sbom-snyk.log 2>&1
                            '''
                        )

                        if (snykStatus == 0) {
                            echo 'SBOM generated using Snyk CLI.'
                        } else {
                            echo 'Snyk SBOM unavailable. Using CycloneDX npm.'
                            sh 'cat sbom-snyk.log'

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

                        sh '''
                            test -s sbom.json
                            echo "SBOM successfully generated."
                        '''
                    }
                }
            }
        }

        stage('Security Gate') {
            steps {
                script {
                    if (env.SNYK_BLOCKER == 'true') {
                        error(
                            'SECURITY GATE FAILED: HIGH/CRITICAL vulnerabilities detected.'
                        )
                    }

                    echo 'SECURITY GATE PASSED.'
                    echo 'No HIGH/CRITICAL vulnerabilities detected.'
                }
            }
        }
    }

    post {
        always {
            archiveArtifacts(
                artifacts: 'snyk-report.txt,snyk-report.json,sbom.json,sbom-snyk.log',
                allowEmptyArchive: true
            )
        }

        success {
            echo 'Pipeline completed successfully.'
        }

        failure {
            echo 'Pipeline failed. Check the Console Output and archived reports.'
        }
    }
}
