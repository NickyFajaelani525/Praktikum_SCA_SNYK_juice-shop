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
        JUICE_SHOP_IMAGE = 'bkimminich/juice-shop:latest'
        WORKSPACE_HOST = '/var/lib/docker/volumes/jenkins_home/_data/workspace/Pipeline_SCA_SNYK'
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

                    echo "Checking Juice Shop image..."
                    docker image inspect "$JUICE_SHOP_IMAGE" > /dev/null

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

                        sh '''
                            set +x

                            docker run --rm \
                              -e SNYK_TOKEN \
                              -v "$WORKSPACE_HOST:/app" \
                              -w /app \
                              "$SNYK_IMAGE" \
                              snyk --version
                        '''

                        int status = sh(
                            returnStatus: true,
                            script: '''
                                set +x
                                set +e

                                docker run --rm \
                                  -e SNYK_TOKEN \
                                  -v "$WORKSPACE_HOST:/app" \
                                  -w /app \
                                  "$SNYK_IMAGE" \
                                  snyk test \
                                  --json-file-output=snyk-report.json \
                                  > snyk-report.txt 2>&1

                                scan_status=$?

                                cat snyk-report.txt

                                exit "$scan_status"
                            '''
                        )

                        if (status == 0) {
                            echo 'Snyk SCA scan completed. No vulnerabilities found.'
                        } else if (status == 1) {
                            echo 'SCA vulnerabilities detected. Proceeding to Security Gate.'
                        } else {
                            error("Snyk SCA scan failed. Exit code: ${status}")
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
                                  -v "$WORKSPACE_HOST:/app" \
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
                                  -v "$WORKSPACE_HOST:/app" \
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

        stage('Snyk Container Scan') {
            steps {
                script {
                    withCredentials([
                        string(
                            credentialsId: 'snyk-token',
                            variable: 'SNYK_TOKEN'
                        )
                    ]) {

                        echo "Scanning local image: ${env.JUICE_SHOP_IMAGE}"

                        int containerStatus = sh(
                            returnStatus: true,
                            script: '''
                                set +x
                                set +e

                                docker run --rm \
                                  -e SNYK_TOKEN \
                                  -e DOCKER_HOST=unix:///var/run/docker.sock \
                                  -v /var/run/docker.sock:/var/run/docker.sock \
                                  -v "$WORKSPACE_HOST:/app" \
                                  -w /app \
                                  "$SNYK_IMAGE" \
                                  snyk container test "$JUICE_SHOP_IMAGE" \
                                  --severity-threshold=high \
                                  --json-file-output=snyk-container-report.json \
                                  > snyk-container-report.txt 2>&1

                                scan_status=$?

                                cat snyk-container-report.txt

                                exit "$scan_status"
                            '''
                        )

                        if (containerStatus == 0) {
                            echo 'CONTAINER SCAN COMPLETED: No HIGH or CRITICAL vulnerabilities found.'
                        } else if (containerStatus == 1) {
                            echo 'CONTAINER VULNERABILITIES DETECTED: HIGH or CRITICAL findings exist.'
                            echo 'Results will be archived for analysis.'
                        } else {
                            error("Snyk Container Scan failed. Exit code: ${containerStatus}")
                        }
                    }
                }
            }
        }

        stage('Security Gate') {
            steps {
                script {
                    withCredentials([
                        string(
                            credentialsId: 'snyk-token',
                            variable: 'SNYK_TOKEN'
                        )
                    ]) {

                        int gateStatus = sh(
                            returnStatus: true,
                            script: '''
                                set +x
                                set +e

                                docker run --rm \
                                  -e SNYK_TOKEN \
                                  -v "$WORKSPACE_HOST:/app" \
                                  -w /app \
                                  "$SNYK_IMAGE" \
                                  snyk test \
                                  --severity-threshold=low \
                                  > snyk-gate-report.txt 2>&1

                                scan_status=$?

                                cat snyk-gate-report.txt

                                exit "$scan_status"
                            '''
                        )

                        if (gateStatus == 0) {
                            echo 'SECURITY GATE PASSED: No vulnerabilities detected.'
                        } else if (gateStatus == 1) {
                            error('SECURITY GATE FAILED: Vulnerabilities detected (LOW to CRITICAL).')
                        } else {
                            error("Security Gate scan failed. Exit code: ${gateStatus}")
                        }
                    }
                }
            }
        }
    }

    post {
        always {
            archiveArtifacts(
                artifacts: 'snyk-report.txt,snyk-report.json,sbom.json,sbom-snyk.log,snyk-container-report.txt,snyk-container-report.json,snyk-gate-report.txt',
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
