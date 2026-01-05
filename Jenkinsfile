pipeline {
    agent any

    environment {
        APP_IMAGE = "vuln-api:${env.BUILD_NUMBER}"
        APP_PORT  = "8000"
        TARGET_URL = "https://165.227.59.98:9200"
        OWASP_URL = "http://api:8000/openapi.json"
    }

    stages {
       // ETAPA DE TESTS: Comentada hasta que los tests estén listos
        
        stage('Unit Tests & Coverage') {
            steps {
                sh '''
                    docker compose build api
                    docker compose run --rm \
                        -v "$WORKSPACE/vuln-api:/coverage" \
                        api sh -c "PYTHONPATH=/app pytest tests \
                        --cov=app \
                        --cov-report=xml:/coverage/coverage.xml \
                        --cov-report=term"
                '''
            }
        }
        

        stage('SonarQube Analysis') {
            environment {
                SONAR_HOST_URL = "http://sonarqube:9000"
                SONAR_AUTH_TOKEN = credentials('sonar-token')
            }
            steps {
                script {
                    docker.image('sonarsource/sonar-scanner-cli').inside("--network=vuln-app-wazuh_app-network --user=root") {
                        sh """
                        sonar-scanner \
                            -Dsonar.projectKey=vuln-app-api \
                            -Dsonar.host.url=${SONAR_HOST_URL} \
                            -Dsonar.login=${SONAR_AUTH_TOKEN} \
                            -Dsonar.sources=vuln-api/app
                        """
                        // Nota: Cuando habilites los tests, recuerda añadir esta línea al comando de arriba:
                        // -Dsonar.qualitygate.wait=true \
                        // -Dsonar.qualitygate.timeout=300 \
                        // -Dsonar.python.coverage.reportPaths=vuln-api/coverage.xml
                        // -Dsonar.python.coverage.reportPaths=coverage.xml
                    }
                }
            }
        }

        stage('Deploy app') {
            steps {
                sh '''
                docker compose up -d --build api zap
                '''
            }
        }

        stage('OWASP ZAP Scan') {
            steps {
                script {
                    sh 'mkdir -p reports && chmod 777 reports'
                    sh 'chmod +x jenkins/scripts/run_zap.sh'
                    sh "./jenkins/scripts/run_zap.sh ${OWASP_URL} ${env.BUILD_NUMBER}"
                }
            }
        }

        stage('Sincronizar vulnerabilidades desde Wazuh') {
            steps {
                script {
                    // Llamas al endpoint /auth/login y /vulns/sync con curl
                    // (aquí asumo usuario admin:admin creado previamente)
                    sh """
                    TOKEN=\$(curl -s -X POST ${TARGET_URL}/auth/login \
                        -H "Content-Type: application/x-www-form-urlencoded" \
                        -d "username=admin&password=admin" | python3 -c "import sys, json; print(json.load(sys.stdin)['access_token'])")

                    curl -s -X POST ${TARGET_URL}/vulns/sync \
                        -H "Authorization: Bearer \$TOKEN" \
                        -H "Content-Type: application/json"
                    """
                }
            }
        }
    }

    post {
        always {
            script {
                def scanId = env.BUILD_NUMBER
                // Publicar reporte HTML de ZAP (si tienes HTML Publisher)
                publishHTML(target: [
                    reportDir: '.',
                    reportFiles: "zap_report_${scanId}.html",
                    reportName: "OWASP ZAP Report",
                    keepAll: true,
                    alwaysLinkToLastBuild: true
                ])
                archiveArtifacts artifacts: "zap_report_${scanId}.html,zap_report_${scanId}.json", onlyIfSuccessful: false
            }

            // Limpieza opcional
            sh 'docker ps -a'
        }
    }
}
