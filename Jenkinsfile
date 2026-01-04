pipeline {
    agent any

    environment {
        APP_IMAGE = "vuln-api:${env.BUILD_NUMBER}"
        APP_PORT  = "8000"
        TARGET_URL = "https://165.227.59.98:9200"  // ajusta según tu entorno
    }

    stages {
       stage('SonarQube Analysis') {
            environment {
                SONAR_HOST_URL = "http://sonarqube:9000"
                SONAR_AUTH_TOKEN = credentials('sonar-token')
            }
            steps {
                sh '''
                docker run --rm \
                --network=vuln-app-wazuh_app-network \
                -e SONAR_HOST_URL=$SONAR_HOST_URL \
                -e SONAR_TOKEN=$SONAR_AUTH_TOKEN \
                -v "$(pwd):/usr/src" \
                sonarsource/sonar-scanner-cli \
                -Dsonar.projectKey=vuln-api \
                -Dsonar.host.url=$SONAR_HOST_URL
                -Dsonar.projectName="Vuln Api" \
                -Dsonar.sources=vuln-api/app \
                -Dsonar.tests=vuln-api/tests \
                -Dsonar.sourceEncoding=UTF-8
                '''
            }
        }

        stage('Deploy app') {
            steps {
                sh '''
                docker compose up -d --build api zap
                '''
            }
        }

        stage('OWASP ZAP baseline') {
            steps {
                sh 'chmod +x scripts/run_zap.sh'
                script {
                    def scanId = env.BUILD_NUMBER
                    sh "scripts/run_zap.sh ${TARGET_URL} ${scanId}"
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
