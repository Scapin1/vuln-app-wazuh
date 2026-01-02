pipeline {
    agent any

    environment {
        APP_IMAGE = "vuln-api:${env.BUILD_NUMBER}"
        APP_PORT  = "8000"
        TARGET_URL = "https://165.227.59.98:9200"  // ajusta según tu entorno
    }

    stages {
        stage('Build Docker image') {
            steps {
                sh "docker build -t ${APP_IMAGE} ."
            }
        }

        stage('Deploy app (Docker)') {
            steps {
                // Parar contenedor viejo si existe
                sh 'docker rm -f vuln-api || true'
                // Levantar app conectada a la BD
                withCredentials([
                    string(credentialsId: 'vuln-db-url', variable: 'DATABASE_URL'),
                    usernamePassword(credentialsId: 'wazuh-indexer-creds', usernameVariable: 'WZ_USER', passwordVariable: 'WZ_PASS')
                ]) {
                    sh """
                    docker run -d --name vuln-api \
                      -e DATABASE_URL=$DATABASE_URL \
                      -e WAZUH_INDEXER_URL=https://wazuh-indexer:9200 \
                      -e WZ_USER=$WZ_USER \
                      -e WZ_PASS=$WZ_PASS \
                      -p ${APP_PORT}:8000 \
                      ${APP_IMAGE}
                    """
                }
            }
        }

        stage('Tests & Coverage') {
            steps {
                sh '''
                cd vuln-api
                pip install -r requirements.txt
                pytest --cov=. --cov-report=xml
                '''
            }
        }

        stage('SonarQube Analysis') {
            steps {
                withCredentials([string(credentialsId: 'sonar-token', variable: 'SONAR_TOKEN')]) {
                    sh '''
                    docker run --rm \
                    -e SONAR_HOST_URL=http://sonarqube:9000 \
                    -e SONAR_LOGIN=$SONAR_TOKEN \
                    -v "$PWD:/usr/src" \
                    sonarsource/sonar-scanner-cli
                    '''
                }
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
