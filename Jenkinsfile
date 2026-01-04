pipeline {
    agent any

    environment {
        APP_IMAGE = "vuln-api:${env.BUILD_NUMBER}"
        APP_PORT  = "8000"
        TARGET_URL = "https://165.227.59.98:9200"  // ajusta según tu entorno
    }

    stages {
       stage('Debug Paths') {
           steps {
               // Esto nos mostrará el árbol de carpetas real en el log de Jenkins
               sh "ls -R" 
           }
       }
       stage('SonarQube Analysis') {
            environment {
                SONAR_HOST_URL = "http://sonarqube:9000"
                SONAR_AUTH_TOKEN = credentials('sonar-token')
            }
            steps {
                script {
                    // 1. Crear el contenedor (sin iniciarlo aún)
                    sh "docker create --name sonar_scanner --network=vuln-app-wazuh_app-network -e SONAR_HOST_URL=http://sonarqube:9000 -e SONAR_TOKEN=${SONAR_TOKEN} -w /usr/src sonarsource/sonar-scanner-cli"

                    // 2. Copiar TODO tu código actual de Jenkins al contenedor
                    sh "docker cp . sonar_scanner:/usr/src"

                    // 3. Iniciar el contenedor y ver los logs
                    sh "docker start -a sonar_scanner"
                }
            }
            post {
                always {
                    // 4. Limpiar el contenedor creado
                    sh "docker rm -f sonar_scanner || true"
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
