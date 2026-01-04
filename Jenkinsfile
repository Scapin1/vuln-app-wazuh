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
                    // Jenkins se encarga de:
                    // 1. Montar el volumen correctamente (incluso en Docker-in-Docker)
                    // 2. Correr el contenedor
                    // 3. Borrar el contenedor al finalizar (pase lo que pase)
                    docker.image('sonarsource/sonar-scanner-cli').inside("--network=vuln-app-wazuh_app-network --user=root") {
                        sh """
                        sonar-scanner \
                            -Dsonar.projectKey=vuln-app-api \
                            -Dsonar.host.url=http://sonarqube:9000 \
                            -Dsonar.login=${SONAR_AUTH_TOKEN} \
                            -Dsonar.sources=vuln-api/app
                        """
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
