pipeline {
    agent any

    environment {
        APP_IMAGE = "vuln-api:${env.BUILD_NUMBER}"
        APP_PORT  = "8000"
        TARGET_URL = "https://165.227.59.98:9200"
        OWASP_URL = "http://api:8000/openapi.json"
    }

    stages {
        stage('Unit Tests & Coverage') {
            steps {
                script {
                    sh '''
                        # Ejecutamos sin --rm para que el contenedor quede "Exited" pero con los archivos dentro
                        docker compose run --name temp-tests api sh -c "PYTHONPATH=/app pytest tests --cov=app --cov-report=xml:coverage.xml"
                        
                        # Copiamos el archivo al workspace de Jenkins
                        docker cp temp-tests:/app/coverage.xml vuln-api/coverage.xml
                        
                        # Limpiamos el contenedor
                        docker rm temp-tests
                        
                        # Corregimos las rutas para SonarQube
                        sed -i 's|<source>/app/app</source>|<source>vuln-api/app</source>|g' vuln-api/coverage.xml
                    '''
                }
            }
        }

        stage('SonarQube Analysis') {
            environment {
                SONAR_HOST_URL = "http://sonarqube:9000"
                SONAR_AUTH_TOKEN = credentials('sonar-token')
            }
            steps {
                script {
                    withSonarQubeEnv('sonarqube') {
                        docker.image('sonarsource/sonar-scanner-cli').inside("--network=vuln-app-wazuh_app-network --user=root") {
                            sh """
                            sonar-scanner \
                                -Dsonar.host.url=${SONAR_HOST_URL} \
                                -Dsonar.login=${SONAR_AUTH_TOKEN} \
                            """
                        }     
                    }
                }
            }
        }

        stage("Quality Gate") {
            steps {
                timeout(time: 5, unit: 'MINUTES') {
                    // Jenkins se detiene aquí hasta que SonarQube termine el análisis
                    waitForQualityGate abortPipeline: true
                }
            }
        }

        stage('Deploy app') {
            steps {
                sh 'docker compose up -d --build api zap'
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
    } // Cierre de STAGES

    post {
        always {
            script {
                def scanId = env.BUILD_NUMBER
                publishHTML(target: [
                    reportDir: 'reports', // <--- CAMBIO AQUÍ: apunta a la carpeta reports
                    reportFiles: "zap_report_${scanId}.html",
                    reportName: "OWASP ZAP Report",
                    keepAll: true,
                    alwaysLinkToLastBuild: true
                ])
                
                // Añadimos allowEmptyArchive: true para que no falle la build si el archivo falta
                // y corregimos la ruta a reports/
                archiveArtifacts artifacts: "reports/zap_report_${scanId}.html, reports/zap_report_${scanId}.json", 
                                 onlyIfSuccessful: false, 
                                 allowEmptyArchive: true 
            }
            sh 'docker ps -a'
        }
    }
}
