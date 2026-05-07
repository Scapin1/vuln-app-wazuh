-- ==========================================================
-- 1. EXTENSIONES Y PREPARACIÓN
-- ==========================================================
CREATE EXTENSION IF NOT EXISTS timescaledb;
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- ==========================================================
-- 2. TIPOS DE DATOS PERSONALIZADOS (ENUMS)
-- ==========================================================
--Debino a que no se tiene certesa severity_level se deja como TEXT para permitir flexibilidad en el catálogo de vulnerabilidades, 
--pero se podría cambiar a ENUM si se desea una validación más estricta.
--CREATE TYPE Severity_level AS ENUM ('Low', 'Medium', 'High', 'Critical');
CREATE TYPE Vuln_status AS ENUM ('Detected', 'Resolved', 'Re-emerged');

-- ==========================================================
-- 3. ENTIDADES
-- ==========================================================

-- Tabla User (según modelo class User)
CREATE TABLE "user" (
    user_id SERIAL PRIMARY KEY,
    user_rol VARCHAR(100),
    user_name VARCHAR(255),
    user_email VARCHAR(255) UNIQUE NOT NULL,
    user_password VARCHAR(255),
    user_status BOOLEAN DEFAULT TRUE,
    user_delete BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMPTZ DEFAULT NOW()
);


-- Configuración de Wazuh Managers (Servidores)
CREATE TABLE managers (
    manager_id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    nombre VARCHAR(255) NOT NULL,
    api_url TEXT NOT NULL,
    api_key_vault_ref TEXT
);

-- 3.1 TABLA INTERMEDIA (Acceso Multitenant)
CREATE TABLE user_manager (
    user_id INT REFERENCES "user"(user_id) ON DELETE CASCADE,
    manager_id UUID REFERENCES managers(manager_id) ON DELETE CASCADE,
    PRIMARY KEY (user_id, manager_id)
);

-- Inventario de Assets (Agentes)
CREATE TABLE assets (
    asset_id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    wazuh_agent_id VARCHAR(255) UNIQUE NOT NULL,
    hostname VARCHAR(255) NOT NULL,
    os_version VARCHAR(255),
    ip_address INET,
    manager_id UUID REFERENCES managers(manager_id) ON DELETE RESTRICT
);

-- Tabla para registrar interacciones de los usuarios con la API 
CREATE TABLE user_interactions (
    user_interaction_id SERIAL PRIMARY KEY,
    user_id INT REFERENCES "user"(user_id) ON DELETE CASCADE,
    endpoint VARCHAR(255),
    method VARCHAR(50),
    details TEXT,
    timestamp TIMESTAMPTZ DEFAULT NOW()
);

-- ==========================================================
-- 4. TABLAS DE WAZUH
-- ==========================================================

CREATE TABLE wazuh_connections (
    id SERIAL PRIMARY KEY,
    name VARCHAR(255) UNIQUE NOT NULL,
    indexer_url TEXT NOT NULL,
    wazuh_user VARCHAR(255) NOT NULL,
    wazuh_password VARCHAR(255) NOT NULL,
    is_active BOOLEAN DEFAULT TRUE,
    tested BOOLEAN DEFAULT FALSE,
    last_tested_at TIMESTAMP WITH TIME ZONE,
    last_test_ok BOOLEAN,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE wazuh_vulnerabilities (
    id SERIAL PRIMARY KEY,
    connection_id INTEGER NOT NULL REFERENCES wazuh_connections(id) ON DELETE CASCADE,
    status VARCHAR(50) DEFAULT 'ACTIVE',
    agent_id VARCHAR(100) NOT NULL,
    agent_name VARCHAR(255),
    os_full TEXT,
    os_platform TEXT,
    os_version TEXT,
    package_name TEXT,
    package_version TEXT,
    package_type TEXT,
    package_arch TEXT,
    cve_id TEXT NOT NULL,
    severity TEXT,
    score_base NUMERIC,
    score_version TEXT,
    detected_at TIMESTAMP WITH TIME ZONE,
    published_at TIMESTAMP WITH TIME ZONE,
    description TEXT,
    reference TEXT,
    scanner_vendor TEXT,
    first_seen TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    last_seen TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT uniq_wazuh_vuln UNIQUE (connection_id, agent_id, package_name, package_version, cve_id)
);

CREATE TABLE vulnerability_history (
    id SERIAL PRIMARY KEY,
    vulnerability_id INTEGER NOT NULL REFERENCES wazuh_vulnerabilities(id) ON DELETE CASCADE,
    action VARCHAR(255) NOT NULL,
    details TEXT,
    timestamp TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- ==========================================================
-- 5. TIMESCALEDB: CATÁLOGO Y HYPERTABLE
-- ==========================================================

CREATE TABLE vulnerability_catalog (
    cve_id TEXT PRIMARY KEY, -- CVE ya es un ID único descriptivo por estándar
    severity TEXT NOT NULL, 
    description TEXT,
    cvss_score DECIMAL(3,1)
);

CREATE TABLE vulnerability_detections (
    timestamp TIMESTAMPTZ NOT NULL,
    asset_id UUID REFERENCES assets(asset_id) ON DELETE CASCADE,
    cve_id TEXT REFERENCES vulnerability_catalog(cve_id) ON DELETE CASCADE,
    first_seen_at TIMESTAMPTZ NOT NULL,
    status vuln_status NOT NULL,
    package_name TEXT,
    package_version TEXT,
    PRIMARY KEY (timestamp, asset_id, cve_id)
);

SELECT create_hypertable('vulnerability_detections', 'timestamp');

-- ==========================================================
-- 6. FUNCIONES INTERNAS Y LÓGICA
-- ==========================================================

-- Lógica de Evolución (Check Evolution)
CREATE OR REPLACE FUNCTION check_vulnerability_evolution()
RETURNS TRIGGER AS $$
DECLARE
    last_status Vuln_status;
BEGIN
    SELECT vuln_status INTO last_status
    FROM vulnerability_detections
    WHERE asset_id = NEW.asset_id 
        AND cve_id = NEW.cve_id
        AND timestamp < NEW.timestamp
    ORDER BY timestamp DESC
    LIMIT 1;

    IF last_status IS NULL THEN
        NEW.vuln_status := 'Detected';
    ELSIF last_status = 'Resolved' THEN
        NEW.vuln_status := 'Re-emerged';
    ELSE
        NEW.vuln_status := 'Detected';
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trg_check_evolution
BEFORE INSERT ON vulnerability_detections
FOR EACH ROW EXECUTE FUNCTION check_vulnerability_evolution();

-- ==========================================================
-- 7. OPTIMIZACIÓN
-- ==========================================================
CREATE INDEX ix_vuln_detections_asset_time ON vulnerability_detections (asset_id, timestamp DESC);
CREATE INDEX ix_user_manager_lookup ON user_manager (user_id);

ALTER TABLE vulnerability_detections SET (
  timescaledb.compress,
  timescaledb.compress_segmentby = 'asset_id, cve_id'
);
SELECT add_compression_policy('vulnerability_detections', INTERVAL '7 days');

-- ==========================================================
-- 8. DATOS DE PRUEBA
-- ==========================================================


-- 1. Insertar el Manager de ejemplo primero
INSERT INTO managers (manager_id, nombre, api_url, api_key_vault_ref)
VALUES (
    '550e8400-e29b-41d4-a716-446655440000', 
    'Administración Central', 
    'http://wazuh-manager.local:55000', 
    'vault/creds/admin'
) ON CONFLICT (manager_id) DO NOTHING;

-- 2. Insertar el Usuario con los nuevos nombres de columna
-- Nota: La tabla es "user" (en minúsculas y entre comillas)
INSERT INTO "user" (user_rol, user_password, user_name, user_email, user_status, user_delete)
VALUES (
    'ADMIN', 
    '$2b$12$r.qDNsr69vZab3VD6J.1/ugXuWLydd7bDfdVJE58kp8seyJX6LTqS', 
    'Administrador Sistema', 
    'admin@tuproyecto.cl', 
    TRUE, 
    FALSE
) ON CONFLICT (user_email) DO NOTHING;

-- 3. Vincular al usuario con el manager en la tabla intermedia
-- Usamos una subconsulta para obtener el user_id que se generó automáticamente
INSERT INTO user_manager (user_id, manager_id)
SELECT user_id, '550e8400-e29b-41d4-a716-446655440000'
FROM "user"
WHERE user_email = 'admin@tuproyecto.cl'
ON CONFLICT (user_id, manager_id) DO NOTHING;