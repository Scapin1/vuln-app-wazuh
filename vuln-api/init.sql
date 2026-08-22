-- ==========================================================
-- EXTENSIONES
-- ==========================================================
CREATE EXTENSION IF NOT EXISTS timescaledb;
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- ==========================================================
-- CREAR USUARIO DE LA APP
-- ==========================================================
DO $$
BEGIN
    IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'vulnadmin') THEN
        CREATE USER vulnadmin WITH PASSWORD 'securepassword123';
    END IF;
END
$$;

-- ==========================================================
-- PERMISOS PARA EL USUARIO DE LA APP
-- ==========================================================
GRANT ALL ON SCHEMA public TO vulnadmin;
GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO vulnadmin;
GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO vulnadmin;
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT ALL ON TABLES TO vulnadmin;
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT ALL ON SEQUENCES TO vulnadmin;

-- Crear usuario de aplicación (sin GRANT - se hace después de crear la BD)
DO $$
BEGIN
    IF NOT EXISTS (SELECT FROM pg_catalog.pg_roles WHERE rolname = 'vulnadmin') THEN
        CREATE USER vulnadmin WITH PASSWORD 'securepassword123';
    END IF;
END
$$;

-- Dar permisos al usuario
GRANT ALL PRIVILEGES ON DATABASE vulnerabilities_db TO vulnadmin;
GRANT ALL ON SCHEMA public TO vulnadmin;

-- ==========================================================
-- 2. TIPOS DE DATOS PERSONALIZADOS (ENUMS)
-- ==========================================================
--Debino a que no se tiene certesa severity_level se deja como TEXT para permitir flexibilidad en el catálogo de vulnerabilidades, 
--pero se podría cambiar a ENUM si se desea una validación más estricta.
--CREATE TYPE Severity_level AS ENUM ('Low', 'Medium', 'High', 'Critical');
CREATE TYPE vuln_status AS ENUM ('Detected', 'Resolved', 'Re-emerged');

-- ==========================================================
-- 4. TABLAS DE WAZUH
-- ==========================================================

CREATE TABLE wazuh_connections(
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

-- ==========================================================
-- 3. ENTIDADES
-- ==========================================================

-- Tabla Roles (catálogo de roles del sistema)
CREATE TABLE roles (
    rol_id SERIAL PRIMARY KEY,
    rol_name VARCHAR(100) UNIQUE NOT NULL,
    rol_description TEXT
);

-- Tabla User (según modelo class User)
CREATE TABLE "user" (
    user_id SERIAL PRIMARY KEY,
    user_rol INTEGER REFERENCES roles(rol_id),
    user_name VARCHAR(255) UNIQUE NOT NULL,
    user_password VARCHAR(255),
    user_status BOOLEAN DEFAULT TRUE,
    user_delete BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

-- Inventario de Assets (Agentes)
CREATE TABLE assets (
    asset_id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    wazuh_agent_id VARCHAR(255) UNIQUE NOT NULL,
    hostname VARCHAR(255) NOT NULL,
    os_version VARCHAR(255),
    ip_address INET,
    wazuh_connection_id BIGINT REFERENCES wazuh_connections(id) ON DELETE RESTRICT
);

-- Tabla para registrar interacciones de los usuarios con la API
CREATE TABLE user_interactions (
    user_interaction_id SERIAL PRIMARY KEY,
    user_id BIGINT REFERENCES "user"(user_id) ON DELETE CASCADE,
    endpoint VARCHAR(255),
    method VARCHAR(50),
    details TEXT,
    timestamp TIMESTAMPTZ DEFAULT NOW()
);

-- ==========================================================
-- TABLAS INTERMEDIAS (ASIGNACIONES)
-- ==========================================================

-- Asignación Usuario <-> Asset
CREATE TABLE user_assets (
    user_id INTEGER NOT NULL REFERENCES "user"(user_id) ON DELETE CASCADE,
    asset_id UUID NOT NULL REFERENCES assets(asset_id) ON DELETE CASCADE,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    PRIMARY KEY (user_id, asset_id)
);

-- Asignación Rol <-> Asset
CREATE TABLE rol_assets (
    rol_id INTEGER NOT NULL REFERENCES roles(rol_id) ON DELETE CASCADE,
    asset_id UUID NOT NULL REFERENCES assets(asset_id) ON DELETE CASCADE,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    PRIMARY KEY (rol_id, asset_id)
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


-- ==========================================================
-- 7. OPTIMIZACIÓN
-- ==========================================================
CREATE INDEX ix_vuln_detections_asset_time ON vulnerability_detections (asset_id, timestamp DESC);


ALTER TABLE vulnerability_detections SET (
  timescaledb.compress,
  timescaledb.compress_segmentby = 'asset_id, cve_id'
);
SELECT add_compression_policy('vulnerability_detections', INTERVAL '7 days');

-- ==========================================================
-- 8. DATOS DE PRUEBA
-- ==========================================================


-- Insertar el ROL base del sistema
INSERT INTO roles (rol_name, rol_description)
VALUES (
    'ADMIN',
    'Administrador del sistema con acceso total'
) ON CONFLICT (rol_name) DO NOTHING;

-- . Insertar el Usuario con los nuevos nombres de columna
-- Nota: La tabla es "user" (en minúsculas y entre comillas)
INSERT INTO "user" (user_rol, user_password, user_name, user_status, user_delete)
VALUES (
    (SELECT rol_id FROM roles WHERE rol_name = 'ADMIN'),
    '$2b$12$r.qDNsr69vZab3VD6J.1/ugXuWLydd7bDfdVJE58kp8seyJX6LTqS',
    'admin',
    TRUE,
    FALSE
);

-- ==========================================================
-- 9. VISTAS MATERIALIZADAS
-- ==========================================================

CREATE MATERIALIZED VIEW mv_critical_vulnerabilities AS
SELECT 
    vc.cve_id,
    vc.cvss_score,
    vc.description,
    COUNT(DISTINCT vd.asset_id) AS total_affected_agents,
    array_agg(DISTINCT a.wazuh_agent_id) AS affected_wazuh_agent_ids,
    array_agg(DISTINCT a.hostname) AS affected_hostnames
FROM 
    vulnerability_catalog vc
JOIN 
    vulnerability_detections vd ON vc.cve_id = vd.cve_id
JOIN 
    assets a ON vd.asset_id = a.asset_id
WHERE 
    UPPER(vc.severity) = 'CRITICAL'
    AND vd.status IN ('Detected', 'Re-emerged')
GROUP BY 
    vc.cve_id, 
    vc.cvss_score, 
    vc.description;

CREATE UNIQUE INDEX idx_mv_critical_cve_id ON mv_critical_vulnerabilities (cve_id);

CREATE OR REPLACE FUNCTION refresh_critical_vulns_view()
RETURNS void AS $$
BEGIN
    REFRESH MATERIALIZED VIEW CONCURRENTLY mv_critical_vulnerabilities;
END;
$$ LANGUAGE plpgsql;

GRANT SELECT ON mv_critical_vulnerabilities TO vulnadmin;

