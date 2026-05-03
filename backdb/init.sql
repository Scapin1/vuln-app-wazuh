-- ==========================================================
-- 1. EXTENSIONES Y PREPARACIÓN
-- ==========================================================

-- Habilita las funciones de series de tiempo de TimescaleDB
CREATE EXTENSION IF NOT EXISTS timescaledb;

-- Habilita la generación de UUIDs versión 4 para llaves primarias
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- ==========================================================
-- 2. TIPOS DE DATOS PERSONALIZADOS (ENUMS)
-- ==========================================================

-- Define los niveles de severidad para el catálogo de CVEs
CREATE TYPE severity_level AS ENUM ('Low', 'Medium', 'High', 'Critical');

-- Define el estado de evolución de una vulnerabilidad
CREATE TYPE vuln_status AS ENUM ('Detected', 'Resolved', 'Re-emerged');

-- ==========================================================
-- 3. ENTIDADES MAESTRAS (TABLAS RELACIONALES)
-- ==========================================================

-- Configuración de Wazuh Managers
CREATE TABLE managers (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    nombre VARCHAR(255) NOT NULL,
    api_url TEXT NOT NULL,
    -- Referencia para el secreto en HashiCorp Vault (almacena el puntero, no el secreto)
    api_key_vault_ref TEXT 
);

-- Tabla de Usuarios
CREATE TABLE IF NOT EXISTS "user" (
    user_id SERIAL PRIMARY KEY,
    user_rol VARCHAR(50) NOT NULL,
    user_password VARCHAR(255) NOT NULL,
    user_name VARCHAR(255) NOT NULL,
    user_email VARCHAR(255) UNIQUE NOT NULL,
    user_status BOOLEAN DEFAULT FALSE, -- Inactivo por defecto
    user_delete BOOLEAN DEFAULT FALSE, -- No eliminado por defecto
    manager_id UUID NOT NULL,
    CONSTRAINT fk_manager_scope        -- Cada usuario está asociado a un solo manager / puede cambiarse de manager pero no puede existir sin uno
        FOREIGN KEY (manager_id) 
        REFERENCES managers(id)
);

-- Inventario de Assets (Servidores Ubuntu)
CREATE TABLE assets (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    -- ID único que le asigna el agente de Wazuh
    wazuh_agent_id VARCHAR(255) UNIQUE NOT NULL,
    hostname VARCHAR(255) NOT NULL,
    os_version VARCHAR(255),
    -- Tipo INET para validación y manejo eficiente de direcciones IP
    ip_address INET,
    manager_id UUID REFERENCES managers(id) ON DELETE RESTRICT
);

-- Diccionario Global de Vulnerabilidades (Evita redundancia de texto)
CREATE TABLE vulnerability_catalog (
    cve_id VARCHAR(50) PRIMARY KEY, -- Ej: 'CVE-2023-1234'
    severity severity_level NOT NULL,
    description TEXT,
    -- Puntuación CVSS con restricción de rango 0.0 a 10.0
    cvss_score DECIMAL(3,1) CHECK (cvss_score >= 0.0 AND cvss_score <= 10.0)
);

-- ==========================================================
-- 4. HYPERTABLE DE EVOLUCIÓN (SERIES DE TIEMPO)
-- ==========================================================

CREATE TABLE vulnerability_detections (
    -- Timestamp: Columna clave para particionamiento temporal
    timestamp TIMESTAMPTZ NOT NULL,
    first_seen_at TIMESTAMPTZ NOT NULL,
    asset_id UUID REFERENCES assets(id) ON DELETE CASCADE,
    cve_id TEXT REFERENCES vulnerability_catalog(cve_id) ON DELETE CASCADE,
    status vuln_status NOT NULL,
    package_name TEXT,
    package_version TEXT
);

-- Transforma la tabla en una Hypertable particionada automáticamente por 'timestamp'
SELECT create_hypertable('vulnerability_detections', 'timestamp');

-- ==========================================================
-- 5. LÓGICA DE DETECCIÓN DE EVOLUCIÓN (PL/pgSQL)
-- ==========================================================

-- Esta función se ejecuta ANTES de cada insert para determinar el estado de evolución
CREATE OR REPLACE FUNCTION check_vulnerability_evolution()
RETURNS TRIGGER AS $$
DECLARE
    last_status vuln_status;
BEGIN
    -- Busca el último estado registrado para este par Asset/CVE
    SELECT status INTO last_status
    FROM vulnerability_detections
    WHERE asset_id = NEW.asset_id AND cve_id = NEW.cve_id
    ORDER BY timestamp DESC
    LIMIT 1;

    -- Lógica de negocio:
    -- Si no existía antes, es una detección nueva (Detected)
    -- Si estaba resuelta y vuelve a aparecer, es una re-emergencia (Re-emerged)
    -- Si ya estaba activa, se mantiene como detección (Detected)
    IF last_status IS NULL THEN
        NEW.status := 'Detected';
    ELSIF last_status = 'Resolved' THEN
        NEW.status := 'Re-emerged';
    ELSE
        NEW.status := 'Detected';
    END IF;

    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

-- Crea el Trigger que automatiza la lógica anterior
CREATE TRIGGER trg_check_evolution
BEFORE INSERT ON vulnerability_detections
FOR EACH ROW EXECUTE FUNCTION check_vulnerability_evolution();

-- ==========================================================
-- 6. ÍNDICES Y POLÍTICAS DE COMPRESIÓN
-- ==========================================================

-- Índices optimizados para las consultas más frecuentes (Filtros por servidor o por CVE)
CREATE INDEX ix_vuln_detections_asset_time ON vulnerability_detections (asset_id, timestamp DESC);
CREATE INDEX ix_vuln_detections_cve_time ON vulnerability_detections (cve_id, timestamp DESC);

-- Configura la compresión nativa para ahorrar ~90% de espacio en datos históricos
-- Los datos se comprimen agrupándolos por asset y cve después de 7 días
ALTER TABLE vulnerability_detections SET (
  timescaledb.compress,
  timescaledb.compress_segmentby = 'asset_id, cve_id'
);

-- Aplica la política de compresión automática
SELECT add_compression_policy('vulnerability_detections', INTERVAL '7 days');

-- ==========================================================
-- 7. DATOS DE PRUEBA (OPCIONAL)

-- Inserta un manager de ejemplo(necesario para la FK)
-- Usamos una variable para capturar el ID o simplemente lo insertamos
INSERT INTO managers (id, nombre, api_url, api_key_vault_ref)
VALUES (
    '550e8400-e29b-41d4-a716-446655440000', 
    'Administración Central', 
    'http://wazuh-manager.local:55000', 
    'vault/creds/admin'
) ON CONFLICT (id) DO NOTHING;

-- 2. Insertar el usuario ADMIN vinculado a ese Manager
-- Password: admin123 (hasheado con bcrypt)
INSERT INTO "user" (user_rol, user_password, user_name, user_email, user_status, manager_id)
VALUES (
    'ADMIN', 
    '$2b$12$r.qDNsr69vZab3VD6J.1/ugXuWLydd7bDfdVJE58kp8seyJX6LTqS', 
    'Administrador Sistema', 
    'admin@tuproyecto.cl', 
    TRUE, -- Importante: activado manualmente para el primer ingreso
    '550e8400-e29b-41d4-a716-446655440000'
) ON CONFLICT (user_email) DO NOTHING;