const MOCK_DELAY = 500;

const mockData = {
    vulns: [
        {
            id: 1,
            cve_id: 'CVE-2023-1234',
            severity: 'critical',
            agent_name: 'server-01',
            package_name: 'bash',
            package_version: '5.0-1',
            first_seen: new Date(Date.now() - 1000 * 60 * 30).toISOString(), // hace 30 min (NUEVO)
            last_seen: new Date().toISOString()
        },
        {
            id: 2,
            cve_id: 'CVE-2022-9876',
            severity: 'high',
            agent_name: 'desktop-mx',
            package_name: 'openssl',
            package_version: '1.1.1',
            first_seen: new Date(Date.now() - 1000 * 60 * 60 * 48).toISOString(), // hace 48 horas
            last_seen: new Date().toISOString()
        },
        {
            id: 3,
            cve_id: 'CVE-2021-3452',
            severity: 'medium',
            agent_name: 'web-server-02',
            package_name: 'nginx',
            package_version: '1.18.0',
            first_seen: new Date(Date.now() - 1000 * 60 * 60 * 72).toISOString(),
            last_seen: new Date(Date.now() - 1000 * 60 * 60 * 24).toISOString()
        },
        {
            id: 4,
            cve_id: 'CVE-2020-0001',
            severity: 'low',
            agent_name: 'vpn-node',
            package_name: 'curl',
            package_version: '7.68.0',
            first_seen: new Date(Date.now() - 1000 * 60 * 60 * 120).toISOString(),
            last_seen: new Date(Date.now() - 1000 * 60 * 60 * 20).toISOString()
        }
    ],
    user: {
        id: 1,
        username: 'admin',
        is_default_password: false // Falso para que puedas explorar el panel sin que te obligue a cambiar la password
    }
}

export default {
    get: async (url) => {
        return new Promise((resolve) => {
            setTimeout(() => {
                if (url === '/users/me') resolve({ data: mockData.user })
                if (url === '/vulns') resolve({ data: mockData.vulns })
                if (url === '/wazuh-config') resolve({ data: { indexer_url: 'https://mock-indexer:9200', user: 'admin', password: '' } })

                resolve({ data: {} })
            }, MOCK_DELAY)
        })
    },
    post: async (url, data) => {
        return new Promise((resolve, reject) => {
            setTimeout(() => {
                if (url === '/auth/login') {
                    // Acepta cualquier login
                    resolve({ data: { access_token: 'dummy-token-123' } })
                }
                if (url === '/auth/change-password') resolve({ data: { message: 'ok' } })
                if (url === '/users') resolve({ data: { message: 'ok' } })
                if (url === '/vulns/sync') {
                    // Agregar una vulnerabilidad aleatoria al sincronizar
                    mockData.vulns.unshift({
                        id: Date.now(),
                        cve_id: 'CVE-2024-' + Math.floor(Math.random() * 9000 + 1000),
                        severity: ['critical', 'high', 'medium', 'low'][Math.floor(Math.random() * 4)],
                        agent_name: 'agente-nuevo-0' + Math.floor(Math.random() * 9),
                        package_name: 'paquete-random',
                        package_version: '1.0.' + Math.floor(Math.random() * 10),
                        first_seen: new Date().toISOString(),
                        last_seen: new Date().toISOString()
                    })
                    resolve({ data: { synced: 1 } })
                }

                resolve({ data: {} })
            }, MOCK_DELAY)
        })
    },
    put: async (url, data) => {
        return new Promise((resolve) => {
            setTimeout(() => resolve({ data: { message: 'Configuración actualizada.' } }), MOCK_DELAY)
        })
    }
}
