import { describe, it, expect, vi, beforeEach } from 'vitest'
import { mount, flushPromises } from '@vue/test-utils'
import ConfigWazuh from '@/presentation/views/ConfigWazuh.vue'
import wazuhService from '@/application/services/wazuhService'
import Swal from 'sweetalert2'

vi.mock('@/application/services/wazuhService', () => ({
    default: {
        getConnections: vi.fn(),
        createConnection: vi.fn(),
        editConnection: vi.fn(),
        deleteConnection: vi.fn(),
        testConnection: vi.fn(() => Promise.resolve({ data: { success: true } }))
    }
}))

vi.mock('sweetalert2', () => ({
    default: {
        fire: vi.fn()
    }
}))

describe('ConfigWazuh.vue', () => {
    const mockConnections = [
        { id: 1, name: 'Prod Cluster', indexer_url: 'https://prod:9200', wazuh_user: 'admin', is_active: true },
        { id: 2, name: 'Dev Cluster', indexer_url: 'https://dev:9200', wazuh_user: 'admin', is_active: false }
    ]

    beforeEach(() => {
        vi.clearAllMocks()
        wazuhService.getConnections.mockResolvedValue({ data: mockConnections })
    })

    it('fetches and displays connections on mount', async () => {
        const wrapper = mount(ConfigWazuh)
        expect(wrapper.vm.loadingConns).toBe(true)

        await flushPromises()

        expect(wrapper.vm.loadingConns).toBe(false)
        expect(wazuhService.getConnections).toHaveBeenCalledTimes(1)
        expect(wrapper.vm.connections.length).toBe(2)

        const rows = wrapper.findAll('tbody tr')
        expect(rows.length).toBe(2)
        expect(rows[0].text()).toContain('Prod Cluster')
        expect(rows[0].text()).toContain('ACTIVO')
        expect(rows[1].text()).toContain('INACTIVO')
    })

    it('shows error if fetch connections fails', async () => {
        wazuhService.getConnections.mockRejectedValueOnce(new Error('Network Error'))
        const wrapper = mount(ConfigWazuh)

        await flushPromises()

        expect(wrapper.vm.connsError).toBe('No se pudieron cargar las conexiones.')
        expect(wrapper.vm.connections.length).toBe(0)
    })

    it('opens add connection modal', async () => {
        const wrapper = mount(ConfigWazuh)
        await flushPromises()

        await wrapper.find('.btn-primary').trigger('click')

        expect(wrapper.vm.showAddModal).toBe(true)
        expect(wrapper.vm.isEditing).toBe(false)

        // Check if modal title is correct
        const modalTitle = wrapper.find('.modal-content .title')
        expect(modalTitle.text()).toBe('Añadir nueva conexión')
    })

    it('opens edit connection modal and populates data', async () => {
        // Cambiamos el índice a 1 porque el botón 0 es el de probar conexión
        const editBtn = wrapper.findAll('tbody tr')[0].findAll('.btn-icon')[1] 
        await editBtn.trigger('click')
        await flushPromises() // Esperamos a que el modal aparezca en el DOM

        expect(wrapper.vm.showAddModal).toBe(true)
        expect(wrapper.vm.isEditing).toBe(true)
        expect(wrapper.vm.newConn.name).toBe('Prod Cluster')
    })
    it('submits new connection correctly', async () => {
        const wrapper = mount(ConfigWazuh)
        await flushPromises()

        // Abrir modal
        await wrapper.find('.btn-primary').trigger('click')

        // Llenar datos
        wrapper.vm.newConn.name = 'New Conn'
        wrapper.vm.newConn.indexer_url = 'https://new:9200'
        wrapper.vm.newConn.wazuh_user = 'user'
        wrapper.vm.newConn.wazuh_password = 'pass'

        wazuhService.createConnection.mockResolvedValueOnce({})

        // Enviar el form
        await wrapper.find('form').trigger('submit.prevent')
        await flushPromises()

        expect(wazuhService.createConnection).toHaveBeenCalledWith({
            name: 'New Conn',
            indexer_url: 'https://new:9200',
            wazuh_user: 'user',
            wazuh_password: 'pass'
        })

        expect(wrapper.vm.showAddModal).toBe(false)
        expect(wazuhService.getConnections).toHaveBeenCalledTimes(2) // Una initial, otra tras guardar
    })

    it('shows error on empty required fields submission', async () => {
        const wrapper = mount(ConfigWazuh)
        await flushPromises()

        await wrapper.find('.btn-primary').trigger('click')

        // Dejar name vacío
        wrapper.vm.newConn.name = ''
        wrapper.vm.newConn.indexer_url = 'https://new:9200'
        wrapper.vm.newConn.wazuh_user = 'user'

        await wrapper.find('form').trigger('submit.prevent')

        expect(wrapper.vm.newConnError).toContain('completa todos')
        expect(wazuhService.createConnection).not.toHaveBeenCalled()
    })

    it('handles edit connection fail gracefully', async () => {
        wazuhService.editConnection.mockRejectedValueOnce({ response: { data: { message: 'Error' } } })

        // Abrimos el modal primero (usando índice 1)
        const editBtn = wrapper.findAll('tbody tr')[0].findAll('.btn-icon')[1]
        await editBtn.trigger('click')
        await flushPromises()

        // Ahora el formulario sí existe y podemos hacer el submit
        await wrapper.find('form').trigger('submit.prevent')
        await flushPromises()

        expect(wazuhService.editConnection).toHaveBeenCalled()
    })

    it('deletes connection successfully confirmed', async () => {
        const wrapper = mount(ConfigWazuh)
        await flushPromises()

        // Mock confirm dialog
        Swal.fire.mockResolvedValueOnce({ isConfirmed: true })
        wazuhService.deleteConnection.mockResolvedValueOnce({})

        const deleteBtn = wrapper.findAll('tbody tr')[0].findAll('.btn-icon')[2]
        await deleteBtn.trigger('click')

        await flushPromises()

        expect(wazuhService.deleteConnection).toHaveBeenCalledWith(1) // ID = 1
        expect(wazuhService.getConnections).toHaveBeenCalledTimes(2) // re-fetch
    })

    it('does nothing if delete is cancelled', async () => {
        const wrapper = mount(ConfigWazuh)
        await flushPromises()

        // Mock cancel dialog
        Swal.fire.mockResolvedValueOnce({ isConfirmed: false })

        const deleteBtn = wrapper.findAll('tbody tr')[0].findAll('.btn-icon')[1]
        await deleteBtn.trigger('click')

        await flushPromises()

        expect(wazuhService.deleteConnection).not.toHaveBeenCalled()
    })
})

