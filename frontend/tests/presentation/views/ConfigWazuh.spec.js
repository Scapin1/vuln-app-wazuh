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
        await flushPromises()
        expect(wrapper.vm.connections.length).toBe(2)
    })

    it('opens edit connection modal and populates data', async () => {
        const wrapper = mount(ConfigWazuh) // <--- Agregamos esto
        await flushPromises()

        // El botón de editar es el índice 1 (0: Probar, 1: Editar, 2: Eliminar)
        const editBtn = wrapper.findAll('tbody tr')[0].findAll('.btn-icon')[1] 
        await editBtn.trigger('click')
        await flushPromises()

        expect(wrapper.vm.showAddModal).toBe(true)
        expect(wrapper.vm.isEditing).toBe(true)
        expect(wrapper.vm.newConn.name).toBe('Prod Cluster')
    })

    it('handles edit connection fail gracefully', async () => {
        wazuhService.editConnection.mockRejectedValueOnce({ response: { data: { message: 'Error' } } })
        const wrapper = mount(ConfigWazuh) // <--- Agregamos esto
        await flushPromises()

        const editBtn = wrapper.findAll('tbody tr')[0].findAll('.btn-icon')[1]
        await editBtn.trigger('click')
        await flushPromises()

        await wrapper.find('form').trigger('submit.prevent')
        await flushPromises()

        expect(wazuhService.editConnection).toHaveBeenCalled()
    })

    it('deletes connection successfully confirmed', async () => {
        const wrapper = mount(ConfigWazuh)
        await flushPromises()

        Swal.fire.mockResolvedValueOnce({ isConfirmed: true })
        wazuhService.deleteConnection.mockResolvedValueOnce({})

        const deleteBtn = wrapper.findAll('tbody tr')[0].findAll('.btn-icon')[2]
        await deleteBtn.trigger('click')
        await flushPromises()

        expect(wazuhService.deleteConnection).toHaveBeenCalledWith(1)
    })

    it('does nothing if delete is cancelled', async () => {
        const wrapper = mount(ConfigWazuh)
        await flushPromises()

        Swal.fire.mockResolvedValueOnce({ isConfirmed: false })

        const deleteBtn = wrapper.findAll('tbody tr')[0].findAll('.btn-icon')[2] // <--- Índice 2
        await deleteBtn.trigger('click')
        await flushPromises()

        expect(wazuhService.deleteConnection).not.toHaveBeenCalled()
    })
})
