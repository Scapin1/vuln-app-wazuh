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
        { id: 1, name: 'Prod Cluster', indexer_url: 'https://prod:9200', wazuh_user: 'admin', is_active: true }
    ]

    beforeEach(() => {
        vi.clearAllMocks()
        wazuhService.getConnections.mockResolvedValue({ data: mockConnections })
    })

    it('opens edit connection modal and populates data', async () => {
        const wrapper = mount(ConfigWazuh)
        await flushPromises()

        // Buscamos el botón por su atributo title, que es infalible
        const editBtn = wrapper.find('button[title="Editar"]')
        await editBtn.trigger('click')
        await flushPromises()

        expect(wrapper.vm.showAddModal).toBe(true)
        expect(wrapper.vm.isEditing).toBe(true)
        expect(wrapper.vm.newConn.name).toBe('Prod Cluster')
    })

    it('handles edit connection fail gracefully', async () => {
        wazuhService.editConnection.mockRejectedValueOnce({ response: { data: { message: 'Error' } } })
        const wrapper = mount(ConfigWazuh)
        await flushPromises()

        await wrapper.find('button[title="Editar"]').trigger('click')
        await flushPromises()

        await wrapper.find('form').trigger('submit.prevent')
        await flushPromises()

        expect(wazuhService.editConnection).toHaveBeenCalled()
        expect(wrapper.vm.newConnError).toBe('Error')
    })

    it('deletes connection successfully confirmed', async () => {
        const wrapper = mount(ConfigWazuh)
        await flushPromises()

        Swal.fire.mockResolvedValueOnce({ isConfirmed: true })
        wazuhService.deleteConnection.mockResolvedValueOnce({})

        await wrapper.find('button[title="Eliminar"]').trigger('click')
        await flushPromises()

        expect(wazuhService.deleteConnection).toHaveBeenCalledWith(1)
    })
})
