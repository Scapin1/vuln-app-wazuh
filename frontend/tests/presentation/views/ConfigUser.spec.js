import { describe, it, expect, vi, beforeEach } from 'vitest'
import { mount, flushPromises } from '@vue/test-utils'
import ConfigUser from '@/presentation/views/ConfigUser.vue'
import userService from '@/application/services/userService'
import Swal from 'sweetalert2'

vi.mock('@/application/services/userService', () => ({
    default: {
        getUsers: vi.fn(),
        createUser: vi.fn(),
        deleteUser: vi.fn()
    }
}))

vi.mock('sweetalert2', () => ({
    default: {
        fire: vi.fn()
    }
}))

describe('ConfigUser.vue', () => {
    const mockUsers = [
        { id: 1, username: 'admin' },
        { id: 2, username: 'analista' }
    ]

    beforeEach(() => {
        vi.clearAllMocks()
        userService.getUsers.mockResolvedValue({ data: mockUsers })
    })

    it('fetches and displays users on mount', async () => {
        const wrapper = mount(ConfigUser)
        expect(wrapper.vm.loadingUsers).toBe(true)

        await flushPromises()

        expect(wrapper.vm.loadingUsers).toBe(false)
        expect(userService.getUsers).toHaveBeenCalledTimes(1)
        expect(wrapper.vm.users.length).toBe(2)

        const rows = wrapper.findAll('tbody tr')
        expect(rows.length).toBe(2)
        expect(rows[0].text()).toContain('admin')
        expect(rows[1].text()).toContain('analista')
    })

    it('shows error if fetch users fails', async () => {
        userService.getUsers.mockRejectedValueOnce(new Error('Network Error'))
        const wrapper = mount(ConfigUser)

        await flushPromises()

        expect(wrapper.vm.usersError).toBe('No se pudieron cargar los administradores.')
        expect(wrapper.vm.users.length).toBe(0)
    })

    it('opens and closes add user modal', async () => {
        const wrapper = mount(ConfigUser)
        await flushPromises()

        // Open modal
        await wrapper.find('.btn-primary').trigger('click')
        expect(wrapper.vm.showAddModal).toBe(true)

        // Close modal via Cancel button
        const cancelBtn = wrapper.findAll('.btn-outline').find(b => b.text().includes('Cancelar'))
        await cancelBtn.trigger('click')
        expect(wrapper.vm.showAddModal).toBe(false)
    })

    it('submits new user correctly', async () => {
        const wrapper = mount(ConfigUser)
        await flushPromises()

        await wrapper.find('.btn-primary').trigger('click')

        wrapper.vm.newUser.user_name = 'new_admin'
        wrapper.vm.newUser.user_email = 'new_admin@empresa.com'
        wrapper.vm.newUser.user_rol = 'admin'
        wrapper.vm.newUser.user_password = 'SuperSecret123'

        userService.createUser.mockResolvedValueOnce({})

        await wrapper.find('form').trigger('submit.prevent')
        await flushPromises()

        expect(userService.createUser).toHaveBeenCalledWith({
            user_name: 'new_admin',
            user_email: 'new_admin@empresa.com',
            user_rol: 'admin',
            user_password: 'SuperSecret123'
        })
        expect(wrapper.vm.showAddModal).toBe(false)
        expect(userService.getUsers).toHaveBeenCalledTimes(2) // 1 initial, 1 after add
    })

    it('shows error when creating user without data', async () => {
        const wrapper = mount(ConfigUser)
        await flushPromises()

        await wrapper.find('.btn-primary').trigger('click')

        wrapper.vm.newUser.user_name = ''
        wrapper.vm.newUser.user_email = ''
        wrapper.vm.newUser.user_password = ''

        await wrapper.find('form').trigger('submit.prevent')

        expect(wrapper.vm.error).toContain('Todos los campos son requeridos.')
        expect(userService.createUser).not.toHaveBeenCalled()
    })

    it('handles user creation failure gracefully', async () => {
        const wrapper = mount(ConfigUser)
        await flushPromises()

        await wrapper.find('.btn-primary').trigger('click')
        wrapper.vm.newUser.user_name = 'fail_user'
        wrapper.vm.newUser.user_email = 'fail@empresa.com'
        wrapper.vm.newUser.user_rol = 'admin'
        wrapper.vm.newUser.user_password = 'pass123'

        userService.createUser.mockRejectedValueOnce({ response: { data: { detail: 'User exists' } } })

        await wrapper.find('form').trigger('submit.prevent')
        await flushPromises()

        expect(wrapper.vm.error).toBe('User exists')
        expect(wrapper.vm.showAddModal).toBe(true) // Should remain open
    })

    it('deletes user successfully after confirmation', async () => {
        const wrapper = mount(ConfigUser)
        await flushPromises()

        Swal.fire.mockResolvedValueOnce({ isConfirmed: true })
        userService.deleteUser.mockResolvedValueOnce({})

        const deleteBtn = wrapper.findAll('tbody tr')[0].find('.btn-icon-danger')
        await deleteBtn.trigger('click')

        await flushPromises()

        expect(userService.deleteUser).toHaveBeenCalledWith(1)
        expect(userService.getUsers).toHaveBeenCalledTimes(2)
    })

    it('does nothing if delete is cancelled', async () => {
        const wrapper = mount(ConfigUser)
        await flushPromises()

        Swal.fire.mockResolvedValueOnce({ isConfirmed: false })

        const deleteBtn = wrapper.findAll('tbody tr')[0].find('.btn-icon-danger')
        await deleteBtn.trigger('click')

        await flushPromises()

        expect(userService.deleteUser).not.toHaveBeenCalled()
    })

    it('handles delete failure gracefully', async () => {
        const wrapper = mount(ConfigUser)
        await flushPromises()

        Swal.fire.mockResolvedValueOnce({ isConfirmed: true })
        userService.deleteUser.mockRejectedValueOnce(new Error('Server error'))

        const deleteBtn = wrapper.findAll('tbody tr')[0].find('.btn-icon-danger')
        await deleteBtn.trigger('click')
        await flushPromises()

        expect(Swal.fire).toHaveBeenCalledWith(
            expect.objectContaining({ icon: 'error' })
        )
    })

    it('handles generic create error without detail field', async () => {
        const wrapper = mount(ConfigUser)
        await flushPromises()

        await wrapper.find('.btn-primary').trigger('click')
        wrapper.vm.newUser.user_name = 'test'
        wrapper.vm.newUser.user_email = 'test@test.com'
        wrapper.vm.newUser.user_password = 'pass123'

        userService.createUser.mockRejectedValueOnce(new Error('Network error'))

        await wrapper.find('form').trigger('submit.prevent')
        await flushPromises()

        expect(wrapper.vm.error).toBe('Error al crear el usuario. Asegúrate de que no exista.')
    })

    it('handles nested response data format', async () => {
        userService.getUsers.mockResolvedValueOnce({ data: { data: [{ id: 10, username: 'nested' }] } })
        const wrapper = mount(ConfigUser)
        await flushPromises()

        expect(wrapper.vm.users.length).toBe(1)
        expect(wrapper.vm.users[0].username).toBe('nested')
    })
})
