import { describe, it, expect, vi, beforeEach } from 'vitest'
import { mount, flushPromises } from '@vue/test-utils'
import ChangePassword from '@/presentation/views/ChangePassword.vue'
import authService from '@/application/services/authService'

vi.mock('@/application/services/authService', () => ({
    default: {
        changePassword: vi.fn()
    }
}))

const mockPush = vi.fn()
vi.mock('vue-router', () => ({
    useRouter: () => ({
        push: mockPush
    })
}))

describe('ChangePassword.vue', () => {
    beforeEach(() => {
        vi.clearAllMocks()
        sessionStorage.clear()
    })

    it('renders correctly and checks security message from sessionStorage', async () => {
        sessionStorage.setItem('force_password_message', 'Debes cambiar la contraseña')

        const wrapper = mount(ChangePassword)
        await flushPromises()

        expect(wrapper.text()).toContain('Debes cambiar la contraseña')
        expect(sessionStorage.getItem('force_password_message')).toBeNull() // gets cleared
    })

    it('shows error if new passwords do not match', async () => {
        const wrapper = mount(ChangePassword)

        wrapper.vm.oldPassword = 'oldpass'
        wrapper.vm.newPassword = 'newpass'
        wrapper.vm.confirmPassword = 'newpass123'

        await wrapper.find('form').trigger('submit.prevent')

        expect(wrapper.vm.error).toBe('Las contraseñas no coinciden.')
        expect(authService.changePassword).not.toHaveBeenCalled()
    })

    it('submits change password correctly and redirects to dashboard', async () => {
        const wrapper = mount(ChangePassword)

        wrapper.vm.oldPassword = 'oldpass'
        wrapper.vm.newPassword = 'newpass'
        wrapper.vm.confirmPassword = 'newpass'

        authService.changePassword.mockResolvedValueOnce({})

        await wrapper.find('form').trigger('submit.prevent')
        await flushPromises()

        expect(authService.changePassword).toHaveBeenCalledWith({
            old_password: 'oldpass',
            new_password: 'newpass',
            confirm_password: 'newpass'
        })

        expect(wrapper.vm.success).toBe('Contraseña actualizada correctamente.')
        expect(mockPush).toHaveBeenCalledWith('/dashboard')
    })

    it('handles change password error gracefully', async () => {
        const wrapper = mount(ChangePassword)

        wrapper.vm.oldPassword = 'oldpass'
        wrapper.vm.newPassword = 'newpass'
        wrapper.vm.confirmPassword = 'newpass'

        authService.changePassword.mockRejectedValueOnce({ response: { data: { detail: 'Wrong old password' } } })

        await wrapper.find('form').trigger('submit.prevent')
        await flushPromises()

        expect(wrapper.vm.error).toBe('Wrong old password')
    })

    it('toggles password visibility', async () => {
        const wrapper = mount(ChangePassword)

        expect(wrapper.vm.showOldPassword).toBe(false)
        await wrapper.findAll('.eye-btn')[0].trigger('click')
        expect(wrapper.vm.showOldPassword).toBe(true)

        expect(wrapper.vm.showNewPassword).toBe(false)
        await wrapper.findAll('.eye-btn')[1].trigger('click')
        expect(wrapper.vm.showNewPassword).toBe(true)

        expect(wrapper.vm.showConfirmPassword).toBe(false)
        await wrapper.findAll('.eye-btn')[2].trigger('click')
        expect(wrapper.vm.showConfirmPassword).toBe(true)
    })
})
