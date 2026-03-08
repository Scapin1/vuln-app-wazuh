import { describe, it, expect, vi, beforeEach } from 'vitest'
import { mount } from '@vue/test-utils'
import App from '@/App.vue'
import Swal from 'sweetalert2'

// Mock sweetalert2
vi.mock('sweetalert2', () => ({
    default: {
        fire: vi.fn()
    }
}))

// Mock router
const mockPush = vi.fn()
const mockRoute = {
    name: 'Dashboard',
    path: '/dashboard'
}

vi.mock('vue-router', () => ({
    useRouter: () => ({
        push: mockPush
    }),
    useRoute: () => mockRoute
}))

describe('App.vue', () => {
    beforeEach(() => {
        vi.clearAllMocks()
        localStorage.clear()
        mockRoute.name = 'Dashboard'
        mockRoute.path = '/dashboard'
    })

    it('renders auth layout when on Login route', async () => {
        mockRoute.name = 'Login'
        mockRoute.path = '/login'

        // El app layout no debiera estar
        const wrapper = mount(App, {
            global: {
                stubs: ['router-view', 'router-link']
            }
        })

        expect(wrapper.find('.auth-layout').exists()).toBe(true)
        expect(wrapper.find('.app-layout').exists()).toBe(false)
    })

    it('renders app layout and currentRouteName when authenticated', () => {
        mockRoute.name = 'ConfigUser'
        mockRoute.path = '/config-user'

        const wrapper = mount(App, {
            global: {
                stubs: ['router-view', 'router-link']
            }
        })

        expect(wrapper.find('.app-layout').exists()).toBe(true)
        expect(wrapper.find('.header-title').text()).toBe('Gestión de Usuarios')
    })

    it('blocks navigation and shows alert if must_change_password is true', async () => {
        localStorage.setItem('must_change_password', 'true')

        const wrapper = mount(App, {
            global: {
                stubs: ['router-view', 'router-link']
            }
        })

        // Simulate clicking dashboard in sidebar
        const dashboardLink = wrapper.findAll('.nav-item').find(el => el.text().includes('Dashboard'))
        await dashboardLink.trigger('click')

        expect(Swal.fire).toHaveBeenCalled()
        expect(mockPush).not.toHaveBeenCalled()
    })

    it('allows navigation if must_change_password is false or not set', async () => {
        const wrapper = mount(App, {
            global: {
                stubs: ['router-view', 'router-link']
            }
        })

        const dashboardLink = wrapper.findAll('.nav-item').find(el => el.text().includes('Dashboard'))
        await dashboardLink.trigger('click')

        expect(Swal.fire).not.toHaveBeenCalled()
        expect(mockPush).toHaveBeenCalledWith('/dashboard')
    })

    it('logs out and clears localStorage', async () => {
        localStorage.setItem('token', 'fake-token')
        localStorage.setItem('username', 'admin')

        const wrapper = mount(App, {
            global: {
                stubs: ['router-view', 'router-link']
            }
        })

        const logoutBtn = wrapper.find('.logout-btn')
        await logoutBtn.trigger('click')

        expect(localStorage.getItem('token')).toBeNull()
        expect(localStorage.getItem('username')).toBeNull()
        expect(mockPush).toHaveBeenCalledWith('/login')
    })
})
