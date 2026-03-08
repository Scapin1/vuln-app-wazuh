import { describe, it, expect, beforeEach, vi } from 'vitest'
import router from '@/presentation/router/index'
import userService from '@/application/services/userService'

// 1. OBLIGATORIO: Simular el servicio que usa el router
vi.mock('@/application/services/userService', () => ({
    default: {
        getUserMe: vi.fn()
    }
}))

describe('router/index.js global guard', () => {
    beforeEach(() => {
        localStorage.clear()
        vi.clearAllMocks()
    })

    it('redirects to /login if navigating to auth route without token', async () => {
        await router.push('/dashboard')
        await router.isReady()
        expect(router.currentRoute.value.path).toBe('/login')
    })

    it('allows navigation to auth route with token', async () => {
        localStorage.setItem('token', 'fake-token')
        // 2. Simulamos que el backend responde que el usuario está OK y NO tiene pass por defecto
        userService.getUserMe.mockResolvedValueOnce({ data: { is_default_password: false } })

        await router.push('/dashboard')
        await router.isReady()

        expect(router.currentRoute.value.path).toBe('/dashboard')
    })

    it('redirects to /dashboard if logged in and navigating to /login', async () => {
        localStorage.setItem('token', 'fake-token')
        userService.getUserMe.mockResolvedValueOnce({ data: { is_default_password: false } })

        await router.push('/login')
        await router.isReady()

        expect(router.currentRoute.value.path).toBe('/dashboard')
    })

    it('renders NotFound component for unknown routes correctly', async () => {
        await router.push('/non-existent-route-123')
        await router.isReady()
        expect(router.currentRoute.value.name).toBe('NotFound')
    })
})
