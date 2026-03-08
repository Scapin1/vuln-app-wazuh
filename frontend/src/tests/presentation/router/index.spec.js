import { describe, it, expect, beforeEach } from 'vitest'
import router from '../../../presentation/router/index'

describe('router/index.js global guard', () => {
    beforeEach(() => {
        localStorage.clear()
    })

    // Since we are not mounting the app, we can test the router resolution directly
    it('redirects to /login if navigating to auth route without token', async () => {
        localStorage.removeItem('token')

        // push dashboard, should redirect to login
        await router.push('/dashboard')
        await router.isReady()

        expect(router.currentRoute.value.path).toBe('/login')
    })

    it('allows navigation to auth route with token', async () => {
        localStorage.setItem('token', 'fake-token')

        await router.push('/dashboard')
        await router.isReady()

        expect(router.currentRoute.value.path).toBe('/dashboard')
    })

    it('redirects to /dashboard if logged in and navigating to /login', async () => {
        localStorage.setItem('token', 'fake-token')

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
