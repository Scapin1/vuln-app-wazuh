import { createRouter, createWebHistory } from 'vue-router'
import Login from '../views/Login.vue'
import Dashboard from '../views/Dashboard.vue'
import ConfigUser from '../views/ConfigUser.vue'
import ConfigWazuh from '../views/ConfigWazuh.vue'
import ChangePassword from '../views/ChangePassword.vue'
import NotFound from '../views/NotFound.vue'

const routes = [
  { path: '/login', name: 'Login', component: Login },
  { path: '/', redirect: '/login' },
  { path: '/dashboard', name: 'Dashboard', component: Dashboard, meta: { requiresAuth: true } },
  { path: '/config-user', name: 'ConfigUser', component: ConfigUser, meta: { requiresAuth: true } },
  { path: '/config-wazuh', name: 'ConfigWazuh', component: ConfigWazuh, meta: { requiresAuth: true } },
  { path: '/change-password', name: 'ChangePassword', component: ChangePassword, meta: { requiresAuth: true } },
  { path: '/:pathMatch(.*)*', name: 'NotFound', component: NotFound },
]

const router = createRouter({
  history: createWebHistory(),
  routes
})

router.beforeEach((to, from) => {
  const token = localStorage.getItem('token')
  const requiresAuth = to.matched.some(record => record.meta.requiresAuth)

  if (to.matched.length === 0) {
    return '/login'
  }

  if (requiresAuth && !token) {
    return '/login'
  }

  if (token && to.path === '/login') {
    return '/dashboard'
  }

  return true
})

export default router
