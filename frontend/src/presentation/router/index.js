import { createRouter, createWebHistory } from 'vue-router'
import Login from '../views/Login.vue'
import Dashboard from '../views/Dashboard.vue'
import ConfigUser from '../views/ConfigUser.vue'
import ConfigWazuh from '../views/ConfigWazuh.vue'
import ChangePassword from '../views/ChangePassword.vue'

const routes = [
  { path: '/', redirect: '/dashboard' },
  { path: '/login', name: 'Login', component: Login },
  { path: '/dashboard', name: 'Dashboard', component: Dashboard, meta: { requiresAuth: true } },
  { path: '/config-user', name: 'ConfigUser', component: ConfigUser, meta: { requiresAuth: true } },
  { path: '/config-wazuh', name: 'ConfigWazuh', component: ConfigWazuh, meta: { requiresAuth: true } },
  { path: '/change-password', name: 'ChangePassword', component: ChangePassword, meta: { requiresAuth: true } },
]

const router = createRouter({
  history: createWebHistory(),
  routes
})

router.beforeEach((to, from ) => {
  const token = localStorage.getItem('token')
  const requiresAuth = to.matched.some(record => record.meta.requiresAuth)
  const username = localStorage.getItem('username')
  const passwordChanged = username
    ? localStorage.getItem(`pwd_changed_${username}`)
    : null

  // si la ruta requiere auten- pero no tiene token
  if (requiresAuth && !token) { 
    next('/login')
    return
  } 

  // Si ya está logeado pero no ha cambiado contraseña,
  // solo puede entrar a /change-password
  if (token && passwordChanged !== 'true' && to.path !== '/change-password') {
    sessionStorage.setItem(
      'force_password_message',
      'Para seguir navegando, debes cambiar tu contraseña.'
    )
    return '/change-password'
  }

  // Si ya cambió contraseña y trata de ir al login, lo mandas al dashboard
  if (token && passwordChanged === 'true' && to.path === '/login') {
    return '/'
  }
  
  return true
})

export default router
