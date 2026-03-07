import { createRouter, createWebHistory } from 'vue-router'
import Login from '../views/Login.vue'
import Dashboard from '../views/Dashboard.vue'
import AddUser from '../views/AddUser.vue'
import Config from '../views/Config.vue'
import ChangePassword from '../views/ChangePassword.vue'

const routes = [
  { path: '/', redirect: '/dashboard' },
  { path: '/login', name: 'Login', component: Login },
  { path: '/dashboard', name: 'Dashboard', component: Dashboard, meta: { requiresAuth: true } },
  { path: '/add-user', name: 'AddUser', component: AddUser, meta: { requiresAuth: true } },
  { path: '/config', name: 'Config', component: Config, meta: { requiresAuth: true } },
  { path: '/change-password', name: 'ChangePassword', component: ChangePassword, meta: { requiresAuth: true } },
]

const router = createRouter({
  history: createWebHistory(),
  routes
})

router.beforeEach((to, from, next) => {
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

  if (token && passwordChanged !== 'true' && to.path !== '/change-password') {
    sessionStorage.setItem(
      'force_password_message',
      'Para seguir navegando, debes cambiar tu contraseña.'
    )
    return next('/change-password')
  }

  // Si ya está logeado pero no ha cambiado contraseña,
  // solo puede entrar a /change-password
  if (token && passwordChanged !== 'true' && to.path !== '/change-password') {
    return next('/change-password')
  }

  // Si ya cambió contraseña y trata de ir al login, lo mandas al dashboard
  if (token && passwordChanged === 'true' && to.path === '/login') {
    return next('/dashboard')
  }
  
  next()
})

export default router
