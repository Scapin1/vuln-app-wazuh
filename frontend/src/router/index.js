import { createRouter, createWebHistory } from 'vue-router'
import Login from '../views/Login.vue'
import Dashboard from '../views/Dashboard.vue'
import AddUser from '../views/AddUser.vue'
import Config from '../views/Config.vue'
import ChangePassword from '../views/ChangePassword.vue'

const routes = [
  { path: '/login', name: 'Login', component: Login },
  { path: '/', name: 'Dashboard', component: Dashboard, meta: { requiresAuth: true } },
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

  if (requiresAuth && !token) {
    next('/login')
  } else {
    next()
  }
})

export default router
