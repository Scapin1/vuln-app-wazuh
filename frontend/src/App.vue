<template>
  <div v-if="!isAuthenticated" class="auth-layout">
    <router-view></router-view>
  </div>
  
  <div v-else class="app-layout fade-in">
    <!-- Top Navbar -->
    <nav class="top-navbar">
      <div class="navbar-left">
        <div class="navbar-brand">
          <div class="logo-box">
            <svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="white" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"></path></svg>
          </div>
          <span>VulnSync</span>
        </div>

        <div class="navbar-menu">
          <a href="#" @click.prevent="handleNavClick('/dashboard')" class="nav-item" :class="{ 'router-link-active': route.path === '/dashboard' }">
            <svg xmlns="http://www.w3.org/2000/svg" width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="3" y="3" width="7" height="9"></rect><rect x="14" y="3" width="7" height="5"></rect><rect x="14" y="12" width="7" height="9"></rect><rect x="3" y="16" width="7" height="5"></rect></svg>
            <span>Dashboard</span>
          </a>

          <a href="#" @click.prevent="handleNavClick('/timeline')" class="nav-item" :class="{ 'router-link-active': route.path === '/timeline' }">
            <svg xmlns="http://www.w3.org/2000/svg" width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"></circle><polyline points="12 6 12 12 16 14"></polyline></svg>
            <span>Vulnerabilidades</span>
          </a>
          
          <a href="#" @click.prevent="handleNavClick('/config-user')" class="nav-item" :class="{ 'router-link-active': route.path === '/config-user' }">
            <svg xmlns="http://www.w3.org/2000/svg" width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M17 21v-2a4 4 0 0 0-4-4H5a4 4 0 0 0-4 4v2"></path><circle cx="9" cy="7" r="4"></circle><path d="M23 21v-2a4 4 0 0 0-3-3.87"></path><path d="M16 3.13a4 4 0 0 1 0 7.75"></path></svg>
            <span>Usuarios</span>
          </a>

          <a href="#" @click.prevent="handleNavClick('/config-wazuh')" class="nav-item" :class="{ 'router-link-active': route.path === '/config-wazuh' }">
            <svg xmlns="http://www.w3.org/2000/svg" width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="3"></circle><path d="M19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 0 1 0 2.83 2 2 0 0 1-2.83 0l-.06-.06a1.65 1.65 0 0 0-1.82-.33 1.65 1.65 0 0 0-1 1.51V21a2 2 0 0 1-2 2 2 2 0 0 1-2-2v-.09A1.65 1.65 0 0 0 9 19.4a1.65 1.65 0 0 0-1.82.33l-.06.06a2 2 0 0 1-2.83 0 2 2 0 0 1 0-2.83l.06-.06a1.65 1.65 0 0 0 .33-1.82 1.65 1.65 0 0 0-1.51-1H3a2 2 0 0 1-2-2 2 2 0 0 1 2-2h.09A1.65 1.65 0 0 0 4.6 9a1.65 1.65 0 0 0-.33-1.82l-.06-.06a2 2 0 0 1 0-2.83 2 2 0 0 1 2.83 0l.06.06a1.65 1.65 0 0 0 1.82.33H9a1.65 1.65 0 0 0 1-1.51V3a2 2 0 0 1 2-2 2 2 0 0 1 2 2v.09a1.65 1.65 0 0 0 1 1.51 1.65 1.65 0 0 0 1.82-.33l.06-.06a2 2 0 0 1 2.83 0 2 2 0 0 1 0 2.83l-.06.06a1.65 1.65 0 0 0-.33 1.82V9a1.65 1.65 0 0 0 1.51 1H21a2 2 0 0 1 2 2 2 2 0 0 1-2 2h-.09a1.65 1.65 0 0 0-1.51 1z"></path></svg>
            <span>Conexiones</span>
          </a>
        </div>
      </div>

      <div class="navbar-right">
        <div class="header-user">
          <div class="user-info">
            <span class="user-greeting">Hola,</span>
            <span class="user-name">{{ username }}</span>
          </div>
          <div class="avatar">
            <svg xmlns="http://www.w3.org/2000/svg" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2"></path><circle cx="12" cy="7" r="4"></circle></svg>
          </div>
        </div>

        <div class="navbar-actions">
          <router-link to="/change-password" class="nav-action-btn" title="Cambiar contraseña">
            <svg xmlns="http://www.w3.org/2000/svg" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="3" y="11" width="18" height="11" rx="2" ry="2"></rect><path d="M7 11V7a5 5 0 0 1 10 0v4"></path></svg>
          </router-link>
          <button @click="logout" class="nav-action-btn logout-btn" title="Cerrar sesión">
            <svg xmlns="http://www.w3.org/2000/svg" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4"></path><polyline points="16 17 21 12 16 7"></polyline><line x1="21" y1="12" x2="9" y2="12"></line></svg>
          </button>
        </div>
      </div>
    </nav>

    <!-- Main Content wrapper -->
    <div class="main-wrapper">
      <main class="content">
        <router-view></router-view>
      </main>
    </div>
  </div>
</template>

<script setup>
import { computed, ref, watch } from 'vue'
import { useRouter, useRoute } from 'vue-router'
import Swal from 'sweetalert2'

const router = useRouter()
const route = useRoute()

const username = ref(localStorage.getItem('username') || 'Usuario')

const isAuthenticated = computed(() => {
  return !['Login', 'NotFound'].includes(route.name)
})

watch(() => route.path, () => {
  if (isAuthenticated.value) {
    username.value = localStorage.getItem('username') || 'Usuario'
  }
})

const currentRouteName = computed(() => {
  switch(route.name) {
    case 'VulnAnalytics': return 'Dashboard'
    case 'Timeline': return 'Vulnerabilidades'
    case 'ConfigUser': return 'Gestión de Usuarios'
    case 'ConfigWazuh': return 'Configuración de Wazuh'
    case 'ChangePassword': return 'Seguridad de Cuenta'
    case 'NotFound': return 'Página no encontrada'
    default: return ''
  }
})

const handleNavClick = (path) => {
  const mustChange = localStorage.getItem('must_change_password') === 'true'
  if (mustChange) {
    Swal.fire({
      title: 'Acceso bloqueado',
      text: 'Debes cambiar tu contraseña para continuar navegando.',
      icon: 'warning',
      confirmButtonText: 'Entendido',
      background: 'var(--bg-panel)',
      color: 'var(--text-main)',
      confirmButtonColor: 'var(--primary)',
      iconColor: 'var(--warning, #f59e0b)'
    })
  } else {
    router.push(path)
  }
}

const logout = () => {
  localStorage.removeItem('token')
  localStorage.removeItem('username')
  router.push('/login')
}

</script>

<style scoped>
/* App Layout */
.app-layout {
  display: flex;
  flex-direction: column;
  height: 100vh;
  background-color: var(--bg-dark);
}

.auth-layout {
  min-height: 100vh;
  display: flex;
  align-items: center;
  justify-content: center;
  background: radial-gradient(circle at top, var(--bg-panel) 0%, var(--bg-dark) 100%);
}

/* Top Navbar */
.top-navbar {
  height: 70px;
  background-color: var(--bg-panel);
  border-bottom: 1px solid var(--border);
  display: flex;
  align-items: center;
  justify-content: space-between;
  padding: 0 2rem;
  gap: 2rem;
  flex-shrink: 0;
}

.navbar-left {
  display: flex;
  align-items: center;
  gap: 2rem;
  flex: 1;
}

.navbar-brand {
  display: flex;
  align-items: center;
  gap: 0.75rem;
  font-size: 1.1rem;
  font-weight: 700;
  color: var(--text-main);
  white-space: nowrap;
  flex-shrink: 0;
}

.logo-box {
  width: 36px;
  height: 36px;
  background: var(--primary);
  border-radius: 8px;
  display: flex;
  align-items: center;
  justify-content: center;
  color: #000;
  box-shadow: 0 0 12px var(--primary-glow);
  flex-shrink: 0;
}

.navbar-menu {
  display: flex;
  align-items: center;
  gap: 0.5rem;
}

.nav-item {
  display: flex;
  align-items: center;
  gap: 0.5rem;
  padding: 0.5rem 1rem;
  color: var(--text-muted);
  font-weight: 500;
  font-size: 0.9rem;
  transition: var(--transition);
  border-bottom: 2px solid transparent;
  background: transparent;
  border: none;
  cursor: pointer;
  white-space: nowrap;
}

.nav-item span {
  display: inline-block;
}

.nav-item:hover {
  color: var(--primary);
  background-color: rgba(31, 138, 59, 0.1);
}

.nav-item.router-link-active {
  color: var(--primary);
  border-bottom-color: var(--primary);
}

.nav-item.router-link-active svg {
  color: var(--primary);
}

.nav-item svg {
  color: currentColor;
}

.navbar-right {
  display: flex;
  align-items: center;
  gap: 1.5rem;
  flex-shrink: 0;
}

.header-user {
  display: flex;
  align-items: center;
  gap: 0.75rem;
}

.user-info {
  display: flex;
  flex-direction: column;
  text-align: right;
}

.user-greeting {
  font-size: 0.75rem;
  color: var(--text-muted);
}

.user-name {
  font-size: 0.85rem;
  font-weight: 600;
  color: var(--text-main);
}

.avatar {
  width: 36px;
  height: 36px;
  border-radius: 50%;
  background-color: var(--bg-hover);
  display: flex;
  align-items: center;
  justify-content: center;
  color: var(--text-muted);
  border: 1px solid var(--border);
  flex-shrink: 0;
}

.navbar-actions {
  display: flex;
  align-items: center;
  gap: 0.5rem;
  border-left: 1px solid var(--border);
  padding-left: 1rem;
}

.nav-action-btn {
  display: flex;
  align-items: center;
  justify-content: center;
  width: 36px;
  height: 36px;
  border-radius: 6px;
  background-color: transparent;
  color: var(--text-muted);
  border: 1px solid transparent;
  cursor: pointer;
  transition: var(--transition);
  flex-shrink: 0;
}

.nav-action-btn:hover {
  color: var(--primary);
  background-color: rgba(31, 138, 59, 0.1);
  border-color: rgba(31, 138, 59, 0.2);
}

.nav-action-btn.logout-btn:hover {
  color: var(--danger);
  background-color: rgba(220, 38, 38, 0.1);
  border-color: rgba(220, 38, 38, 0.2);
}

/* Main Content Wrapper */
.main-wrapper {
  flex-grow: 1;
  display: flex;
  flex-direction: column;
  overflow: hidden;
}

/* Content Area */
.content {
  flex-grow: 1;
  overflow-y: auto;
  overflow-x: hidden;
  padding: 2.5rem;
}

/* Responsive */
@media (max-width: 1200px) {
  .top-navbar {
    padding: 0 1.5rem;
    gap: 1.5rem;
  }
  
  .nav-item span {
    display: none;
  }
  
  .nav-item {
    padding: 0.5rem;
  }
}

@media (max-width: 768px) {
  .navbar-left {
    gap: 1rem;
  }
  
  .navbar-menu {
    gap: 0.25rem;
  }
  
  .user-greeting {
    display: none;
  }
  
  .content {
    padding: 1.5rem;
  }
}
</style>
