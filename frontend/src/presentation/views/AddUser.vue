<template>
  <div class="card max-w-lg fade-in">
    <div class="card-header">
      <div class="icon-box">
        <svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M16 21v-2a4 4 0 0 0-4-4H5a4 4 0 0 0-4 4v2"></path><circle cx="8.5" cy="7" r="4"></circle><line x1="20" y1="8" x2="20" y2="14"></line><line x1="23" y1="11" x2="17" y2="11"></line></svg>
      </div>
      <div>
        <h1 class="title">Añadir Nuevo Administrador</h1>
        <p class="subtitle" style="margin-bottom:0">Registra nuevos usuarios con acceso a la plataforma.</p>
      </div>
    </div>

    <form @submit.prevent="handleAddUser" class="mt-4">
      <div class="form-group">
        <label class="form-label">Nombre de usuario</label>
        <div class="input-icon">
          <svg class="icon" xmlns="http://www.w3.org/2000/svg" width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2"></path><circle cx="12" cy="7" r="4"></circle></svg>
          <input type="text" v-model="username" class="form-input" required placeholder="Ej: analista_soc">
        </div>
      </div>
      
      <div class="form-group">
        <label class="form-label">Contraseña inicial</label>
        <div class="input-icon">
          <svg class="icon" xmlns="http://www.w3.org/2000/svg" width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="3" y="11" width="18" height="11" rx="2" ry="2"></rect><path d="M7 11V7a5 5 0 0 1 10 0v4"></path></svg>
          <input type="password" v-model="password" class="form-input" required placeholder="••••••••">
        </div>
      </div>

      <div v-if="error" class="alert alert-danger fade-in">
        <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"></circle><line x1="12" y1="8" x2="12" y2="12"></line><line x1="12" y1="16" x2="12.01" y2="16"></line></svg>
        {{ error }}
      </div>
      
      <div v-if="success" class="alert alert-success fade-in">
        <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"></path><polyline points="22 4 12 14.01 9 11.01"></polyline></svg>
        {{ success }}
      </div>

      <button type="submit" class="btn btn-primary" :disabled="loading" style="margin-top: 1rem;">
        <svg v-if="loading" class="spin" xmlns="http://www.w3.org/2000/svg" width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><line x1="12" y1="2" x2="12" y2="6"></line><line x1="12" y1="18" x2="12" y2="22"></line><line x1="4.93" y1="4.93" x2="7.76" y2="7.76"></line><line x1="16.24" y1="16.24" x2="19.07" y2="19.07"></line><line x1="2" y1="12" x2="6" y2="12"></line><line x1="18" y1="12" x2="22" y2="12"></line><line x1="4.93" y1="19.07" x2="7.76" y2="16.24"></line><line x1="16.24" y1="7.76" x2="19.07" y2="4.93"></line></svg>
        <span v-else>Crear Usuario</span>
      </button>
    </form>
  </div>
</template>

<script setup>
import { ref } from 'vue'
import userService from '../../application/services/userService'

const username = ref('')
const password = ref('')
const error = ref('')
const success = ref('')
const loading = ref(false)

const handleAddUser = async () => {
  error.value = ''
  success.value = ''
  loading.value = true
  
  try {
    await userService.createUser({
      username: username.value,
      password: password.value
    })
    success.value = 'Usuario creado correctamente.'
    username.value = ''
    password.value = ''
    
    setTimeout(() => success.value = '', 4000)
  } catch (err) {
    if (err.response && err.response.data.detail) {
      error.value = err.response.data.detail
    } else {
      error.value = 'Error al crear el usuario. Asegúrate de que no exista ya.'
    }
  } finally {
    loading.value = false
  }
}
</script>

<style scoped>
.max-w-lg {
  max-width: 600px;
}

.card-header {
  display: flex;
  align-items: center;
  gap: 1.25rem;
  margin-bottom: 2rem;
  padding-bottom: 1.5rem;
  border-bottom: 1px solid var(--border);
}

.icon-box {
  width: 48px;
  height: 48px;
  background-color: var(--primary-glow);
  color: var(--primary);
  border-radius: var(--radius-sm);
  display: flex;
  align-items: center;
  justify-content: center;
  flex-shrink: 0;
}

.input-icon {
  position: relative;
}

.input-icon .icon {
  position: absolute;
  left: 1rem;
  top: 50%;
  transform: translateY(-50%);
  color: var(--text-muted);
}

.input-icon .form-input {
  padding-left: 3rem;
}

.alert {
  padding: 1rem;
  border-radius: var(--radius-sm);
  margin-bottom: 1.5rem;
  font-size: 0.9rem;
  display: flex;
  align-items: center;
  gap: 0.5rem;
  font-weight: 500;
}

.alert-danger {
  color: var(--danger);
  background-color: var(--danger-bg);
  border: 1px solid rgba(239, 68, 68, 0.3);
}

.alert-success {
  color: var(--success);
  background-color: var(--success-bg);
  border: 1px solid rgba(16, 185, 129, 0.3);
}
</style>
