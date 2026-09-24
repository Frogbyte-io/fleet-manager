import { QueryClient, VueQueryPlugin } from '@tanstack/vue-query'
import { createApp } from 'vue'
import 'vue-sonner/style.css'

import App from './App.vue'
import { router } from './router'
import { applyInitialTheme } from './shell/theme'
import './style.css'

applyInitialTheme()

const queryClient = new QueryClient({
  defaultOptions: {
    queries: { staleTime: 10_000, retry: 1, refetchOnWindowFocus: false },
  },
})

const app = createApp(App)
app.use(router)
app.use(VueQueryPlugin, { queryClient })
app.mount('#app')
