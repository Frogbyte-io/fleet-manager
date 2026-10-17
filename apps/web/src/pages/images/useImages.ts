import { useMutation, useQueries, useQuery, useQueryClient } from '@tanstack/vue-query'
import { computed, ref, toValue, type MaybeRefOrGetter } from 'vue'

import {
  deleteImageSecret,
  getImageBuild,
  listImageBuilds,
  listImageRecipes,
  listImageRecipeVersions,
  listImageSecrets,
  listLabLeases,
  listLabTemplates,
  listOperations,
  setImageSecret,
  type ImageBuildDto,
  type ImageSecretDto,
  type LabTemplateDto,
  type LeaseDto,
  type OperationDto,
  type RecipeDto,
  type RecipeVersionDto,
} from '@frogbyte-io/fleet-api-client'

import { LEASES_KEY, TEMPLATES_KEY } from '../lab/useLab'
import { isTerminal, retryTransient, unwrap } from '../machine/api'

import { buildRunning, latestBuilds } from './images'

// Server state for the Images pipeline. Lab templates and leases share the
// Lab page's cache entries (same keys, same plain-list shape).

export const RECIPES_KEY = ['images', 'recipes'] as const
export const BUILD_OPERATIONS_KEY = ['images', 'build-operations'] as const
/** Every build-record query; invalidated when a build starts or settles. */
export const BUILD_RECORDS_KEY = ['images', 'build-records'] as const
export function versionsKey(recipeId: string) {
  return ['images', 'recipes', recipeId, 'versions'] as const
}

/** How many operations the build list reads (the operations API has no kind filter). */
export const OPERATIONS_LIMIT = 200
const LIVE_REFRESH_MS = 3000

function items<T>(response: { status: number, data: unknown }): { items: T[], truncated: boolean } {
  if (response.status !== 200)
    unwrap(response)
  const page = response.data as { items: T[], page?: { nextCursor?: string | null } }
  return { items: page.items, truncated: Boolean(page.page?.nextCursor) }
}

// Builds this browser tab started: operation id → version id. Operations
// carry no payload, so a running build is attributable only this way.
const STARTED_KEY = 'fleet-console-image-builds'
function loadStarted(): Record<string, string> {
  try {
    const parsed = JSON.parse(sessionStorage.getItem(STARTED_KEY) ?? '{}')
    return parsed && typeof parsed === 'object' ? parsed as Record<string, string> : {}
  }
  catch {
    return {}
  }
}
const started = ref<Record<string, string>>(loadStarted())

export function trackBuild(operationId: string, versionId: string) {
  started.value = { ...started.value, [operationId]: versionId }
  try {
    sessionStorage.setItem(STARTED_KEY, JSON.stringify(started.value))
  }
  catch {
    // Memory-only for this tab.
  }
}

export function useImages() {
  const recipes = useQuery({
    queryKey: RECIPES_KEY,
    queryFn: async () => items<RecipeDto>(await listImageRecipes({ limit: 200 })),
    retry: retryTransient,
  })
  const recipeIds = computed(() => (recipes.data.value?.items ?? []).map(r => r.id))
  const versionQueries = useQueries({
    queries: computed(() => recipeIds.value.map(id => ({
      queryKey: versionsKey(id),
      queryFn: async () => items<RecipeVersionDto>(await listImageRecipeVersions(id)).items,
      retry: retryTransient,
    }))),
  })
  const templates = useQuery({
    queryKey: TEMPLATES_KEY,
    queryFn: async () => items<LabTemplateDto>(await listLabTemplates()).items,
    retry: retryTransient,
  })
  const leases = useQuery({
    queryKey: LEASES_KEY,
    queryFn: async () => items<LeaseDto>(await listLabLeases()).items,
    retry: retryTransient,
  })
  const operations = useQuery({
    queryKey: BUILD_OPERATIONS_KEY,
    queryFn: async () => items<OperationDto>(await listOperations({ limit: OPERATIONS_LIMIT })).items,
    retry: retryTransient,
    // Poll only while a build is still running.
    refetchInterval: q => ((q.state.data ?? []).some(o => o.kind === 'image.build' && !isTerminal(o.state)) ? LIVE_REFRESH_MS : false),
  })

  const versions = computed(() => versionQueries.value.flatMap(q => q.data ?? []))
  const builds = computed(() => latestBuilds(operations.data.value ?? [], started.value))
  const loadError = computed(() => [
    recipes.error.value && ['recipes', recipes.error.value],
    ...versionQueries.value.map(q => q.error && ['versions', q.error]),
    templates.error.value && ['Lab templates', templates.error.value],
    leases.error.value && ['leases', leases.error.value],
    operations.error.value && ['build operations', operations.error.value],
  ].filter(Boolean) as [string, unknown][])
  const loading = computed(() => recipes.isLoading.value || versionQueries.value.some(q => q.isLoading))

  return { recipes, versions, templates, leases, operations, builds, loadError, loading }
}

/** How many build records a version's history reads (the API's default page). */
export const BUILD_HISTORY_LIMIT = 50

/**
 * A version's immutable build records, newest first (the API's order), as
 * `fleetctl images builds --version <id>` reports them. Polls while one is
 * still running, and while `live` (a build this page follows has not
 * settled, so its record may not exist yet).
 */
export function useVersionBuilds(versionId: MaybeRefOrGetter<string>, live: MaybeRefOrGetter<boolean> = false) {
  return useQuery({
    queryKey: computed(() => [...BUILD_RECORDS_KEY, 'version', toValue(versionId)] as const),
    queryFn: async () => items<ImageBuildDto>(await listImageBuilds({ versionId: toValue(versionId), limit: BUILD_HISTORY_LIMIT })),
    retry: retryTransient,
    refetchInterval: q => (toValue(live) || (q.state.data?.items ?? []).some(buildRunning) ? LIVE_REFRESH_MS : false),
  })
}

/** One build record (`fleetctl images build-show <id>`), for a record not on the listed page. */
export function useBuildRecord(buildId: MaybeRefOrGetter<string | null>, enabled: MaybeRefOrGetter<boolean>) {
  return useQuery({
    queryKey: computed(() => [...BUILD_RECORDS_KEY, 'record', toValue(buildId)] as const),
    queryFn: async () => unwrap<ImageBuildDto>(await getImageBuild(toValue(buildId)!)),
    enabled: computed(() => !!toValue(buildId) && toValue(enabled)),
    retry: retryTransient,
    refetchInterval: q => (q.state.data && buildRunning(q.state.data) ? LIVE_REFRESH_MS : false),
  })
}

/** The `images/<name>` build secret names. Values are never readable. */
export const IMAGE_SECRETS_KEY = ['images', 'secrets'] as const

export function useImageSecrets() {
  return useQuery({
    queryKey: IMAGE_SECRETS_KEY,
    queryFn: async () => items<ImageSecretDto>(await listImageSecrets()).items,
    retry: retryTransient,
  })
}

/**
 * Writes one build secret. The value is a secret, so it is never a mutation
 * variable (those live in the TanStack mutation cache): the call is a
 * closure, the mutation is not kept (`gcTime: 0`), and it is reset as soon
 * as the call settles.
 */
export function useSetImageSecret() {
  const queryClient = useQueryClient()
  const mutation = useMutation({
    mutationFn: async (send: () => Promise<{ status: number, data: unknown }>) => unwrap<ImageSecretDto>(await send()),
    gcTime: 0,
    onSettled: () => queryClient.invalidateQueries({ queryKey: IMAGE_SECRETS_KEY }),
  })
  return {
    isPending: mutation.isPending,
    async save(name: string, value: string): Promise<ImageSecretDto> {
      try {
        return await mutation.mutateAsync(() => setImageSecret({ name, value }))
      }
      finally {
        mutation.reset()
      }
    },
  }
}

export function useDeleteImageSecret() {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: async (name: string) => unwrap<ImageSecretDto>(await deleteImageSecret(name)),
    onSettled: () => queryClient.invalidateQueries({ queryKey: IMAGE_SECRETS_KEY }),
  })
}
