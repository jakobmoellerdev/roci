<script setup lang="ts">
import { computed, ref } from 'vue'
import { useData } from 'vitepress'

type Status = 'done' | 'wip' | 'planned' | 'blocked'
interface Item { status: Status; title: string; detail?: string }
interface Area { id: string; title: string; tagline: string; items: Item[] }

const { frontmatter } = useData()
const areas = computed<Area[]>(() => frontmatter.value.areas ?? [])

const LABEL: Record<Status, string> = {
  done: 'Shipped',
  wip: 'In progress',
  planned: 'Planned',
  blocked: 'Blocked',
}
const ORDER: Status[] = ['done', 'wip', 'planned', 'blocked']

const filter = ref<Status | 'all'>('all')

function count(items: Item[], s: Status) {
  return items.filter((i) => i.status === s).length
}

const all = computed(() => areas.value.flatMap((a) => a.items))
const totals = computed(() =>
  ORDER.map((s) => ({ status: s, n: count(all.value, s) })).filter((t) => t.n > 0),
)
const inFlight = computed(() =>
  areas.value.flatMap((a) =>
    a.items.filter((i) => i.status === 'wip').map((i) => ({ ...i, area: a.title })),
  ),
)
const visible = computed(() =>
  areas.value
    .map((a) => ({
      ...a,
      shown: filter.value === 'all' ? a.items : a.items.filter((i) => i.status === filter.value),
    }))
    .filter((a) => a.shown.length > 0),
)

function pct(n: number, total: number) {
  return total ? `${(n / total) * 100}%` : '0%'
}

// Inline `code` spans are the only markup the roadmap data uses.
function parts(text = '') {
  return text.split('`').map((t, i) => ({ t, code: i % 2 === 1 }))
}
</script>

<template>
  <div class="rm">
    <section class="rm-summary">
      <div v-for="t in totals" :key="t.status" class="rm-stat" :class="t.status">
        <span class="rm-stat-n">{{ t.n }}</span>
        <span class="rm-stat-l">{{ LABEL[t.status] }}</span>
      </div>
      <div class="rm-bar rm-bar-lg" role="img" :aria-label="totals.map((t) => `${t.n} ${LABEL[t.status]}`).join(', ')">
        <span v-for="t in totals" :key="t.status" :class="t.status" :style="{ width: pct(t.n, all.length) }" />
      </div>
    </section>

    <section v-if="inFlight.length" class="rm-now">
      <h2>Being built now</h2>
      <ul>
        <li v-for="i in inFlight" :key="i.area + i.title">
          <span class="rm-pulse" aria-hidden="true" />
          <div>
            <strong>{{ i.title }}</strong>
            <span class="rm-area">{{ i.area }}</span>
          </div>
        </li>
      </ul>
    </section>

    <nav class="rm-filters" aria-label="Filter by status">
      <button :class="{ on: filter === 'all' }" @click="filter = 'all'">All · {{ all.length }}</button>
      <button
        v-for="t in totals"
        :key="t.status"
        :class="[t.status, { on: filter === t.status }]"
        @click="filter = t.status"
      >
        <span class="rm-dot" :class="t.status" /> {{ LABEL[t.status] }} · {{ t.n }}
      </button>
    </nav>

    <div class="rm-grid">
      <article v-for="a in visible" :key="a.id" class="rm-card">
        <header>
          <div class="rm-card-head">
            <h3 :id="a.id">{{ a.title }}</h3>
            <span class="rm-frac">{{ count(a.items, 'done') }}/{{ a.items.length }}</span>
          </div>
          <p>{{ a.tagline }}</p>
          <div class="rm-bar">
            <span
              v-for="s in ORDER"
              :key="s"
              :class="s"
              :style="{ width: pct(count(a.items, s), a.items.length) }"
            />
          </div>
        </header>
        <ul>
          <li v-for="i in a.shown" :key="i.title" :class="i.status">
            <span class="rm-dot" :class="i.status" :title="LABEL[i.status]" />
            <div>
              <span class="rm-title">{{ i.title }}</span>
              <span v-if="i.status !== 'done'" class="rm-tag" :class="i.status">{{ LABEL[i.status] }}</span>
              <p v-if="i.detail" class="rm-detail">
                <template v-for="(p, k) in parts(i.detail)" :key="k">
                  <code v-if="p.code">{{ p.t }}</code><template v-else>{{ p.t }}</template>
                </template>
              </p>
            </div>
          </li>
        </ul>
      </article>
    </div>
  </div>
</template>

<style scoped>
.rm {
  --rm-done: var(--roci-rust-base);
  --rm-wip: var(--roci-rust-bright);
  --rm-planned: var(--vp-c-divider);
  --rm-blocked: var(--roci-slate);
  margin-top: 24px;
}

/* Summary */
.rm-summary {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(110px, 1fr));
  gap: 12px;
  padding: 20px;
  border-radius: 16px;
  background:
    linear-gradient(120deg, rgba(244, 113, 59, 0.12), rgba(158, 47, 30, 0.04)),
    var(--vp-c-bg-soft);
  border: 1px solid var(--vp-c-divider);
}
.rm-stat { display: flex; flex-direction: column; }
.rm-stat-n {
  font-size: 40px;
  font-weight: 700;
  line-height: 1.1;
  letter-spacing: -0.02em;
}
.rm-stat.done .rm-stat-n {
  background: linear-gradient(120deg, var(--roci-rust-bright), var(--roci-rust-deep));
  -webkit-background-clip: text;
  background-clip: text;
  color: transparent;
}
.rm-stat.wip .rm-stat-n { color: var(--rm-wip); }
.rm-stat.planned .rm-stat-n, .rm-stat.blocked .rm-stat-n { color: var(--vp-c-text-2); }
.rm-stat-l {
  font-size: 12px;
  text-transform: uppercase;
  letter-spacing: 0.08em;
  color: var(--vp-c-text-2);
}

/* Segmented progress bars */
.rm-bar {
  display: flex;
  height: 6px;
  border-radius: 999px;
  overflow: hidden;
  background: var(--rm-planned);
  margin-top: 12px;
}
.rm-bar-lg { grid-column: 1 / -1; height: 10px; margin-top: 4px; }
.rm-bar span { height: 100%; transition: width 0.4s ease; }
.rm-bar .done { background: linear-gradient(90deg, var(--roci-rust-bright), var(--roci-rust-deep)); }
.rm-bar .wip {
  background: repeating-linear-gradient(
    45deg, var(--rm-wip), var(--rm-wip) 4px, rgba(244, 113, 59, 0.55) 4px, rgba(244, 113, 59, 0.55) 8px
  );
}
.rm-bar .planned { background: var(--rm-planned); }
.rm-bar .blocked { background: var(--rm-blocked); }

/* Now */
.rm-now { margin-top: 32px; }
.rm-now h2 {
  border: 0;
  margin: 0 0 12px;
  padding: 0;
  font-size: 13px;
  text-transform: uppercase;
  letter-spacing: 0.1em;
  color: var(--vp-c-text-2);
}
.rm-now ul {
  list-style: none;
  padding: 0;
  margin: 0;
  display: grid;
  grid-template-columns: repeat(auto-fill, minmax(220px, 1fr));
  gap: 10px;
}
.rm-now li {
  display: flex;
  gap: 10px;
  align-items: flex-start;
  margin: 0;
  padding: 12px 14px;
  border-radius: 12px;
  border: 1px solid rgba(244, 113, 59, 0.35);
  background: var(--vp-c-bg-soft);
}
.rm-now strong { display: block; font-size: 14px; line-height: 1.35; }
.rm-area { font-size: 12px; color: var(--vp-c-text-2); }
.rm-pulse {
  flex: none;
  width: 10px;
  height: 10px;
  margin-top: 5px;
  border-radius: 50%;
  background: var(--rm-wip);
  box-shadow: 0 0 0 0 rgba(244, 113, 59, 0.6);
  animation: rm-pulse 2s infinite;
}
@keyframes rm-pulse {
  70% { box-shadow: 0 0 0 8px rgba(244, 113, 59, 0); }
  100% { box-shadow: 0 0 0 0 rgba(244, 113, 59, 0); }
}
@media (prefers-reduced-motion: reduce) { .rm-pulse { animation: none; } }

/* Filters */
.rm-filters { display: flex; flex-wrap: wrap; gap: 8px; margin: 32px 0 16px; }
.rm-filters button {
  display: inline-flex;
  align-items: center;
  gap: 6px;
  padding: 4px 12px;
  border-radius: 999px;
  border: 1px solid var(--vp-c-divider);
  font-size: 13px;
  color: var(--vp-c-text-2);
  transition: all 0.2s;
}
.rm-filters button:hover { color: var(--vp-c-text-1); border-color: var(--vp-c-brand-1); }
.rm-filters button.on { color: var(--vp-c-text-1); border-color: var(--vp-c-brand-1); background: var(--vp-c-brand-soft); }

/* Cards */
.rm-grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(320px, 1fr)); gap: 16px; }
.rm-card {
  padding: 20px;
  border-radius: 16px;
  border: 1px solid var(--vp-c-divider);
  background: var(--vp-c-bg-soft);
  transition: border-color 0.2s, transform 0.2s;
}
.rm-card:hover { border-color: rgba(206, 66, 43, 0.5); transform: translateY(-2px); }
.rm-card-head { display: flex; justify-content: space-between; align-items: baseline; gap: 8px; }
.rm-card h3 { margin: 0; font-size: 18px; }
.rm-frac { font-size: 13px; font-variant-numeric: tabular-nums; color: var(--vp-c-text-2); }
.rm-card header p { margin: 4px 0 0; font-size: 14px; color: var(--vp-c-text-2); line-height: 1.5; }
.rm-card ul { list-style: none; padding: 0; margin: 16px 0 0; }
.rm-card li { display: flex; gap: 10px; margin: 0; padding: 8px 0; border-top: 1px solid var(--vp-c-divider); }
.rm-card li:first-child { border-top: 0; }
.rm-title { font-size: 14px; font-weight: 500; }
.rm-detail { margin: 2px 0 0; font-size: 13px; line-height: 1.5; color: var(--vp-c-text-2); }
.rm-detail code { overflow-wrap: anywhere; }
.rm-card li.planned .rm-title, .rm-card li.blocked .rm-title { color: var(--vp-c-text-2); }

/* Status marks */
.rm-dot {
  flex: none;
  width: 10px;
  height: 10px;
  margin-top: 6px;
  border-radius: 50%;
  border: 2px solid var(--vp-c-text-3);
}
.rm-filters .rm-dot { margin-top: 0; }
.rm-dot.done { border-color: var(--rm-done); background: var(--rm-done); }
.rm-dot.wip { border-color: var(--rm-wip); background: linear-gradient(90deg, var(--rm-wip) 50%, transparent 50%); }
.rm-dot.blocked { border-color: var(--rm-blocked); border-style: dashed; }
.rm-tag {
  margin-left: 8px;
  padding: 1px 8px;
  border-radius: 999px;
  font-size: 11px;
  font-weight: 600;
  vertical-align: 1px;
  color: var(--vp-c-text-2);
  background: var(--vp-c-default-soft);
}
.rm-tag.wip { color: var(--rm-wip); background: rgba(244, 113, 59, 0.14); }
</style>
