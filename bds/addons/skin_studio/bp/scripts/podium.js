import { world, system } from '@minecraft/server';
import { ModalFormData } from '@minecraft/server-ui';
import { relayOf } from './relay.js';
import { hudOf, showHud } from './hud.js';
import { PODIUM, YAW, facingToPlacer, loaded, set, settle, refund } from './util.js';

const RANKS = [1, 2, 3];
const LABELS = ['§61位', '§72位', '§c3位'];
const STEPS = [
  [0, 22.4],
  [-18, 16.4],
  [18, 12.4],
];
const EGG = 'skin_studio:podium_spawn_egg';
const busy = new Set();

const ranking = (podium) => JSON.parse(String(podium.getDynamicProperty('ss:who') ?? '[null,null,null]'));

export function setup(podium, facing) {
  podium.setDynamicProperty('ss:f', facing);
  update(podium, world.getAllPlayers());
}

export function assign(podium, place, player) {
  const who = ranking(podium);
  who[place - 1] = player ? { id: player.id, name: player.name } : null;
  save(podium, who);
}

function save(podium, who) {
  const before = ranking(podium);
  podium.setDynamicProperty('ss:who', JSON.stringify(who));
  update(podium, world.getAllPlayers());
  for (const place of RANKS) {
    if (who[place - 1] && who[place - 1].id !== before[place - 1]?.id) cheer(podium, place);
  }
}

function cheer(podium, place) {
  const [across, top] = STEPS[place - 1];
  const turn = (YAW[Number(podium.getDynamicProperty('ss:f'))] * Math.PI) / 180;
  const { x, y, z } = podium.location;
  const spot = { x: x + (Math.cos(turn) * across) / 16, y: y + (top + 34) / 16, z: z + (Math.sin(turn) * across) / 16 };
  podium.dimension.spawnParticle('minecraft:totem_particle', spot);
  podium.dimension.playSound(place === 1 ? 'random.levelup' : 'random.orb', spot, { volume: 0.7, pitch: 1 + (place - 1) * 0.15 });
}

function update(podium, players) {
  const { x, y, z } = podium.location;
  settle(podium, { x: Math.floor(x) + 0.5, y, z: Math.floor(z) + 0.5 }, Number(podium.getDynamicProperty('ss:f')));

  const who = ranking(podium);
  const lines = [];
  for (const place of RANKS) {
    const entry = who[place - 1];
    const player = entry && players.find((p) => p.id === entry.id || p.name === entry.name);
    const relay = player && relayOf(player);
    if (relay || !entry) {
      set(podium, `skin_studio:s${place}`, relay?.slot ?? 0);
      set(podium, `skin_studio:g${place}`, relay?.gen ?? 0);
    }
    if (entry) lines.push(`${LABELS[place - 1]} §f${entry.name}`);
  }
  const tag = lines.join('\n');
  if (podium.nameTag !== tag) podium.nameTag = tag;
}

async function edit(player, podium) {
  const who = ranking(podium);
  const people = world.getAllPlayers().map(({ id, name }) => ({ id, name }));
  const form = new ModalFormData().title('表彰台');
  const choices = RANKS.map((place) => {
    const list = [null, ...people];
    const current = who[place - 1];
    let index = current ? list.findIndex((entry) => entry?.id === current.id) : 0;
    if (index < 0) index = list.push(current) - 1;
    form.dropdown(`${place}位`, list.map((entry) => entry?.name ?? '（なし）'), { defaultValueIndex: index });
    return list;
  });
  const showing = hudOf(player)?.id === podium.id;
  form.toggle('自分の画面に出す', { defaultValue: showing });
  form.toggle('§c片付ける', { defaultValue: false });

  const response = await form.show(player);
  if (response.canceled || !podium.isValid) return;
  const [first, second, third, show, remove] = response.formValues;
  if (remove) {
    refund(podium, player, EGG);
    return;
  }
  save(podium, [first, second, third].map((pick, i) => choices[i][Number(pick)] ?? null));
  if (show) showHud(player, podium);
  else if (showing) showHud(player, undefined);
}

world.afterEvents.entitySpawn.subscribe(({ entity }) => {
  if (!entity.isValid || entity.typeId !== PODIUM) return;
  system.run(() => {
    if (entity.isValid && entity.getDynamicProperty('ss:f') === undefined) setup(entity, facingToPlacer(entity));
  });
});

world.beforeEvents.playerInteractWithEntity.subscribe((event) => {
  if (event.target.typeId !== PODIUM) return;
  event.cancel = true;
  const { player, target } = event;
  if (busy.has(player.id)) return;
  busy.add(player.id);
  system.run(() => edit(player, target).finally(() => busy.delete(player.id)));
});

system.runInterval(() => {
  const players = world.getAllPlayers();
  for (const podium of loaded(PODIUM)) {
    if (podium.getDynamicProperty('ss:f') === undefined) setup(podium, facingToPlacer(podium));
    else update(podium, players);
  }
}, 20);
