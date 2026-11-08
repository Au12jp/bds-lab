import { world, system } from '@minecraft/server';
import { REFLECTED, SLOTS } from './reflected.js';
import { DIMENSIONS, YAW, set, settle } from './util.js';

const LIMIT = 6;
const AGAIN = 40;
const REST = 40;
const FAMILY = 'skin_studio_reflection';
const FAR = 64000;

const claims = new Map();
const resting = new Map();
const shown = new Map();
let tick = 0;

const clamp = (value, low, high) => Math.min(high, Math.max(low, Math.round(value)));
const reflectable = (entity) => entity.isValid && REFLECTED[entity.typeId] !== undefined;
const flag = (entity, component) => entity.getComponent(component) !== undefined;
const number = (entity, component) => clamp(entity.getComponent(component)?.value ?? 0, -1000000, 1000000);

function play(source, animation, controller) {
  try {
    source.playAnimation(animation, { controller, stopExpression: '0', blendOutTime: 0 });
  } catch {}
}

function announce(claim) {
  if (!claim.source.isValid) return;
  play(claim.source, `animation.skin_studio.s.${claim.key}.${claim.slot}`, 'skin_studio_slot');
  if (claim.slot) play(claim.source, `animation.skin_studio.p.${claim.key}`, 'skin_studio_publish');
}

function freeSlot() {
  const held = new Set([...claims.values()].map((claim) => claim.slot));
  for (let slot = 1; slot <= SLOTS; slot++) {
    if (!held.has(slot) && (resting.get(slot) ?? 0) <= tick) return slot;
  }
  return 0;
}

function claimOf(source) {
  let claim = claims.get(source.id);
  if (!claim) {
    claim = { source, ...REFLECTED[source.typeId], slot: 0 };
    claims.set(source.id, claim);
  }
  if (!claim.slot) {
    claim.slot = freeSlot();
    if (claim.slot) announce(claim);
  }
  return claim;
}

function release(id) {
  const claim = claims.get(id);
  if (!claim) return;
  claims.delete(id);
  if (!claim.slot) return;
  resting.set(claim.slot, tick + REST);
  claim.slot = 0;
  if (claim.source.isValid) announce(claim);
}

function drop(entryKey) {
  const entry = shown.get(entryKey);
  if (!entry) return;
  shown.delete(entryKey);
  try {
    if (entry.reflection.isValid) entry.reflection.remove();
  } catch {}
  if (![...shown.values()].some((other) => other.source.id === entry.source.id)) release(entry.source.id);
}

function follow(entry) {
  const { reflection, source, glass } = entry;
  const claim = claims.get(source.id);
  const { x, y, z } = source.location;
  set(reflection, 'skin_studio:slot', claim?.slot ?? 0);
  set(reflection, 'skin_studio:dx', clamp((x - glass.x) * 1000, -FAR, FAR));
  set(reflection, 'skin_studio:dy', clamp((y - glass.y) * 1000, -FAR, FAR));
  set(reflection, 'skin_studio:dz', clamp((z - glass.z) * 1000, -FAR, FAR));
  set(reflection, 'skin_studio:yaw', clamp(((((source.getRotation().y + 180) % 360) + 360) % 360) * 10 - 1800, -1800, 1800));
  set(reflection, 'skin_studio:scale', clamp((source.getComponent('minecraft:scale')?.value ?? 1) * 100, 1, 10000));
  if (claim && tick % 10 === 0) look(reflection, source, claim.seeds);
}

function look(reflection, source, seeds) {
  for (const [name, kind, from] of seeds) {
    try {
      const value = kind === 'p' ? source.getProperty(from) : kind === 'f' ? flag(source, from) : number(source, from);
      if (value !== undefined) set(reflection, name, value);
    } catch {}
  }
}

function near(mirror, frame, isInFront) {
  const far = ({ typeId, location: { x, y, z } }) => (typeId === 'minecraft:xp_orb' ? 1000 : 0) + (x - frame.glass.x) ** 2 + (y - frame.glass.y) ** 2 + (z - frame.glass.z) ** 2;
  try {
    return mirror.dimension
      .getEntities({ location: frame.glass, maxDistance: 16, excludeTypes: ['minecraft:player'], excludeFamilies: ['skin_studio'] })
      .filter((entity) => reflectable(entity) && isInFront(entity.location))
      .sort((a, b) => far(a) - far(b))
      .slice(0, LIMIT);
  } catch {
    return [];
  }
}

export function showMobs(mirror, frame, isInFront) {
  const found = near(mirror, frame, isInFront);
  const wanted = new Set(found.map((source) => `${mirror.id}|${source.id}`));
  for (const key of [...shown.keys()]) if (key.startsWith(`${mirror.id}|`) && !wanted.has(key)) drop(key);

  for (const source of found) {
    const key = `${mirror.id}|${source.id}`;
    const claim = claimOf(source);
    let entry = shown.get(key);
    if (!entry || !entry.reflection.isValid) {
      let reflection;
      try {
        reflection = mirror.dimension.spawnEntity(`skin_studio:m_${claim.key}`, frame.glass, { initialRotation: YAW[frame.facing] });
      } catch {
        continue;
      }
      reflection.setDynamicProperty('ss:o', mirror.id);
      look(reflection, source, claim.seeds);
      entry = { reflection, source, mirror, glass: { ...frame.glass }, facing: frame.facing };
      shown.set(key, entry);
    }
    follow(entry);
  }
}

export function forget(mirror) {
  for (const key of [...shown.keys()]) if (key.startsWith(`${mirror.id}|`)) drop(key);
}

function sweep() {
  const live = new Set([...shown.values()].map((entry) => entry.reflection.id));
  for (const id of DIMENSIONS) {
    for (const reflection of world.getDimension(id).getEntities({ families: [FAMILY] })) {
      if (!live.has(reflection.id)) {
        try {
          reflection.remove();
        } catch {}
      }
    }
  }
}

system.runInterval(() => {
  tick++;
  for (const [key, entry] of shown) {
    try {
      if (!entry.source.isValid || !entry.reflection.isValid || !entry.mirror.isValid || entry.source.dimension.id !== entry.mirror.dimension.id) {
        drop(key);
        continue;
      }
      follow(entry);
      if (tick % 20 === 0) settle(entry.reflection, entry.glass, entry.facing);
    } catch {
      drop(key);
    }
  }
  if (tick % AGAIN === 0) for (const claim of claims.values()) if (claim.slot) announce(claim);
  if (tick % 20 === 1) sweep();
});
