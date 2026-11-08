import { world, system, BlockVolume, GameMode } from '@minecraft/server';
import { MessageFormData } from '@minecraft/server-ui';
import { relayOf } from './relay.js';
import { showMobs, forget } from './reflections.js';
import { BLOCKS } from './blocks.js';
import { MIRROR, GHOST, WALL, facingOf, placerOf, loaded, set, settle, refund } from './util.js';

const AHEAD = [
  { x: 0, z: 1 },
  { x: -1, z: 0 },
  { x: 0, z: -1 },
  { x: 1, z: 0 },
];
const FIGURES = 4;
const DEPTH = 8;
const SIDE = 6;
const REACH = 96;
const RISE = 48;
const WALLS = [-1.2, -0.4, 0.4, 1.2];
const OPEN = ['minecraft:air', 'minecraft:barrier'];
const MIRRORED = Object.keys(BLOCKS);
const EGG = 'skin_studio:mirror_spawn_egg';
const WHERE = '§c鏡は、壁にあけた 3×3 の窓の「一番下の真ん中」に置いてください。';
const dirty = new Set();
const warned = new Set();
let mirrors = [];
let tick = 0;

const keyOf = ({ x, y, z }) => `${x},${y},${z}`;
const windowAt = ({ x, y, z }) => ({ x: Math.floor(x), y: Math.floor(y + 0.01), z: Math.floor(z) });

function frameAt(window, facing) {
  const ahead = AHEAD[facing];
  return {
    facing,
    ahead,
    side: { x: ahead.z, z: -ahead.x },
    window,
    glass: { x: window.x + 0.5 + ahead.x / 2, y: window.y, z: window.z + 0.5 + ahead.z / 2 },
  };
}

function frameOf(mirror) {
  const [x, y, z] = JSON.parse(String(mirror.getDynamicProperty('ss:w')));
  return frameAt({ x, y, z }, Number(mirror.getDynamicProperty('ss:f')));
}

const cell = (frame, depth, side, height) => ({
  x: frame.window.x + frame.ahead.x * depth + frame.side.x * side,
  y: frame.window.y + height,
  z: frame.window.z + frame.ahead.z * depth + frame.side.z * side,
});

function blockAt(dimension, location) {
  try {
    return dimension.getBlock(location);
  } catch {
    return undefined;
  }
}

const isOpen = (block) => !!block && (block.isAir || block.typeId === 'minecraft:barrier');

function* scan(dimension, from, to, includeTypes) {
  const { min, max } = dimension.heightRange;
  const low = Math.max(Math.min(from.y, to.y), min);
  const high = Math.min(Math.max(from.y, to.y), max - 1);
  if (low > high) return;
  const volume = new BlockVolume({ ...from, y: low }, { ...to, y: high });
  yield* dimension.getBlocks(volume, { includeTypes }, true).getBlockLocationIterator();
}

export function windowProblem(dimension, location, facing) {
  const frame = frameAt(windowAt(location), facing);
  for (let side = -1; side <= 1; side++) {
    for (let height = 0; height <= 2; height++) {
      if (!isOpen(blockAt(dimension, cell(frame, 0, side, height)))) return WHERE;
    }
  }
}

export function setup(mirror, facing) {
  const { x, y, z } = windowAt(mirror.location);
  mirror.setDynamicProperty('ss:f', facing);
  mirror.setDynamicProperty('ss:w', JSON.stringify([x, y, z]));
  const frame = frameOf(mirror);
  settle(mirror, frame.glass, facing);
  fence(mirror, frame);
  dirty.add(mirror.id);
}

function fence(mirror, frame) {
  const mine = mirror.dimension.getEntities({ type: WALL, location: frame.glass, maxDistance: 3 }).filter((wall) => wall.getDynamicProperty('ss:o') === mirror.id);
  WALLS.forEach((offset, i) => {
    const spot = { x: frame.glass.x + frame.side.x * offset, y: frame.glass.y, z: frame.glass.z + frame.side.z * offset };
    const wall = mine.find((each) => each.getDynamicProperty('ss:i') === i);
    if (wall) return settle(wall, spot, frame.facing);
    const made = mirror.dimension.spawnEntity(WALL, spot, { initialRotation: 0 });
    made.setDynamicProperty('ss:o', mirror.id);
    made.setDynamicProperty('ss:i', i);
  });
}

export function removeMirror(mirror) {
  clearReflections(mirror);
  mirror.remove();
}

function place(mirror) {
  const placer = placerOf(mirror);
  const facing = facingOf((placer?.getRotation().y ?? 0) + 180);
  const problem = windowProblem(mirror.dimension, mirror.location, facing);
  if (problem) {
    placer?.sendMessage(problem);
    refund(mirror, placer, EGG);
  } else {
    setup(mirror, facing);
  }
}

function inFront(frame, { x, y, z }) {
  const dx = x - frame.glass.x;
  const dz = z - frame.glass.z;
  const front = dx * frame.ahead.x + dz * frame.ahead.z;
  const across = dx * frame.side.x + dz * frame.side.z;
  const ok = front > 0.05 && front < REACH && Math.abs(across) < REACH && Math.abs(y - frame.glass.y) < RISE;
  return ok ? front * front + across * across : undefined;
}

function reflect(mirror, frame, players) {
  const near = [];
  for (const player of players) {
    const relay = relayOf(player);
    if (!relay || player.dimension.id !== mirror.dimension.id || player.getGameMode() === GameMode.Spectator) continue;
    const far = inFront(frame, player.location);
    if (far !== undefined) near.push({ ...relay, y: Math.round(player.location.y * 16), far });
  }
  near.sort((a, b) => a.far - b.far);
  near.length = Math.min(near.length, FIGURES);

  const shown = [];
  for (let k = 1; k <= FIGURES; k++) shown.push(near.find((person) => person.slot === mirror.getProperty(`skin_studio:r${k}`)));
  for (const person of near) if (!shown.includes(person)) shown[shown.indexOf(undefined)] = person;
  shown.forEach((person, i) => {
    set(mirror, `skin_studio:r${i + 1}`, person?.slot ?? 0);
    set(mirror, `skin_studio:g${i + 1}`, person?.gen ?? 0);
    if (person) set(mirror, `skin_studio:y${i + 1}`, person.y);
  });
  showMobs(mirror, frame, (location) => inFront(frame, location) !== undefined, Math.hypot(REACH, REACH, RISE));
}

function rebuild(mirror, frame) {
  const dimension = mirror.dimension;
  const open = new Set();
  for (const spot of scan(dimension, cell(frame, 0, -SIDE, -1), cell(frame, 1 - DEPTH, SIDE, 5), OPEN)) open.add(keyOf(spot));

  const wanted = new Map();
  for (const spot of scan(dimension, cell(frame, 1, -SIDE, -1), cell(frame, DEPTH, SIDE, 5), MIRRORED)) {
    const depth = (spot.x - frame.window.x) * frame.ahead.x + (spot.z - frame.window.z) * frame.ahead.z;
    const image = keyOf({ x: spot.x + frame.ahead.x * (1 - 2 * depth), y: spot.y, z: spot.z + frame.ahead.z * (1 - 2 * depth) });
    const texture = BLOCKS[blockAt(dimension, spot)?.typeId];
    if (texture !== undefined && open.has(image)) wanted.set(image, texture);
  }

  for (const ghost of dimension.getEntities({ type: GHOST, location: cell(frame, -DEPTH / 2, 0, 2), maxDistance: 12 })) {
    if (ghost.getDynamicProperty('ss:o') !== mirror.id) continue;
    const key = String(ghost.getDynamicProperty('ss:k'));
    const texture = wanted.get(key);
    if (texture === undefined) {
      ghost.remove();
      continue;
    }
    set(ghost, 'skin_studio:tex', texture);
    wanted.delete(key);
  }

  for (const [key, texture] of wanted) {
    const [x, y, z] = key.split(',').map(Number);
    const ghost = dimension.spawnEntity(GHOST, { x: x + 0.5, y, z: z + 0.5 });
    ghost.setDynamicProperty('ss:o', mirror.id);
    ghost.setDynamicProperty('ss:k', key);
    ghost.setProperty('skin_studio:tex', texture);
  }
}

function clearReflections(mirror) {
  forget(mirror);
  for (const type of [GHOST, WALL]) {
    for (const entity of mirror.dimension.getEntities({ type })) {
      if (entity.getDynamicProperty('ss:o') === mirror.id) entity.remove();
    }
  }
}

function sweep() {
  for (const entity of [...loaded(GHOST), ...loaded(WALL)]) {
    if (world.getEntity(String(entity.getDynamicProperty('ss:o')))?.typeId !== MIRROR) entity.remove();
  }
}

async function ask(player, mirror) {
  const response = await new MessageFormData()
    .title('鏡')
    .body('前に立つと映ります。窓の奥の空いている所に、手前のブロックと人と生き物が映ります。')
    .button1('§c片付ける')
    .button2('閉じる')
    .show(player);
  if (response.selection !== 0 || !mirror.isValid) return;
  clearReflections(mirror);
  refund(mirror, player, EGG);
}

function touch({ block }) {
  for (const mirror of mirrors) {
    if (!mirror.isValid || mirror.dimension.id !== block.dimension.id) continue;
    const { x, y, z } = mirror.location;
    if (Math.abs(x - block.x) + Math.abs(y - block.y) + Math.abs(z - block.z) < 24) dirty.add(mirror.id);
  }
}

world.afterEvents.entitySpawn.subscribe(({ entity }) => {
  if (!entity.isValid || entity.typeId !== MIRROR) return;
  system.run(() => {
    if (entity.isValid && entity.getDynamicProperty('ss:f') === undefined) place(entity);
  });
});

world.beforeEvents.playerInteractWithEntity.subscribe((event) => {
  const { player, target } = event;
  if (target.typeId !== MIRROR && target.typeId !== WALL) return;
  event.cancel = true;
  const mirror = target.typeId === MIRROR ? target : world.getEntity(String(target.getDynamicProperty('ss:o')));
  if (mirror?.typeId === MIRROR) system.run(() => ask(player, mirror));
});

world.afterEvents.playerPlaceBlock.subscribe(touch);
world.afterEvents.playerBreakBlock.subscribe(touch);

system.runInterval(() => {
  tick++;
  mirrors = loaded(MIRROR);
  const players = world.getAllPlayers();
  for (const mirror of mirrors) {
    try {
      if (!mirror.isValid) continue;
      if (mirror.getDynamicProperty('ss:f') === undefined) {
        place(mirror);
        continue;
      }
      const frame = frameOf(mirror);
      reflect(mirror, frame, players);
      if (tick % 5 === 0) settle(mirror, frame.glass, frame.facing);
      if (tick % 5 === 2) fence(mirror, frame);
      if (dirty.delete(mirror.id) || tick % 50 === 0) rebuild(mirror, frame);
    } catch (error) {
      if (!warned.has(mirror.id)) console.warn(`[Skin Studio] mirror ${mirror.id}: ${error}`);
      warned.add(mirror.id);
    }
  }
  if (tick % 50 === 25) sweep();
}, 4);
