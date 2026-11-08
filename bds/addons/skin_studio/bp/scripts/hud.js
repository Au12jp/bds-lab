import { world, system } from '@minecraft/server';
import { PODIUM, set } from './util.js';

const RANKS = [1, 2, 3];
const SCREENS = {
  Desktop: { cx: -6, cy: -278 },
  Mobile: { cx: -417, cy: -526 },
  Console: { cx: -6, cy: -278 },
};

export const hudOf = (player) => JSON.parse(String(player.getDynamicProperty('ss:hud') ?? 'null'));

export function showHud(player, podium) {
  if (podium) {
    const { x, y, z } = podium.location;
    player.setDynamicProperty('ss:hud', JSON.stringify({ id: podium.id, dim: podium.dimension.id, x, y, z }));
  } else {
    player.setDynamicProperty('ss:hud', undefined);
  }
  refresh(player);
}

export function resizeHud(player, percent) {
  player.setDynamicProperty('ss:size', percent === 100 ? undefined : percent);
  refresh(player);
}

function refresh(player) {
  const screen = SCREENS[player.clientSystemInfo.platformType] ?? SCREENS.Desktop;
  set(player, 'skin_studio:cx', screen.cx);
  set(player, 'skin_studio:cy', screen.cy);
  set(player, 'skin_studio:size', Number(player.getDynamicProperty('ss:size') ?? 100));

  const target = hudOf(player);
  const podium = target && world.getEntity(target.id);
  if (podium?.typeId === PODIUM) {
    for (const rank of RANKS) {
      set(player, `skin_studio:h${rank}s`, podium.getProperty(`skin_studio:s${rank}`));
      set(player, `skin_studio:h${rank}g`, podium.getProperty(`skin_studio:g${rank}`));
    }
  } else if (target && player.dimension.id === target.dim && player.dimension.isChunkLoaded(target)) {
    player.setDynamicProperty('ss:hud', undefined);
    set(player, 'skin_studio:hud', false);
    return;
  }
  set(player, 'skin_studio:hud', !!target);
}

system.runInterval(() => {
  for (const player of world.getAllPlayers()) refresh(player);
}, 20);
