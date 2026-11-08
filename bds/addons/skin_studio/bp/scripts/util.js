import { world, GameMode, ItemStack } from '@minecraft/server';

export const PODIUM = 'skin_studio:podium';
export const MIRROR = 'skin_studio:mirror';
export const GHOST = 'skin_studio:ghost';
export const YAW = [0, 90, 180, -90];
export const FACINGS = ['south', 'west', 'north', 'east'];
export const DIMENSIONS = ['overworld', 'nether', 'the_end'];

export const facingOf = (yaw) => ((Math.round(yaw / 90) % 4) + 4) % 4;
export const placerOf = (entity) => entity.dimension.getPlayers({ location: entity.location, maxDistance: 8, closest: 1 })[0];
export const facingToPlacer = (entity) => facingOf((placerOf(entity)?.getRotation().y ?? 0) + 180);
export const loaded = (type) => DIMENSIONS.flatMap((id) => world.getDimension(id).getEntities({ type }));

export function set(entity, key, value) {
  if (entity.getProperty(key) !== value) entity.setProperty(key, value);
}

export function settle(entity, spot, facing) {
  const { x, y, z } = entity.location;
  const turn = (((entity.getRotation().y - YAW[facing]) % 360) + 360) % 360;
  const moved = Math.abs(x - spot.x) + Math.abs(y - spot.y) + Math.abs(z - spot.z) > 0.01;
  if (moved || (turn > 0.5 && turn < 359.5)) entity.teleport(spot, { rotation: { x: 0, y: YAW[facing] } });
}

export function refund(entity, player, egg) {
  entity.remove();
  if (!player || player.getGameMode() === GameMode.Creative) return;
  const left = player.getComponent('minecraft:inventory')?.container.addItem(new ItemStack(egg));
  if (left) player.dimension.spawnItem(left, player.location);
}
