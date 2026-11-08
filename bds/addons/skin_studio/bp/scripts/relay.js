import { world, system } from '@minecraft/server';
import { set } from './util.js';

const SLOTS = 100;
const holders = new Map();

export function relayOf(player) {
  const slot = Number(player.getProperty('skin_studio:slot'));
  const gen = Number(player.getProperty('skin_studio:gen'));
  return slot > 0 && gen > 0 ? { slot, gen } : undefined;
}

function refresh() {
  const players = world.getAllPlayers();
  const online = new Set(players.map((player) => player.id));
  for (const [slot, id] of holders) if (!online.has(id)) holders.delete(slot);

  const waiting = [];
  for (const player of players) {
    const slot = Number(player.getProperty('skin_studio:slot'));
    const holder = holders.get(slot);
    if (slot > 0 && (holder === undefined || holder === player.id)) holders.set(slot, player.id);
    else waiting.push(player);
  }
  if (!waiting.length) return;

  const start = Number(world.getDynamicProperty('ss:gen') ?? 0);
  let gen = start;
  for (const player of waiting) {
    let slot = 1;
    while (holders.has(slot)) slot++;
    if (slot > SLOTS) {
      set(player, 'skin_studio:slot', 0);
      continue;
    }
    gen = (gen % 999999) + 1;
    holders.set(slot, player.id);
    player.setProperty('skin_studio:slot', slot);
    player.setProperty('skin_studio:gen', gen);
  }
  if (gen !== start) world.setDynamicProperty('ss:gen', gen);
}

world.afterEvents.playerSpawn.subscribe(({ initialSpawn }) => {
  if (initialSpawn) system.run(refresh);
});

system.runInterval(refresh, 20);
