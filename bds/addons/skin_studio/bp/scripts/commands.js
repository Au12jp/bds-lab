import { world, system, Player, CommandPermissionLevel, CustomCommandParamType as Param, CustomCommandStatus } from '@minecraft/server';
import { PODIUM, MIRROR, FACINGS, facingOf } from './util.js';
import { setup as setupPodium, assign } from './podium.js';
import { setup as setupMirror, windowProblem, removeMirror } from './mirror.js';
import { showHud, resizeHud } from './hud.js';

const REACH = 32;
const ok = (message) => ({ status: CustomCommandStatus.Success, message });
const no = (message) => ({ status: CustomCommandStatus.Failure, message: message.replace(/§./g, '') });
const selfOf = (origin) => (origin.sourceEntity instanceof Player ? origin.sourceEntity : undefined);
const names = (players) => players.map((player) => player.name).join('、');

function sourceOf(origin) {
  const entity = origin.sourceEntity;
  if (entity) return { entity, dimension: entity.dimension, location: entity.location };
  const block = origin.sourceBlock;
  if (block) return { dimension: block.dimension, location: { x: block.x + 0.5, y: block.y + 1, z: block.z + 0.5 } };
}

function nearest(origin, types) {
  const source = sourceOf(origin);
  if (!source) return undefined;
  if (types.includes(source.entity?.typeId)) return source.entity;
  const { x, y, z } = source.location;
  const far = ({ location }) => (location.x - x) ** 2 + (location.y - y) ** 2 + (location.z - z) ** 2;
  const found = types.flatMap((type) => source.dimension.getEntities({ type, location: source.location, maxDistance: REACH, closest: 1 }));
  return found.sort((a, b) => far(a) - far(b))[0];
}

function facingFor(origin, dimension, location, name) {
  if (name) return FACINGS.indexOf(name);
  const viewer = selfOf(origin) ?? dimension.getPlayers({ location, maxDistance: 16, closest: 1 })[0];
  return viewer ? facingOf(viewer.getRotation().y + 180) : 0;
}

function targets(origin, players) {
  const self = selfOf(origin);
  const list = players ?? (self ? [self] : []);
  const others = list.some((player) => player.id !== self?.id);
  if (others && self && self.commandPermissionLevel < CommandPermissionLevel.GameDirectors) return undefined;
  return list;
}

function placeWith(type, label, setup, check) {
  return (origin, location, facing) => {
    const source = sourceOf(origin);
    const spot = location ?? source?.location;
    if (!spot) return no('置く場所を指定してください（例: 0 64 0）');
    const dimension = source?.dimension ?? world.getDimension('overworld');
    const { min, max } = dimension.heightRange;
    if (spot.y < min || spot.y >= max || !dimension.isChunkLoaded(spot)) return no('そこは読み込まれていないか、高さの外です');
    const turn = facingFor(origin, dimension, spot, facing);
    const problem = check?.(dimension, spot, turn);
    if (problem) return no(problem);
    const at = { x: Math.floor(spot.x) + 0.5, y: spot.y, z: Math.floor(spot.z) + 0.5 };
    system.run(() => setup(dimension.spawnEntity(type, at), turn));
    return ok(`${label}を置きました（${at.x} ${at.y} ${at.z}、${FACINGS[turn]} 向き）`);
  };
}

function setRank(origin, place, players) {
  if (![1, 2, 3].includes(place)) return no('順位は 1・2・3 のどれかです');
  if (players && players.length !== 1) return no('入れる人は 1 人だけ指定してください');
  const podium = nearest(origin, [PODIUM]);
  if (!podium) return no(`${REACH} ブロック以内に表彰台がありません`);
  const player = players?.[0];
  system.run(() => podium.isValid && assign(podium, place, player));
  return ok(player ? `${place}位に ${player.name} を入れました` : `${place}位を空けました`);
}

function hud(origin, state, players) {
  const list = targets(origin, players);
  if (!list) return no('ほかの人の画面を変えられるのはオペレーターだけです');
  if (!list.length) return no('だれの画面かを指定してください（例: @a）');
  if (state === 'off') {
    system.run(() => list.forEach((player) => player.isValid && showHud(player, undefined)));
    return ok(`画面の表彰台を消しました（${names(list)}）`);
  }
  const podium = nearest(origin, [PODIUM]);
  if (!podium) return no(`${REACH} ブロック以内に表彰台がありません`);
  system.run(() => list.forEach((player) => player.isValid && podium.isValid && showHud(player, podium)));
  return ok(`画面に表彰台を出しました（${names(list)}）`);
}

function resize(origin, percent, players) {
  const list = targets(origin, players);
  if (!list) return no('ほかの人の画面を変えられるのはオペレーターだけです');
  if (!list.length) return no('だれの画面かを指定してください（例: @a）');
  if (!(percent >= 30 && percent <= 300)) return no('大きさは 30〜300（%）です。ふつうは 100');
  system.run(() => list.forEach((player) => player.isValid && resizeHud(player, Math.round(percent))));
  return ok(`画面の表彰台を ${Math.round(percent)}% にしました（${names(list)}）`);
}

function remove(origin) {
  const target = nearest(origin, [PODIUM, MIRROR]);
  if (!target) return no(`${REACH} ブロック以内に表彰台も鏡もありません`);
  const mirror = target.typeId === MIRROR;
  system.run(() => target.isValid && (mirror ? removeMirror(target) : target.remove()));
  return ok(mirror ? '鏡を片付けました' : '表彰台を片付けました');
}

system.beforeEvents.startup.subscribe(({ customCommandRegistry: registry }) => {
  const op = { permissionLevel: CommandPermissionLevel.GameDirectors, cheatsRequired: false };
  const anyone = { permissionLevel: CommandPermissionLevel.Any, cheatsRequired: false };
  const where = [
    { name: 'location', type: Param.Location },
    { name: 'studio:facing', type: Param.Enum },
  ];
  const players = { name: 'players', type: Param.PlayerSelector };

  registry.registerEnum('studio:facing', FACINGS);
  registry.registerEnum('studio:switch', ['on', 'off']);
  registry.registerCommand({ name: 'studio:podium', description: '表彰台を置く', ...op, optionalParameters: where }, placeWith(PODIUM, '表彰台', setupPodium));
  registry.registerCommand(
    { name: 'studio:mirror', description: '鏡を置く（壁にあけた 3×3 の窓の一番下の真ん中に）', ...op, optionalParameters: where },
    placeWith(MIRROR, '鏡', setupMirror, windowProblem),
  );
  registry.registerCommand(
    {
      name: 'studio:rank',
      description: '近くの表彰台の順位に人を入れる（人を省くと空ける）',
      ...op,
      mandatoryParameters: [{ name: 'rank', type: Param.Integer }],
      optionalParameters: [{ name: 'player', type: Param.PlayerSelector }],
    },
    setRank,
  );
  registry.registerCommand(
    { name: 'studio:hud', description: '近くの表彰台を画面に出す・消す', ...anyone, mandatoryParameters: [{ name: 'studio:switch', type: Param.Enum }], optionalParameters: [players] },
    hud,
  );
  registry.registerCommand(
    {
      name: 'studio:hudsize',
      description: '画面の表彰台の大きさ（%。ふつうは 100）',
      ...anyone,
      mandatoryParameters: [{ name: 'percent', type: Param.Integer }],
      optionalParameters: [players],
    },
    resize,
  );
  registry.registerCommand({ name: 'studio:remove', description: '近くの表彰台か鏡を片付ける', ...op }, remove);
});
