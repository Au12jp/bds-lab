# skin_studio

## Request
表彰台と鏡（統合版アドオン）。配置は自動、編集は最低限のフォーム。コマンドだけでも全部操作できる。GeoUI で表彰台を画面に出す。鏡はサーバーの遅れなしでカクつかず、本物のブロックを置かずに映す。鏡の前の生き物も、手書きなしで全種類（バニラ 99 種）左右反転して映す。

(a person's addon, imported from Skin_Studio.mcaddon: keep its pack names and UUIDs, so their worlds update in place)

## Acceptance (one tests.txt `## ` section each)
- [x] 人ごとに中継の番号がつく（## every player gets a relay slot of their own）
- [x] コマンドで表彰台を置く。ブロックの中心、言った向き（## /studio:podium puts a podium on the block centre, facing the way asked）
- [x] コマンドで順位を入れる・空ける（## /studio:rank puts people on the steps and /studio:rank without a player empties a step）
- [x] コマンドブロックと execute as でも動く（## a command block uses the podium next to it, execute as a podium uses that podium）
- [x] コマンドで表彰台を自分の画面に出す（GeoUI のデータ）（## /studio:hud puts the podium on the player's own screen (GeoUI data on the player)）
- [x] 画面の表彰台の大きさをコマンドで変える、角の位置は端末から（## /studio:hudsize resizes the screen podium, and the device decides where its corner is）
- [x] オペレーターでない人は自分の画面だけ（## someone who is not an operator only changes their own screen）
- [x] コマンドで鏡を置く。窓でない所は断る（## /studio:mirror refuses a plain wall and fits a 3x3 window, facing the room）
- [x] 鏡の面は見えない箱 4 つでふさがっていて、近づきすぎて体がガラスを突き抜けない（## the glass is solid and exact: four invisible boxes close the window, walking into it stops in front）
- [x] 鏡の前のブロックは奥に描くだけで、本物のブロックは置かない（## a block in front of the mirror is drawn behind it, and no real block is placed）
- [x] 鏡の前の生き物に鏡像がつき、動きについていき、いなくなれば消える（## an animal in front of the mirror gets a mirrored copy that follows it, and goes when it goes）
- [x] 再起動しても残る（## the podium, the mirror and the screen podium are still there after a restart）
- [x] フォームとコマンドが同じ結果（## the podium form agrees with the commands）
- [x] コマンドで片付ける（## /studio:remove takes the nearest one away: the mirror with its ghosts, then the podium and the screen podium）
- [x] サーバーのコンソールからも（## the server console can do it all too）
- [ ] 画面の表彰台と鏡の見た目（生き物の鏡像と、画面の外にいる生き物の予備の動きも）は実機アプリで（app.txt: `node lab.mjs app run -a skin_studio`）

## Guessed
<!-- values decided without asking -->
- コマンドの名前空間は `studio:`（2.x の `/scriptevent studio:guide` と同じ）
- コマンドで探す台・鏡は、実行した人・コマンドブロックから 32 ブロック以内でいちばん近いもの。`execute as <台>` なら、その台
- 画面の表彰台は右上の角、画面の高さの 30%（GeoUI Studio の実機の値: 画面の高さ = 176 モデル単位）。描画パネルの中心を右端に置くので横縦比は要らない。大きさは `/studio:hudsize`
