# Stormy Castle 75+ FPS build

The original `0.swf` is preserved byte-for-byte. The separate deliverable is:

- `Stormy Castle 75+ FPS.swf`

The controls are embedded in the SWF's AVM2/Main code; there is no HTML wrapper or external overlay.

## In-game controls

1. Enter a level and press **Right Shift**. The embedded `Stormy Castle FPS` panel opens near the mouse cursor.
2. Drag the panel by its blue header.
3. Use `75 FPS`, `120 FPS`, or type another finite value from `1` through `1000` in the FPS field and press `Apply`.
4. In the `Money amount` field, enter the desired amount and press `Set money`. The current level's player money is changed and the normal HUD is marked for refresh.
5. `Close` removes the panel.

Invalid FPS or money input is clamped to a safe value. The money edit is applied only when the active state is an in-game level, so opening the panel on a menu/loading state is safe.

The panel is positioned with an edge clamp so it remains on the 800 by 600 stage.

## Timing changes

- The SWF header render rate is `75 FPS`.
- `GameData.FRAMERATE` is `75`, so `GameEngine` computes its normal simulation timestep as `1 / 75` instead of advancing the game by 2.5x.
- Runtime FPS changes update both `Stage.frameRate` and `GameEngine`'s timestep through an embedded `GameEngine.setFrameRate` method.
- The frame-counted earthquake/shake counter is scaled from 10 to 25 frames so its visual duration remains approximately unchanged at 75 Hz.

## Rebuild and verification

From the repository root:

```text
python3 make_fps_swf.py
```

The builder always reads `0.swf` and writes the separate output file. Static checks performed for this build include SWF tag parsing, ABC re-parsing, frame-rate header verification, embedded handler/trait verification, and SHA-256 verification that the source remains:

```text
f8e99fb7a278cf25f14a47b9ddbdc68a0398b62bac158fcf28dced812c73f724
```

A Flash/Ruffle runtime is not installed in the build sandbox, so interactive launch testing must be done in a Flash-compatible runtime.
