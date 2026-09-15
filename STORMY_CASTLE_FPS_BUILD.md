# Stormy Castle 75+ FPS build

The original `0.swf` is preserved byte-for-byte. The separate deliverable is:

- `Stormy Castle 75+ FPS.swf`

The FPS controls are embedded in the SWF's AVM2/Main code; there is no HTML wrapper or external overlay.

## In-game controls

1. Start the game and right-click anywhere in the game stage.
2. The embedded `Stormy Castle FPS` panel opens at the pointer position.
3. Drag the panel by its blue header.
4. Use `75 FPS`, `120 FPS`, or type another numeric value in the input and press `Apply`.
5. `Close` removes the panel.

The panel is positioned with a small edge clamp so it remains on the 800 by 600 stage.

## Timing changes

- The SWF header render rate is `75 FPS`.
- `GameData.FRAMERATE` is `75`, so `GameEngine` computes its normal simulation timestep as `1 / 75` instead of advancing the game by 2.5x.
- Runtime menu changes update both `Stage.frameRate` and `GameEngine`'s timestep through an embedded `GameEngine.setFrameRate` method.
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
