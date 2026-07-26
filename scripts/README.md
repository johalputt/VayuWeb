# scripts/ — build and project tooling

Tooling that supports the repository itself rather than the protocol.

| Script | Purpose |
|---|---|
| `build-assets.py` | Regenerates every file in `assets/` from the source artwork: trims the canvas, converts the white background to transparency, produces light and dark ink variants, and thickens hairlines for favicon sizes so the mark stays legible at 32px. |

## Regenerating the brand assets

```bash
pip install Pillow numpy
python3 scripts/build-assets.py assets/
```

The source artwork (`assets/vayuweb-logo-source.jpg` and `assets/vayuweb-logo-alt-source.png`) is
the original design and is kept in the repository so every derived asset can be rebuilt from
it rather than edited by hand.
