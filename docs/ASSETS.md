# Assets and icons – licenses and sources

This document lists icons and images used in the project and their licenses. **We prefer open-source or free-to-use assets and use Bootstrap Italia–compatible icons (Bootstrap Icons, MIT) where possible.**

## Icon set: Bootstrap Icons (MIT)

- **Source:** [Bootstrap Icons](https://icons.getbootstrap.com/) (GitHub: [twbs/icons](https://github.com/twbs/icons))
- **License:** MIT
- **Use:** UI icons (trash, memory, card, PDF, QR code, etc.) are from Bootstrap Icons so they are open source and consistent with the Bootstrap Italia design system.

## Icons and images in use

| Asset | Location | Source / license | Notes |
|-------|----------|------------------|--------|
| **trash** (delete) | `static/images/trash-delete-icon.svg` | Bootstrap Icons (MIT) | Replaces previous SVG Repo asset. |
| **memory / storage** | `static/images/memory.svg` | Bootstrap Icons – `device-hdd` (MIT) | Icon for “Memoria” / storage. |
| **credential card** | `static/images/card-violet.svg` | Bootstrap Icons – `card-heading` (MIT) | Violet fill for credential card style. |
| **PDF** | `static/images/pdf.svg` | Bootstrap Icons – `file-earmark-pdf` (MIT) | Replaces previous SVG Repo asset. |
| **QR code** | `static/images/qr-code-icon.svg` | Bootstrap Icons – `qr-code` (MIT) | Import QR action. |
| **Wallet logo** | `static/images/wallet_logo.svg` | Generic digital wallet icon (Bootstrap Icons wallet2, MIT) | Favicon and header logo. |
| **Country flags** | `static/images/flags/4x3/*.svg` | EU + 27 member states only (eu, at, be, bg, hr, cy, cz, dk, de, ee, es, fi, fr, gr, hu, ie, it, lv, lt, lu, mt, nl, pl, pt, ro, sk, si, se) | Used for country selector. |
| **Tessera Sanitaria (card front)** | `static/images/Tessera_Sanitaria_Italia-Fronte.svg` | Project SVG (stylized card illustration) | Replaces JPG; demo only, not an official document. |
| **Emblem of Italy** | `static/images/Emblem_of_Italy.svg` | Official emblem (public domain / government) | Italian government symbol. |
| **Medal / certificate** | `static/images/medal.svg` | Bootstrap Icons – `award` (MIT) | Certificate icon. |
| **Laurea (education)** | `static/images/laurea1.svg`, `laurea2.svg` | Bootstrap Icons – `mortarboard` (MIT) | Education credentials. |
| **Italy map** | `static/images/italy_map.svg` | Project SVG (simplified outline) | PID card badge. |

**Country flags:** Only the EU flag and the 27 countries in the wallet dropdown are kept in `static/images/flags/4x3/` (eu, at, be, bg, hr, cy, cz, dk, de, ee, es, fi, fr, gr, hu, ie, it, lv, lt, lu, mt, nl, pl, pt, ro, sk, si, se). Unreferenced flag SVGs and other unused icons have been removed.

## Third-party icon/font code

- **QR code reader UI** (`static/js/qr_code/all.min.js`, `static/css/qr_code/all.min.css`): **Font Awesome** (Icons: CC BY 4.0, Fonts: SIL OFL 1.1, Code: MIT). Acceptable for use with attribution; consider migrating to Bootstrap Icons if you want a single icon set.
- **Tom Select** (`static/js/tom-select.base.js`): Apache 2.0.

## Bootstrap Italia

- **Bootstrap Italia** is the design system for Italian public administration sites: [italia.github.io/bootstrap-italia](https://italia.github.io/bootstrap-italia/), [GitHub](https://github.com/italia/bootstrap-italia) (BSD-3-Clause).
- It is based on Bootstrap 5 and is compatible with **Bootstrap Icons**. Using Bootstrap Icons for UI icons keeps the project aligned with Bootstrap Italia and ensures all such icons are open source (MIT).

## Raster → SVG

All raster icons/images used in the UI have been replaced with SVG equivalents:

- **Wallet logo**: `wallet_logo.svg` (generic digital wallet icon, Bootstrap Icons); favicon serves this SVG.
- **medal.png** → `medal.svg` (Bootstrap Icons award).
- **laurea1.png**, **laurea2.png** → `laurea1.svg`, `laurea2.svg` (Bootstrap Icons mortarboard).
- **italy_map.png** → `italy_map.svg` (simplified Italy outline).
- **Tessera_Sanitaria_Italia-Fronte.jpg** → `Tessera_Sanitaria_Italia-Fronte.svg` (stylized card front).

Unreferenced assets have been removed: former raster files, unused SVGs (add-document, document, eu_logo, emblem in static root; add, card, no-image, noun-card, qr-code-placeholder, rounded-rectangle in images), and all flag SVGs except EU + the 27 dropdown countries.

## Summary

- **UI icons** used in the app (trash, memory, card, PDF, QR, medal, laurea) are from **Bootstrap Icons (MIT)** or project SVGs, in line with Bootstrap Italia.
- **Logos and symbols** (wallet logo, flags, Emblem of Italy) are SVG where used.
- **Demo/reference images** are SVG illustrations where possible; ensure compliance with any official branding when required.
