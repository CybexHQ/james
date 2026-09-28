# Boot artwork

`pxe-menu.svg` is the editable Tiaris boot background, using the supplied bird and
wordmark. `pxe-menu.png` is its 1024 × 864 raster export used by iPXE and GRUB.
Keep the menu area at x=280, y=260, width=464, height=464 so existing boot text
placement stays aligned. Render the SVG at its intrinsic size when exporting.
