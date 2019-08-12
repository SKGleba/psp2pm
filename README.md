# psp2pm
Internal Producting Mode (i_manufacturing_mode) enabler/disabler for PSP2 Dolce (PSTV) and Vita (PSVITA)

# Warning
- Messing with the device at such low level may result in a unrecoverable brick, DO NOT USE IT unless you know what the target mode does.

# Description
- This tool should be compatible with firmwares 3.60, 3.65 - 3.71. It has been tested on firmwares 3.65 and 3.70.
- This tool sets the internal producting mode bit on the console's secure memory by using a crypto coprocessor exploit. It can also disable "manufacturing_mode" on any console.

# Notes
- To set External Producting Mode (e_manufacturing_mode) use the ```patch_pm_jig``` payload instead.

# Credits
- Team Molecule for their crypto processor exploit and ~~spoonfeeding~~ help on discord.
- Mathieulh and Zecoxao for their useful ideas.
