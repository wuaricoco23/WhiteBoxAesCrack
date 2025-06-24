# WhiteBox AES Fault Injection Plugin for IDA Pro

This plugin enables you to perform fault injection and key recovery on Whitebox AES implementations directly inside IDA Pro. It supports two modes:

* **Direct Mode**: load existing TBox and TYiBox tables and inject faults at specified bytes.
* **GenTYI Mode**: derive TYiBox tables from a 3D TBox base and then perform fault injection.

## Features

* Automatic generation and fault injection of AES encryption traces.
* Integration with `WBModule.getRoundKey.crack_from_traces` for last-round key recovery.
* Supports both direct table input and on-the-fly TYiBox generation.
* Configurable fault byte index for DFA attacks.

## Prerequisites

1. **IDA Pro**: Tested on IDA Pro 7.7+.
2. **Python**: The IDA embedded Python interpreter (>= 3.7).
3. **WBModule**: Ensure the `WBModule` directory (containing `getRoundKey.py` and `GetAllKey.py`) is placed alongside this plugin file.

## Installation

1. Copy this plugin file (`WhiteBoxAesCrack.py`) into your IDA `plugins` directory. For example:

   ```bash
   cp WhiteBoxAesCrack.py ~/.idapro/plugins/
   cp -r WBModule ~/.idapro/plugins/
   ```

2. Restart IDA Pro or refresh plugins (Shift+F12).

3. Verify the plugin loads by checking the IDA output window for:

   ```text
   [WhiteboxAES] initialized
   ```

## Usage

1. Open a binary containing a Whitebox AES implementation in IDA.

2. Press the hotkey `Ctrl+Shift+W` or navigate to **Edit → Plugins → WhiteBoxAesCrack**.

3. Fill in the form fields:

   * **TBox Base**: Address of the flat 16×256 byte TBox table (for Direct Mode).
   * **TYiBox Base**: Address of the 9×16×256×4 byte TYiBox table (Direct Mode only).
   * **3D TBox Base**: Address of the 10×16×256 byte 3D TBox base (GenTYI Mode).



4. Leave **TYiBox Base** blank and specify **3D TBox Base** to use GenTYI Mode. Otherwise, fill both TBox and TYiBox for Direct Mode.

5. Click **OK**. The plugin will:

   * Read tables at given addresses.
   * Generate a fault-free trace and 16 faulty traces (one per byte index).
   * Print traces as hex strings in the IDA output window.
   * Recover the last round key using DFA analysis and print the result.

## Example Output

```text
[*] Using GenTYI Mode from 3D TBox
FaultData:
33e1a6...  # baseline trace
...
# Last round key found: [0x3a, 0x7f, ..., 0xc2]
```

## Advanced Configuration

* **Fault Index**: By default, faults are injected across all 16 byte positions. To customize, modify the `aes_encrypt` call loop in `run()`.
* **Random Seed**: The plugin seeds the RNG with the byte index to ensure reproducible faults.

## Troubleshooting

* **Empty Table Read**: If you see a warning `Failed to read TBox at 0x...`, verify the address and ensure the table is mapped in IDA.
* **Module Import Errors**: Ensure `WBModule` is in the same directory as the plugin and that `sys.path` includes it.