# MCIGN Firmware

## Introduction
This is firmware for a BLE keyless motorcycle ignition that is controlled by a smartphone app. An extra layer of encryption is used to make up for vulnerabilities in the BLE pairing process, and up to 16 keys can be registered on the device at a time. User keys can optionally be set to expire at a certain time, or to be disabled at a certain time of day (curfew). It is made for the Silicon Labs BGM111 module, and can be flashed with openocd or Simplicity Studio.

The BGM111 module was chosen because it has already been FCC certified, which normally makes it much easier to sell the hardware without violating FCC regulations. However, this project is exempt from the required testing because it is "a digital device utilized exclusively in any transportation vehicle including motor vehicles." The project is now being ported to the nRF51822 chip for several reason:

 * It is cheaper
 * Cheap generic breakout boards are available
 * Supports open source tools (gcc & make), which have less bugs, more documentation, and better integration with git than Simplicity Studio, which is required for the BGM111
 * An automotive grade (AEC-Q100) drop-in replacement is available (nRF51824), allowing the hardware to be built to automotive standards

## Usage
Once the firmware has been flashed to a BGM111 module it is controlled entirely by the [smartphone app](https://github.com/mcign/app). To connect to the ignition, the app needs a copy of the master key and the BGM111's bluetooth address in QR code format. The QR code should be formatted as `[bt-addr]\n[master_key]`. The master key is currently hardcoded to `IEi07yA1VFxEEo7c3VRiHQ==:VoXoX4o2E01NTJrVOBcQGXlpwEF7lypDirgKoAwDYEM=` and can be changed by modifying the TEST_MASTER_KEYS define in `app/crypto.h`.

## Contributing
This project is in its early stages, and all contributions are greatly appreciated.

## Help
Please post a github issue for any help requests or feature requests.

## Installation

### Requirements
Simplicity Studio (including the Bluetooth SDK v2.5.5) is required to build this project. It can be downloaded after registering a free account at [silabs.com](http://silabs.com). 

Either Simplicity Studio, Simplicity Commander, or OpenOCD can be used to flash the device. An SWDIO adapter is also required; Simplicity Studio and Simplicity require a J-Link adapter such as the [https://www.silabs.com/products/development-tools/wireless/bluetooth/bluegecko-bluetooth-low-energy-module-wireless-starter-kit](BGM111 dev kit), while OpenOCD supports more adapters including a Raspberry Pi.

### Build
Import the project into Simplicity Studio (File > Import), then build it (Project > Build Project). A .s37 file (among others) will be generated.

Note: There is a bug that prevents Simplicity Studio from exporting project settings correctly. Further development will focus on porting the project to the nRF51822 chip.

### Installation (Simplicity Studio & BGM111 dev kit)
Connect the WSTK debug socket to the corresponding SWDIO test pads on the PCB. Right click on the .s37 file in Simplicity Studio and select "Flash to Device". If the device doesn't work (ie. an "MCIGN" BLE device can't be seen in a BLE scanner app), you may need to [https://www.silabs.com/products/development-tools/wireless/bluetooth/bluegecko-bluetooth-low-energy-module-wireless-starter-kit](flash the bootloader).

### Installation (OpenOCD & Raspberry Pi)
Connect the Raspberry Pi's GPIO pins (see the `openocd.cfg` file for pin numbers) to the corresponding SWDIO test pads on the PCB. Install OpenOCD on the Raspberry Pi. Copy the `openocd.cfg` file from your repository and the .s37 file from Simplicity Studio to the Raspberry Pi, then run `sudo openocd` in the same directory as the Raspberry Pi.

## License
This project is license under GPLv3.
