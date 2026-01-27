# IoTFoundry Zephyr Endpoint

![License](https://img.shields.io/github/license/PICMG/iot-foundry-zephyr-endpoint)
![Coverage](https://img.shields.io/codecov/c/github/PICMG/iot-foundry-zephyr-endpoint)
![Issues](https://img.shields.io/github/issues/PICMG/iot-foundry-zephyr-endpoint)
![Forks](https://img.shields.io/github/forks/PICMG/iot-foundry-zephyr-endpoint)
![Stars](https://img.shields.io/github/stars/PICMG/iot-foundry-zephyr-endpoint)
![Last Commit](https://img.shields.io/github/last-commit/PICMG/iot-foundry-zephyr-endpoint)

This project implements an IoTFoundry serial MCTP/PLDM endpoint for the Zephyr boards.

The code in this project implements an application which is intended to be built as a "standalone" Zephyr application.  More information on Zephyr can be found at [https://docs.zephyrproject.org](https://docs.zephyrproject.org).

This repository is part of the IoTFoundry family of open source projects.  For more information about IoTFoundry, please visit the main IoTFoundry site at: [https://picmg.github.io/iot-foundry/](https://picmg.github.io/iot-foundry/)

## System Requirements
The following are system requirements for buidling/testing teh code in this library.

- Linux with the gnu toolchain and make tools installed.
- An Zephyr-supported microcontroller board (the project default is Arduino Nano 33 IoT).

## Repository Resources

- `CMakeLists.txt` — Configuration for the cmake that includes dependencies and paths.
- `CONRIBUTING.md` — instructions for contributing to this project.
- `LICENSE` — The license for this project (Apache 2.0)
- `prj.conf` — The top-level configuration file for the West/Zephyr build system.
- `README.md` — This document.
- `west.yml` — The project manefest
- `.github/workflows/` — Continuous integration workflows used by github to validate pull requirests for this project.
- `boards/` — Board configuration and overlay files used by the project.
- `include/` — Include files used by the project
- `patches/` — Patches to the Zephyr project files for project-based changes that have either not yet been upstreamed or are not appropriate for upstreaming.
- `src/` — application C source (and header) files.
- `tests/` — test scripts and code for validating the project.

## Environment Installation
These instructions show how to install the application build environment on an Ubuntu Linux system.  Some changes may be required for other linux environments. Throughout these instructions <application_path> is the full path to where the application (this repository) has been stored.  <workspace_path> is the full path to where the zephyrproject workspace will be downloaded.

The project uses the `west` build system to manage the application build.  The first step is to create a python virtual environment and install the `west` toolchain.
```bash
cd <application_path> 
python3 -m venv ./.venv
source ./.venv/bin/activate
python -m pip install --upgrade pip setuptools wheel
pip install west
```
After `west` is installed, you will use it to initialize the project workspace (where Zephyr source will be stored).  This step can take several minutes and will require multiple gigabytes of memory because the Zephyr source code will be downloaded.  Note that the <workspace_path> must not be the same as, or subordinate to the <application_path>.
```bash
# create workspace outside repo.  
mkdir -p <workspace_path> && cd <workspace_path>
west init -m <application_path>
west update
```
Now that the workspace is initialized, it is important to install any further python dependencies required by `west` and optionally install the Zephyr sdk.
```
# install Zephyr Python dependencies and sdk.
west packages pip --install
west sdk install
```
This applicaiton may require patches to the Zephyr source-base that are not general enough to warrant upstreaming them.  This next step applies any necessary patches.
```bash
# apply patches for this project
cd <workspace_path>
chmod +x <application_path>/patches/apply_patches.sh
<application_path>/patches/apply_patches.sh
```
The environment is now installed and ready to use.  Note that sourcing the virtual environment will be required with each new terminal session.

## Build Flow

To build the project, use the following commands:
```bash
cd <workspace_path>
west build -p auto -b arduino_nano_33_iot <application_path>
```
The device can be programmed using:
```bash
west flash
```

## Running device tests

The tests folder contains test scripts for testing the programmed IoT-Foundry endpoint.  The tests are detailed below:

- **run_mctp_tests.py** a python script that runs several different mctp control requests to the endpoint and shows response information. Run the command using the following syntax:

    ```bash
    python3 ./tests/run_mctp_tests.py <device> <baud>
    # <device> is the linux path to the device to test (e.g. /dev/ttyUSB0)
    # <baud> is the baud rate for the device.  The default is 115200
    ```
