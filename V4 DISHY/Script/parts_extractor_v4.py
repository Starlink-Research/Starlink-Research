import sys
import os
import argparse

# New MEMORY_LAYOUT based on the provided partition table
MEMORY_LAYOUT = [
    ("BOOTFIP_0", 0x100000, 0x00000000),
    ("BOOTFIP_1", 0x100000, 0x100000),
    ("BOOTFIP_2", 0x100000, 0x200000),
    ("BOOTFIP_3", 0x100000, 0x300000),
    ("BOOTTERM1", 0x80000, 0x400000),
    ("BOOTTERM2", 0x80000, 0x500000),
    ("BOOT_A_0", 0x100000, 0x600000),
    ("BOOT_B_0", 0x100000, 0x700000),
    ("BOOT_A_1", 0x100000, 0x800000),
    ("BOOT_B_1", 0x100000, 0x900000),
    ("UBOOT_TERM1", 0x100000, 0xA00000),
    ("UBOOT_TERM2", 0x100000, 0xB00000),
    ("SXID", 0x50000, 0xFB0000),
    ("KERNEL_A", 0x1800000, 0x1000000),
    ("CONFIG_A", 0x800000, 0x2800000),
    ("KERNEL_B", 0x1800000, 0x3000000),
    ("CONFIG_B", 0x800000, 0x4800000),
    ("SX_A", 0x1800000, 0x5000000),
    ("SX_B", 0x1800000, 0x6800000),
    ("VERSION_INFO_A", 0x20000, 0xF30000),
    ("VERSION_INFO_B", 0x20000, 0xF50000),
    ("SECRETS_A", 0x20000, 0xF70000),
    ("SECRETS_B", 0x20000, 0xF90000),
    ("MTDOOPS", 0x30000, 0xF00000),
    ("EDR", 0x93D1C00, 0x8000000),
    ("DISH_CONFIG", 0x2000000, 0x113D1C00),
    ("OBS_MAP", 0x8000000, 0x133D1C00),
    ("PER_VEHICLE_CONFIG_A", 0x20000, 0xEC0000),
    ("PER_VEHICLE_CONFIG_B", 0x20000, 0xEE0000),
]

def handle_file(file_in, output_folder):
    for partition in MEMORY_LAYOUT:
        name, size, offset = partition
        file_in.seek(offset)
        with open(os.path.join(output_folder, name), "wb") as file_out:
            file_out.write(file_in.read(size))

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "input_file",
        type=str,
        help="Path to the input file (the raw disk image you extracted from the dish)",
    )
    parser.add_argument(
        "output_folder",
        type=str,
        help="Path of the folder in which partitions will be written (will overwrite any existing file with the same names)",
    )
    args = parser.parse_args()

    os.makedirs(args.output_folder, exist_ok=True)
    with open(args.input_file, "rb") as file_in:
        handle_file(file_in, args.output_folder)
