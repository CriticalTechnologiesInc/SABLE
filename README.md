**SABLE**: The **S**yracuse **A**ssured **B**oot **L**oader **E**xecutive
=================

Overview
-----------------

SABLE is a trusted bootloader which uses a TPM chip to establish mutual trust
between a user and his/her platform. SABLE can be thought of as a wrapper for
a GRUB2 menuentry, which can be used to attest to the integrity of that specific
GRUB2 menuentry. For example, if a trusted kernel is corrupted or replaced
by a malicious entity, SABLE provides a mechanism to inform the user that the
boot configuration has been corrupted.

We refer to each SABLE-wrapped GRUB2 menuentry as a SABLE-Enabled Configuration (SEC).

Requirements
----------------

To build SABLE:
- CMake >= 3.0.2
- gcc >= 4.3
- python >= 3.4

To configure and boot SABLE:
- Any AMD CPU with support for AMD-V virtualization
- A v1.2 TPM chip
- GRUB2
- tpm-tools

Build
----------------

For a typical build, use:
```
$ cd <path/to/sable>
$ mkdir build
$ cd build
$ cmake -DCMAKE_BUILD_TYPE=RELEASE ../
$ make
```
For a debug build, you can instead do:
```
$ cd <path/to/sable>
$ mkdir build-debug
$ cd build-debug
$ cmake -DCMAKE_BUILD_TYPE=DEBUG ../
$ make
```
Additional build options can be accessed by running `ccmake`, from a build
directory, see the CMake documention for examples. At this time, the only
supported build types are RELEASE and DEBUG.

To compile SABLE source as input for Isabelle/HOL, run
```
$ make sable-isa
```
This build target is only valid with a RELEASE build.

Note: When building for the Qemu environment, use `ccmake` to add `-DTARGET_QEMU`
to the `CMAKE_C_FLAGS` variable. This will disable certain checks on platform hardware.

Note: Some systems may be configured in such a manner that TPM NVRAM can only
be read by the TPM owner. In this case, SABLE should be build with the
`NV_OWNER_REQUIRED` option enabled. This can be set by appending `-DNV_OWNER_REQUIRED`
to the `CMAKE_C_FLAGS` variable in `ccmake`.

Installation
---------------

The easiest way to add a SEC is to copy an existing GRUB2 menuentry
from your `grub.cfg` into your `/etc/grub.d/40_custom`, then edit the entry to
boot with SABLE. For instance, the following entry
```
menuentry 'Ubuntu' {
  ...
  linux /boot/mylinux
  initrd /boot/myinitrd
}
```
would become
```
menuentry 'SABLE-Ubuntu' {
  ...
  multiboot /boot/sable
  module /boot/grub/i386-pc/core.img
  module /boot/mylinux
  module /boot/myinitrd
}
```
Note that you will need to copy the `sable` binary to your `/boot` directory. Then
you may run
```
# update-grub2
```
to generate an updated `grub.cfg` with the new menuentry.

Configuration
---------------

SABLE uses TPM NVRAM to store sensitive data. Before an SEC can be configured, the
platform owner must define a space within TPM NVRAM for that SEC. The easiest way to
do this is to use tpm-tools:
```
# tpm_nvdefine -o <TPM owner password> \
               -a <NVRAM space password> \
               -i <index> \
               -s <size> \
               --permissions="AUTHWRITE|READ_STCLEAR"
```
If the TPM owner password is well-known (all zeros), use the `-y` flag instead of `-o`.
The NVRAM space password should be unique to each SEC, and known only to the platform
owner and the user(s) of that SEC. The NVRAM index should be at least 4, and the
minimum recommended size is 384 bytes. Here's an example configuration command:
```
# tpm_nvdefine -o myownerpass -a thisSECpass -i 4 -s 400 \
    --permissions="AUTHWRITE|READ_STCLEAR"
```

Once the space has been configured, reboot your system, and select the new SEC
from the GRUB2 boot menu. SABLE will ask if you want to configure. Type "y", then
enter the following credentials:

- The **passphrase** is a unique text string that should be known only to the user(s)
  of this SEC. On a trusted boot, this passphrase will be displayed to the user
  if and only if the boot configuration is valid.
- The **passphrase authdata** is a password unique to this configuration. It must be known
  to the SEC user(s), but may not be known to the platform owner.
- The **SRK password**
- The **NVRAM password** is that password designated by the platform owner as a requirement
  for writing to this NVRAM space

Usage
---------------

Once an SEC has been configured, the user can attempt a trusted boot. Select the SEC
from the GRUB2 menu as in the Configuration step, but this time strike the 'n' key
when prompted to initiate a trusted boot. SABLE will measure the boot components, and
attempt to unseal the passphrase. The user must additionally enter the following
credentials:

- The **passphrase authdata**
- The **SRK password**

Then the **passphrase** will be displayed to the user if and only if the boot
configuration is valid, AND the provided credentials were correct. If the user
recognizes the passphrase as the one associated with the SEC, he/she types "YES"
in all capitals to proceed with the boot.
