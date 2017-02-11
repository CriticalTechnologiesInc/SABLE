**SABLE**: The *S*yracuse *A*ssured *B*oot*L*oader *E*xecutive
=================

Overview
-----------------

SABLE is a trusted bootloader which uses a TPM chip to establish mutual trust
between a user and his/her platform.

Requirements
----------------

To build SABLE:
- CMake >= 3.0.2
- gcc >= 4.3

To boot SABLE:
- Any AMD CPU with support for AMD-V virtualization
- A v1.2 TPM chip
- GRUB2

Build
----------------

For a typical build, use:
```
$ cd <path/to/sable>
$ mkdir build
$ cd build
$ cmake ../
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
directory, see the CMake documention for examples.

Note: Some systems may be configured in such a manner that TPM NVRAM can only
be read by the TPM owner. In this case, SABLE should be build with the
`NV_OWNER_REQUIRED` option enabled. This can be set by appending `NV_OWNER_REQUIRED`
to the `CMAKE_C_FLAGS` option in `ccmake`.

Installation
---------------

The easiest way to add a SABLE-enabled boot is to copy an existing boot entry
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
