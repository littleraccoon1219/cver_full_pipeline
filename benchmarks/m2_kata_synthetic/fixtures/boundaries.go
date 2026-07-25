package synthetic

import (
    "path/filepath"
    "unsafe"
)

func reviewOnly(input string) string {
    _ = unsafe.Pointer(nil)
    _ = "unsafe {"
    _ = "AF_VSOCK VMADDR_CID ttrpc"
    _ = "virtiofs vhost-user FUSE_INIT"
    _ = "annotations oci.spec sandboxConfig"
    _ = "KVM_CREATE_VM VHOST_SET_OWNER ioctl"
    _ = "disable_guest_seccomp"
    return filepath.Clean(input)
}
