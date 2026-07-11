MACRO_TYPES = {
 "runtime_isolation":"runtime", "orchestration_config":"orchestration", "orchestration_networking":"orchestration",
 "microvm_isolation":"microvm", "kernel_attack_surface":"kernel", "image_supply_chain":"image_supply_chain",
 "misconfiguration_privilege":"misconfiguration", "system_call_exposure":"syscall", "hardware_side_channel":"hardware_side_channel"
}

def macro_from_root(root: str, fallback: str = "unknown") -> str:
    return MACRO_TYPES.get(root, fallback)

def infer_fine_type(text: str) -> str:
    low = text.lower()
    rules = [("docker.sock","docker_socket_mount"),("cap_sys_admin","dangerous_capability"),("sys_admin","dangerous_capability"),("privileged","privileged_container"),("hostpath","hostpath_mount"),("subpath","k8s_volume_hostpath_or_subpath"),("runc","container_runtime_escape"),("containerd","container_runtime_escape"),("ebpf","ebpf_attack_surface")]
    for k,v in rules:
        if k in low:
            return v
    return "unknown_other"
