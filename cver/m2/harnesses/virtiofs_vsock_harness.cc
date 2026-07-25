#include <cstddef>
#include <cstdint>
#include <cstring>

namespace {

#pragma pack(push, 1)
struct FuseInHeader {
  uint32_t len;
  uint32_t opcode;
  uint64_t unique;
  uint64_t nodeid;
  uint32_t uid;
  uint32_t gid;
  uint32_t pid;
  uint16_t total_extlen;
  uint16_t padding;
};

struct VsockHeader {
  uint64_t src_cid;
  uint64_t dst_cid;
  uint32_t src_port;
  uint32_t dst_port;
  uint32_t len;
  uint16_t type;
  uint16_t op;
  uint32_t flags;
  uint32_t buf_alloc;
  uint32_t fwd_cnt;
};
#pragma pack(pop)

template <typename T>
bool load(const uint8_t* data, size_t size, T& out) {
  if (size < sizeof(T)) return false;
  std::memcpy(&out, data, sizeof(T));
  return true;
}

}  // namespace

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  if (data == nullptr || size == 0 || size > (8U << 20)) return 0;
  const uint8_t selector = data[0] & 1U;
  data += 1;
  size -= 1;

  if (selector == 0) {
    FuseInHeader header{};
    if (!load(data, size, header)) return 0;
    const bool length_ok = header.len >= sizeof(FuseInHeader) && header.len <= size;
    const bool ext_ok = static_cast<uint64_t>(header.total_extlen) * 8U <= header.len;
    volatile uint64_t sink = header.unique ^ header.nodeid ^ static_cast<uint64_t>(length_ok && ext_ok);
    (void)sink;
  } else {
    VsockHeader header{};
    if (!load(data, size, header)) return 0;
    const bool length_ok = header.len <= size - sizeof(VsockHeader);
    const bool cid_ok = header.src_cid != header.dst_cid;
    const bool op_known = header.op <= 7U;
    volatile uint64_t sink = header.src_cid ^ header.dst_cid ^
                             static_cast<uint64_t>(length_ok && cid_ok && op_known);
    (void)sink;
  }
  return 0;
}
