#include <cstddef>
#include <cstdint>

namespace {

bool read_varint(const uint8_t* data, size_t size, size_t& pos, uint64_t& value) {
  value = 0;
  for (unsigned shift = 0; shift < 64; shift += 7) {
    if (pos >= size) return false;
    const uint8_t byte = data[pos++];
    value |= static_cast<uint64_t>(byte & 0x7fU) << shift;
    if ((byte & 0x80U) == 0) return true;
  }
  return false;
}

bool parse_protobuf_fields(const uint8_t* data, size_t size) {
  size_t pos = 0;
  size_t fields = 0;
  while (pos < size && fields++ < 10000) {
    uint64_t tag = 0;
    if (!read_varint(data, size, pos, tag) || tag == 0) return false;
    const unsigned wire = static_cast<unsigned>(tag & 0x7U);
    uint64_t value = 0;
    switch (wire) {
      case 0:
        if (!read_varint(data, size, pos, value)) return false;
        break;
      case 1:
        if (size - pos < 8) return false;
        pos += 8;
        break;
      case 2:
        if (!read_varint(data, size, pos, value)) return false;
        if (value > size - pos || value > (8U << 20)) return false;
        pos += static_cast<size_t>(value);
        break;
      case 5:
        if (size - pos < 4) return false;
        pos += 4;
        break;
      default:
        return false;
    }
  }
  return pos == size;
}

uint32_t load_le32(const uint8_t* data) {
  return static_cast<uint32_t>(data[0]) |
         (static_cast<uint32_t>(data[1]) << 8U) |
         (static_cast<uint32_t>(data[2]) << 16U) |
         (static_cast<uint32_t>(data[3]) << 24U);
}

}  // namespace

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  if (data == nullptr || size < 4 || size > (8U << 20)) return 0;

  // Generic length-prefixed ttrpc/protobuf boundary envelope. This exercises
  // framing and protobuf wire constraints without sending messages to an agent.
  const uint32_t declared = load_le32(data);
  const size_t available = size - 4;
  if (declared <= available) {
    const bool valid = parse_protobuf_fields(data + 4, declared);
    volatile uint64_t sink = static_cast<uint64_t>(valid) ^ declared;
    (void)sink;
  }
  return 0;
}
