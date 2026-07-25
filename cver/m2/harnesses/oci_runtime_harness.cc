#include <cstddef>
#include <cstdint>
#include <limits>
#include <string_view>

namespace {

struct Cursor {
  const uint8_t* data;
  size_t size;
  size_t pos{0};

  bool take(uint8_t& out) {
    if (pos >= size) return false;
    out = data[pos++];
    return true;
  }
};

bool parse_string(Cursor& cursor) {
  uint8_t ch = 0;
  if (!cursor.take(ch) || ch != '"') return false;
  size_t decoded = 0;
  while (cursor.take(ch)) {
    if (ch == '"') return true;
    if (ch == '\\') {
      if (!cursor.take(ch)) return false;
      if (ch == 'u') {
        for (int i = 0; i < 4; ++i) {
          if (!cursor.take(ch)) return false;
        }
      }
    }
    if (++decoded > (1U << 20)) return false;
  }
  return false;
}

bool scan_json_like(Cursor& cursor) {
  size_t depth = 0;
  size_t tokens = 0;
  uint8_t ch = 0;
  while (cursor.pos < cursor.size) {
    ch = cursor.data[cursor.pos];
    if (ch == '"') {
      if (!parse_string(cursor)) return false;
      ++tokens;
      continue;
    }
    ++cursor.pos;
    if (ch == '{' || ch == '[') {
      if (++depth > 128) return false;
    } else if (ch == '}' || ch == ']') {
      if (depth == 0) return false;
      --depth;
    } else if ((ch >= '0' && ch <= '9') || ch == '-') {
      size_t digits = 1;
      while (cursor.pos < cursor.size) {
        const uint8_t next = cursor.data[cursor.pos];
        if (!((next >= '0' && next <= '9') || next == '.' || next == 'e' || next == 'E' || next == '+' || next == '-')) {
          break;
        }
        ++cursor.pos;
        if (++digits > 256) return false;
      }
      ++tokens;
    }
    if (tokens > 100000) return false;
  }
  return depth == 0;
}

}  // namespace

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  if (data == nullptr || size == 0 || size > (4U << 20)) return 0;
  Cursor cursor{data, size};
  const bool structurally_valid = scan_json_like(cursor);

  // Exercise bounded annotation-key searches used by OCI/runtime policy adapters.
  const std::string_view input(reinterpret_cast<const char*>(data), size);
  const bool has_runtime = input.find("io.katacontainers") != std::string_view::npos;
  const bool has_host_path = input.find("hostPath") != std::string_view::npos;
  const bool has_privileged = input.find("privileged") != std::string_view::npos;
  volatile uint32_t sink = static_cast<uint32_t>(structurally_valid) |
                           (static_cast<uint32_t>(has_runtime) << 1U) |
                           (static_cast<uint32_t>(has_host_path) << 2U) |
                           (static_cast<uint32_t>(has_privileged) << 3U);
  (void)sink;
  return 0;
}
