#pragma once
// jsonwriter.h -- minimal JSON-writing helpers for Pin tools
// Single header, no exceptions, no dependencies beyond <string> <ostream> <cstdio>

#include <string>
#include <ostream>
#include <cstdio>

namespace json {

// ---- correct JSON string escaping ----
// Uses character-by-character appends to avoid raw-literal escape traps.
inline std::string escape(const std::string& s) {
    std::string r;
    r.reserve(s.size() * 2);
    for (unsigned char c : s) {
        switch (c) {
        case '"':  r += '\\'; r += '"';  break;
        case '\\': r += '\\'; r += '\\'; break;
        case '\n': r += '\\'; r += 'n';  break;
        case '\r': r += '\\'; r += 'r';  break;
        case '\t': r += '\\'; r += 't';  break;
        default:
            if (c < 0x20) {
                char buf[8];
                snprintf(buf, sizeof(buf), "\\u%04x", (unsigned)c);
                r += buf;
            } else {
                r += (char)c;
            }
        }
    }
    return r;
}

// ---- 16-digit uppercase hex ----
inline std::string hex64(uint64_t v) {
    char buf[24];
    snprintf(buf, sizeof(buf), "%016llX", (unsigned long long)v);
    return buf;
}

// ---- write "key":"escaped_value" + optional comma ----
inline void kv(std::ostream& os, const char* key, const std::string& val, bool comma = true) {
    os << '"'  << key << '"'
       << ':' << '"' << escape(val) << '"';
    if (comma) os << ',';
}

// ---- write "key":raw_value + optional comma (raw is emitted as-is: numbers, bool, null) ----
inline void kv_raw(std::ostream& os, const char* key, const std::string& raw, bool comma = true) {
    os << '"' << key << '"' << ':' << raw;
    if (comma) os << ',';
}

} // namespace json
