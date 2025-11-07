#ifndef PATH_UTILS_H
#define PATH_UTILS_H

#include <string>
#include "pin.H"

namespace tenet_tracer {
namespace pathutils {

#if defined(TARGET_WINDOWS)
    const char* const PATH_SEP = "\\";
#else
    const char* const PATH_SEP = "/";
#endif

/**
 * Extract the base name (filename) from a full path.
 * @param path Full file path
 * @return Base name without directory path
 */
inline std::string GetBaseName(const std::string& path)
{
    std::string::size_type idx = path.rfind(PATH_SEP);
    return (idx == std::string::npos) ? path : path.substr(idx + 1);
}

/**
 * Sanitize a string to be safe for use as a filename.
 * Replaces invalid characters with underscores.
 * @param s Input string
 * @return Sanitized string safe for filenames
 */
inline std::string SanitizeFilename(const std::string& s)
{
    std::string out;
    out.reserve(s.size());
    for (char c : s) {
        switch (c) {
      case '<': case '>': case ':': case '"': case '/': case '\\':
  case '|': case '?': case '*':
            out.push_back('_');
            break;
    default:
            out.push_back((c >= 0 && c < 32) ? '_' : c);
        }
    }
    return out;
}

/**
 * Ensure all directories exist for a given file path.
 * Creates nested directories as needed.
 * @param prefix File path for which to ensure directories exist
 */
inline void EnsureDirectoryExists(const std::string& prefix)
{
 size_t pos = prefix.find_last_of("/\\");
    if (pos == std::string::npos) return;
    std::string dir = prefix.substr(0, pos);
    if (dir.empty()) return;

  std::string cur;
    cur.reserve(dir.size());
    for (size_t i = 0; i < dir.size(); ++i) {
        char c = dir[i];
        cur.push_back(c);
 if (c == '\\' || c == '/') {
  OS_MkDir(cur.c_str(), 0755);
        }
    }
    OS_MkDir(cur.c_str(), 0755);
}

} // namespace pathutils
} // namespace tenet_tracer

#endif // PATH_UTILS_H
