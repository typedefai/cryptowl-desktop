#include "TextDiff.h"

#include <algorithm>
#include <cstddef>
#include <limits>
#include <vector>

namespace {

constexpr std::size_t kMaxDiffCells = 4 * 1024 * 1024;

} // namespace

bool diffLines(const QStringList &before, const QStringList &after,
               std::vector<DiffLine> *lines)
{
    if (!lines)
        return false;
    lines->clear();

    const std::size_t n = static_cast<std::size_t>(before.size());
    const std::size_t m = static_cast<std::size_t>(after.size());
    if ((n + 1) > kMaxDiffCells / (m + 1))
        return false;

    const std::size_t columns = m + 1;
    std::vector<int> lcs((n + 1) * columns, 0);
    for (std::size_t i = 1; i <= n; ++i) {
        for (std::size_t j = 1; j <= m; ++j) {
            if (before[static_cast<qsizetype>(i - 1)]
                == after[static_cast<qsizetype>(j - 1)]) {
                lcs[i * columns + j] = lcs[(i - 1) * columns + j - 1] + 1;
            } else {
                lcs[i * columns + j] =
                    std::max(lcs[(i - 1) * columns + j],
                             lcs[i * columns + j - 1]);
            }
        }
    }

    std::vector<DiffLine> reversed;
    std::size_t i = n;
    std::size_t j = m;
    while (i > 0 || j > 0) {
        if (i > 0 && j > 0
            && before[static_cast<qsizetype>(i - 1)]
                == after[static_cast<qsizetype>(j - 1)]) {
            reversed.push_back(
                {DiffLineKind::Equal, before[static_cast<qsizetype>(i - 1)]});
            --i;
            --j;
        } else if (j > 0
                   && (i == 0
                       || lcs[i * columns + j - 1]
                           >= lcs[(i - 1) * columns + j])) {
            reversed.push_back(
                {DiffLineKind::Added, after[static_cast<qsizetype>(j - 1)]});
            --j;
        } else {
            reversed.push_back(
                {DiffLineKind::Removed, before[static_cast<qsizetype>(i - 1)]});
            --i;
        }
    }

    lines->assign(reversed.rbegin(), reversed.rend());
    return true;
}
