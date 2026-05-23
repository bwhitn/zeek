// See the file "COPYING" in the main distribution directory for copyright.

#include "zeek/file_analysis/analyzer/content_sim/ContentSimAnalyzer.h"

#include <string>

#include "zeek/Event.h"
#include "zeek/file_analysis/Manager.h"
#include "zeek/file_analysis/analyzer/content_sim/events.bif.h"

namespace zeek::file_analysis::detail {

file_analysis::Analyzer* ContentSim::Instantiate(RecordValPtr args, file_analysis::File* file) {
    return file_content_sim ? new ContentSim(std::move(args), file) : nullptr;
}

ContentSim::ContentSim(RecordValPtr args, file_analysis::File* file)
    : file_analysis::Analyzer(file_mgr->GetComponentTag("CONTENT_SIM"), std::move(args), file) {}

bool ContentSim::DeliverStream(const u_char* data, uint64_t len) {
    if ( ! fed )
        fed = len > 0;

    hasher.update(data, len);
    return true;
}

bool ContentSim::EndOfFile() {
    Finalize();
    return false;
}

bool ContentSim::Undelivered(uint64_t offset, uint64_t len) { return false; }

void ContentSim::Finalize() {
    if ( ! fed || ! file_content_sim )
        return;

    auto* file = GetFile();
    if ( file->GetMissingBytes() != 0 || file->GetOverflowBytes() != 0 )
        return;

    auto sim = hasher.finalize();
    if ( ! sim )
        return;

    event_mgr.Enqueue(file_content_sim, file->ToVal(),
                      make_intrusive<StringVal>(std::string(ssdf::SSDF_MINHASH18X24_ALG)),
                      make_intrusive<StringVal>(*sim));
}

} // namespace zeek::file_analysis::detail
