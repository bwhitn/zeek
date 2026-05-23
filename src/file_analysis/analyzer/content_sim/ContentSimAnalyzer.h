// See the file "COPYING" in the main distribution directory for copyright.

#pragma once

#include "SSDF.h"

#include "zeek/Val.h"
#include "zeek/file_analysis/Analyzer.h"
#include "zeek/file_analysis/File.h"

namespace zeek::file_analysis::detail {

/**
 * An analyzer to produce a bounded content similarity value for file contents.
 */
class ContentSim final : public file_analysis::Analyzer {
public:
    /**
     * Create a new instance of the content similarity file analyzer.
     * @param args the \c AnalyzerArgs value which represents the analyzer.
     * @param file the file to which the analyzer will be attached.
     * @return the new analyzer instance or a null pointer if there's no
     *         handler for the "file_content_sim" event.
     */
    static file_analysis::Analyzer* Instantiate(RecordValPtr args, file_analysis::File* file);

    /**
     * Incrementally update the content similarity sketch from file contents.
     * @param data pointer to start of a chunk of file data.
     * @param len number of bytes in the data chunk.
     * @return true while the analyzer remains valid.
     */
    bool DeliverStream(const u_char* data, uint64_t len) override;

    /**
     * Finalizes the sketch and raises a "file_content_sim" event.
     * @return always false so the analyzer will be detached from the file.
     */
    bool EndOfFile() override;

    /**
     * Missing data invalidates the similarity value.
     * @param offset byte offset in file at which missing chunk starts.
     * @param len number of missing bytes.
     * @return always false so analyzer will detach from the file.
     */
    bool Undelivered(uint64_t offset, uint64_t len) override;

private:
    ContentSim(RecordValPtr args, file_analysis::File* file);

    void Finalize();

    ssdf::Hasher hasher;
    bool fed = false;
};

} // namespace zeek::file_analysis::detail
