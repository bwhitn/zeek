// See the file "COPYING" in the main distribution directory for copyright.

#include "zeek/plugin/Plugin.h"

#include "zeek/file_analysis/Component.h"
#include "zeek/file_analysis/analyzer/content_sim/ContentSimAnalyzer.h"

namespace zeek::plugin::detail::Zeek_FileContentSim {

class Plugin : public zeek::plugin::Plugin {
public:
    zeek::plugin::Configuration Configure() override {
        AddComponent(new zeek::file_analysis::Component(
            "CONTENT_SIM", zeek::file_analysis::detail::ContentSim::Instantiate));

        zeek::plugin::Configuration config;
        config.name = "Zeek::FileContentSim";
        config.description = "Content similarity hash for file content";
        return config;
    }
} plugin;

} // namespace zeek::plugin::detail::Zeek_FileContentSim
