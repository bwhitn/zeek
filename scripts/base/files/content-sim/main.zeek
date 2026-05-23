@load base/frameworks/files

module FileContentSim;

export {
	redef record Files::Info += {
		## The algorithm used to produce the content similarity value.
		content_sim_alg: string &log &optional;

		## A bounded content similarity value derived from file contents.
		content_sim: string &log &optional;
	};
}

event file_content_sim(f: fa_file, alg: string, content_sim: string) &priority=5
	{
	if ( f$missing_bytes != 0 || f$overflow_bytes != 0 )
		return;

	if ( f?$info && f$info$timedout )
		return;

	if ( ! f?$info )
		return;

	f$info$content_sim_alg = alg;
	f$info$content_sim = content_sim;
	}
