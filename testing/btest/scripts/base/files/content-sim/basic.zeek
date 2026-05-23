# @TEST-DOC: Test file content similarity analyzer and files.log fields.

# @TEST-EXEC: zeek -b -r $TRACES/http/get.pcap %INPUT
# @TEST-EXEC: btest-diff .stdout
# @TEST-EXEC: zeek-cut content_sim_alg content_sim < files.log > files.log.cut
# @TEST-EXEC: btest-diff files.log.cut

@load base/protocols/http
@load base/files/content-sim

event file_new(f: fa_file)
	{
	Files::add_analyzer(f, Files::ANALYZER_CONTENT_SIM);
	}

event file_content_sim(f: fa_file, alg: string, content_sim: string)
	{
	print alg, content_sim, |content_sim|;
	}
