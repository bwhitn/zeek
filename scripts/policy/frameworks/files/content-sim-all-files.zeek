##! Calculate content similarity values for all files.

@load base/files/content-sim

event file_new(f: fa_file)
	{
	Files::add_analyzer(f, Files::ANALYZER_CONTENT_SIM);
	}
