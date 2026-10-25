-- ASB E2E bridge: a stay-open AppleScript applet that runs queued jobs as a GUI app.
-- Why: macOS grants Screen Recording / Accessibility / Automation to apps, and a command started over ssh
-- has neither a window-server session nor those grants. Grant the ONE app "ASB E2E Bridge" and queue jobs:
--   ~/asb-e2e/q/NAME.sh    run with /bin/sh as a child of this app (screencapture works: Screen Recording)
--   ~/asb-e2e/q/NAME.scpt  run IN this process with `run script` (System Events UI scripting works:
--                          Accessibility is checked against this app; a child osascript would not qualify)
-- Results: NAME.out and NAME.rc appear when the job is done (rc 0 = ok).
on idle
	set q to (POSIX path of (path to home folder)) & "asb-e2e/q/"
	try
		do shell script "cd " & quoted form of q & " 2>/dev/null || exit 0; for f in *.sh; do [ -e \"$f\" ] || continue; b=\"${f%.sh}\"; mv \"$f\" \"$b.run\"; /bin/sh \"$b.run\" > \"$b.out.tmp\" 2>&1; echo $? > \"$b.rc.tmp\"; rm -f \"$b.run\"; mv \"$b.out.tmp\" \"$b.out\"; mv \"$b.rc.tmp\" \"$b.rc\"; done"
	end try
	try
		set jobs to paragraphs of (do shell script "cd " & quoted form of q & " 2>/dev/null && ls *.scpt 2>/dev/null; true")
		repeat with j in jobs
			if (j as text) is not "" then
				set b to text 1 thru -6 of (j as text)
				do shell script "cd " & quoted form of q & " && mv " & quoted form of (j as text) & " " & quoted form of (b & ".scptrun")
				set rc to 0
				try
					with timeout of 100 seconds
						set r to run script (POSIX file (q & b & ".scptrun"))
					end timeout
					set outText to r as text
				on error e number n
					set rc to 1
					set outText to e & " (" & n & ")"
				end try
				do shell script "cd " & quoted form of q & " && rm -f " & quoted form of (b & ".scptrun") & "; printf '%s' " & quoted form of outText & " > " & quoted form of (b & ".out.tmp") & "; echo " & rc & " > " & quoted form of (b & ".rc.tmp") & "; mv " & quoted form of (b & ".out.tmp") & " " & quoted form of (b & ".out") & "; mv " & quoted form of (b & ".rc.tmp") & " " & quoted form of (b & ".rc")
			end if
		end repeat
	end try
	return 0.5
end idle
on quit
	continue quit
end quit
