# Copyright 2026 Query Farm LLC - https://query.farm
#
# Rewrite each `require <ext>` gate in this repo's sqllogictest files into an
# explicit signed INSTALL+LOAD, so the prebuilt standalone `haybarn-unittest`
# (which links none of these extensions) can run the suite. The vgi extension
# comes from the signed community channel; httpfs/json/parquet/spatial from the
# signed core channel. `require-env` and every other directive pass through
# untouched. See ci/README.md.
#
# When invoked with `-v transport=http`, the http:// LOCATION exercised by that
# transport requires DuckDB's `httpfs` extension (the vgi extension's HTTP
# client is built on it; without it ATTACH fails with a Binder Error whose text
# contains "HTTP" — which DuckDB's sqllogictest runner silently *auto-skips*
# via its default `ignore_error_messages = {"HTTP", ...}`, so a missing httpfs
# looks like a pass-by-skip rather than a failure). We therefore inject a signed
# `INSTALL httpfs FROM core; LOAD httpfs;` right after the test's own
# `LOAD vgi;` so the http leg actually runs (and is not silently skipped).
# Harmless/absent for subprocess and unix (transport != http).
/^require[ \t]+vgi[ \t]*$/ {
    print "statement ok"; print "INSTALL vgi FROM community;"; print "";
    print "statement ok"; print "LOAD vgi;";
    if (transport == "http") {
        print "";
        print "statement ok"; print "INSTALL httpfs FROM core;"; print "";
        print "statement ok"; print "LOAD httpfs;";
    }
    next
}
# The vgi-asn1 .test files LOAD vgi explicitly (statement ok + LOAD vgi;)
# rather than via `require vgi`; hook that line too so the http leg gets httpfs.
/^LOAD[ \t]+vgi[ \t]*;[ \t]*$/ {
    print
    if (transport == "http") {
        print "";
        print "statement ok"; print "INSTALL httpfs FROM core;"; print "";
        print "statement ok"; print "LOAD httpfs;";
    }
    next
}
/^require[ \t]+(httpfs|json|parquet|spatial)[ \t]*$/ {
    ext = $2
    print "statement ok"; print "INSTALL " ext " FROM core;"; print "";
    print "statement ok"; print "LOAD " ext ";"; next
}
{ print }
