"""Runtime observer assets, shipped as real readable files.

Each file in this directory is an *instrumentation helper* that
`vash.lang.poc_runtime.materialize_observer` copies into a Hunt task's scratch
directory so the sandboxed agent can wrap its PoC with it. Nothing here is
imported for its side effects — the Python assets are `__main__`-guarded
scripts, not library modules — and nothing here is ever executed by VASH
itself: only the agent, inside the sandbox, runs them.
"""
