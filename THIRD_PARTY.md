# Third-party code

## Metamod:Source and SourceHook headers

Upstream: https://github.com/alliedmodders/metamod-source

Commit: `cb47755826fad1483291e5dc00222aa64303d12f`

Location: `third_party/metamod-source/`

The vendored public headers are unmodified. Metamod and SourceHook copyright,
permission and license notices remain in their original files. The Metamod public
headers contain a permissive three-restriction notice; SourceHook identifies its
license as zlib/libpng. See each header for its exact terms.

`sourcehook/FastDelegate.h` credits Don Clugston, Jody Hagins and subsequent
contributors, and records AlliedModders modifications. Its original credits and
history are preserved. This file is included as supplied by the pinned upstream;
Bridge does not claim authorship of it.

Bridge uses these headers with `META_NO_HL2SDK`. The Metamod/SourceHook runtime
is supplied by the server's Metamod installation.

## Development dependencies

Zig is an external compiler. pyelftools, Capstone and Unicorn are external test
dependencies installed separately; their packages and licenses are not replaced
by Bridge's license. Versions are documented in README and requirements-dev.txt.

## Server binaries

Valve's engine and Steamclient binaries are not distributed here. The optional
fixture tests read locally supplied originals and validate their hashes against
`analysis/profile.json`. Those binaries remain subject to their own terms.
