// TOTK_EARLY_Z (2026-10-23, after the fork's early-fragment-tests change, upstream PR #222): a fragment shader whose NVN
// control section sets byte +0x718 has its depth test run before the shader on the Switch. Metal runs it after the shader
// unless the fragment function says [[early_fragment_tests]], which for the G-buffer's ~2,000 material draws turns early-Z
// and hidden-surface removal back on. The flag is a property of the shader, so the key list is derived offline from the
// seed's control sections (tools/early_z_keys.py -> totk_early_z_keys.h); a shader translated while playing is noted from
// its control section in totk_shader_rt.m variant_request. nvn_mtl.m injects the attribute into the MSL as a text pass
// (prefix form: this Metal rejects it after the parameter list) and keeps its pipelines in their own archive folder.
// TOTK_EARLY_Z=0 turns it off.
#pragma once
#include <stddef.h>

int totk_early_z_on(void);                             // the switch (default on; off on iPhone, whose seed is precompiled)
int totk_early_z_lookup(const char *key64);            // 64-hex shader key, NUL-terminated: 1 = early fragment tests
void totk_early_z_note(const char *key64);             // a shader translated at runtime that asks for them
char *totk_early_z_msl(const char *src, size_t len);   // malloc'd MSL with the attribute, or NULL (not applicable)
