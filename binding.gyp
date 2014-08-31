{
  "targets": [{
    "target_name": "prf",
    "include_dirs": [
      "src",
      "<(node_root_dir)/deps/openssl/openssl/include",
      "<!(node -e \"require('nan')\")",
    ],
    "sources": [
      "src/prf.cc",
    ],
  }],
}
