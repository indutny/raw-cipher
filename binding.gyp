{
  "targets": [{
    "target_name": "rawcipher",
    "include_dirs": [
      "src",
      "<(node_root_dir)/deps/openssl/openssl/include",
    ],
    "sources": [
      "src/rawcipher.cc",
    ],
  }],
}
