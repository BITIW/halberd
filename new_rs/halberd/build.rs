fn main() {
    prost_build::compile_protos(&["proto/halberd.proto"], &["proto"]).unwrap();
}