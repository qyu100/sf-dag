use tokio_util::codec::LengthDelimitedCodec;

/// Maximum frame size accepted by the benchmark network.
///
/// Consensus sync responses can carry full serialized blocks. The default
/// `LengthDelimitedCodec` limit is too small for larger benchmark payloads.
pub const MAX_FRAME_LENGTH: usize = 128 * 1024 * 1024;

pub fn large_frame_codec() -> LengthDelimitedCodec {
    LengthDelimitedCodec::builder()
        .max_frame_length(MAX_FRAME_LENGTH)
        .new_codec()
}
