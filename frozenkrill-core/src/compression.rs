use std::io::Write;

pub fn uncompress(data: &[u8]) -> anyhow::Result<Vec<u8>> {
    let mut e = flate2::write::ZlibDecoder::new(Vec::with_capacity(data.len()));
    e.write_all(data)?;
    Ok(e.finish()?)
}

pub(crate) fn compress(data: &[u8]) -> anyhow::Result<Vec<u8>> {
    let mut e = flate2::write::ZlibEncoder::new(
        Vec::with_capacity(data.len()),
        flate2::Compression::best(),
    );
    e.write_all(data)?;
    Ok(e.finish()?)
}
