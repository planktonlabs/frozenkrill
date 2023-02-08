use std::{
    fs::{File, OpenOptions},
    io::{BufReader, BufWriter, Write},
    path::Path,
};

use anyhow::{self, Context};

pub fn open_create_file(output_file_path: &Path) -> anyhow::Result<BufWriter<File>> {
    Ok(BufWriter::new(
        OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(output_file_path)
            .context("failure opening output file for write")?,
    ))
}

pub fn create_file(data: &[u8], output_file_path: &Path) -> anyhow::Result<()> {
    let mut f = open_create_file(output_file_path)?;
    f.write_all(data).context("failure writing final data")?;
    f.flush().context("failure flushing final data")?;
    Ok(())
}

pub fn open_file(path: &Path) -> anyhow::Result<File> {
    Ok(OpenOptions::new().read(true).open(path)?)
}

pub fn buf_open_file(path: &Path) -> anyhow::Result<BufReader<File>> {
    Ok(BufReader::new(open_file(path)?))
}
