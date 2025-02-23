use std::cmp::Ordering;
use std::fmt::Debug;
use std::fs::read_dir;
use std::path::{Path, PathBuf};

use crate::{DecryptFunc, EncryptFunc, HashFunc, SetBlockSize, SetThreadCount};

const LIB_PATH: &str = "./target/dynlibs";

/// # Errors
/// Function will return an error if the file with `name` does not exist
pub fn lib_files<'a, S: AsRef<str> + Debug>(
    name: &'a str,
    pattern: &'a [S],
) -> Result<impl Iterator<Item = (PathBuf, libloading::Library)> + 'a, std::io::Error> {
    let path: PathBuf = Path::new(LIB_PATH).join(name);
    match read_dir(&path) {
        Ok(dir) => {
            let it = dir
                .filter_map(std::result::Result::ok)
                .filter_map(move |curr_file| {
                    if !pattern.is_empty()
                        && !pattern.iter().any(|pattern| {
                            curr_file
                                .path()
                                .to_string_lossy()
                                .contains(pattern.as_ref())
                        })
                    {
                        return None; // Skip if name does not match requested pattern
                    }
                    let lib = unsafe { libloading::Library::new(curr_file.path()) };
                    match lib {
                        Ok(lib) => Some((curr_file.path(), lib)),
                        Err(err) => {
                            eprintln!(
                            "Cannot open file \"{}\" as a shared library ({err:?}), skipping ...",
                            curr_file.path().display()
                        );
                            None
                        }
                    }
                });
            // Sort by filename for more consistent benchmarking order:
            let mut tmp: Vec<(PathBuf, libloading::Library)> = it.collect();
            tmp.sort_unstable_by(|(p0, _), (p1, _)| {
                let s0 = p0.file_name();
                let s1 = p1.file_name();
                match (s0, s1) {
                    (Some(s0), Some(s1)) => Ord::cmp(s0, s1),
                    (Some(_), None) => Ordering::Less,
                    (None, Some(_)) => Ordering::Greater,
                    (None, None) => Ordering::Equal,
                }
            });
            let it = tmp.into_iter();
            Ok(it)
        }
        Err(err) => {
            eprintln!(
                "Could not find directory \"{}\", skipping benchmarks (error: {err:?}",
                path.display()
            );
            Err(err)
        }
    }
}

#[must_use]
pub fn get_hash_func<'a>(
    lib: &'a libloading::Library,
    func_names: &[&[u8]],
) -> Option<HashFunc<'a>> {
    func_names
        .iter()
        .find_map(|name| unsafe { lib.get(name).ok() })
}

#[must_use]
pub fn get_encrypt_func<'a>(
    lib: &'a libloading::Library,
    func_names: &[&[u8]],
) -> Option<EncryptFunc<'a>> {
    func_names
        .iter()
        .find_map(|name| unsafe { lib.get(name).ok() })
}

#[must_use]
pub fn get_decrypt_func<'a>(
    lib: &'a libloading::Library,
    func_names: &[&[u8]],
) -> Option<DecryptFunc<'a>> {
    func_names
        .iter()
        .find_map(|name| unsafe { lib.get(name).ok() })
}

#[must_use]
pub fn get_thread_count_set_function<'a>(
    lib: &'a libloading::Library,
    func_names: &[&[u8]],
) -> Option<SetThreadCount<'a>> {
    func_names
        .iter()
        .find_map(|name| unsafe { lib.get(name).ok() })
}

#[must_use]
pub fn get_block_size_set_function<'a>(
    lib: &'a libloading::Library,
    func_names: &[&[u8]],
) -> Option<SetBlockSize<'a>> {
    func_names
        .iter()
        .find_map(|name| unsafe { lib.get(name).ok() })
}
